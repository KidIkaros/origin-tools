// SPDX-License-Identifier: Apache-2.0

//! origin-relay — standalone relay server daemon.
//!
//! Trust-preserving byte forwarder (spec REV 3 §5): Noise-IK-authenticated
//! sessions, bounded inboxes, eviction set persisted across restarts,
//! endpoint adverts. The relay routes, throttles, evicts — never reads.
//!
//! Usage:
//!   origin-relay serve --listen 127.0.0.1:7331 --home ~/.origin/relay
//!   origin-relay evict <hex-fingerprint> --home ~/.origin/relay
//!   origin-relay pardon <hex-fingerprint> --home ~/.origin/relay
//!   origin-relay status --home ~/.origin/relay

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};

use origin_network::relay::DEFAULT_MAX_FORWARDINGS;
use origin_network::session::StaticResolver;
use origin_network::transport::TcpTransport;
use origin_network::{EvictionSet, PeerKeys, RelayServer, RelayState, Transport};

#[derive(Parser)]
#[command(name = "origin-relay", about = "Origin relay server daemon")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the relay server.
    Serve {
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:7331")]
        listen: String,
        /// Relay state directory (eviction set lives here).
        #[arg(long, default_value = "~/.origin/relay")]
        home: String,
        /// Max concurrent forwardings.
        #[arg(long, default_value_t = DEFAULT_MAX_FORWARDINGS)]
        max_forwardings: usize,
        /// Optional JSONL allowlist of PeerKeys records (one JSON object
        /// per line). If omitted, the resolver starts empty and every
        /// inbound claim is rejected as unknown.
        #[arg(long)]
        allowlist: Option<String>,
        /// Optional external address to advertise (NAT dial-back for peers
        /// connecting back through their own traversal).
        #[arg(long)]
        external_addr: Option<String>,
        /// Disable the Landlock filesystem sandbox (spec §5.5). On by
        /// default on Linux kernels with Landlock; degrades to a
        /// warning automatically where the kernel lacks support.
        #[arg(long)]
        no_sandbox: bool,
    },
    /// Add a fingerprint to the eviction set.
    Evict {
        /// 64-char hex fingerprint.
        fingerprint: String,
        #[arg(long, default_value = "~/.origin/relay")]
        home: String,
    },
    /// Remove a fingerprint from the eviction set.
    Pardon {
        fingerprint: String,
        #[arg(long, default_value = "~/.origin/relay")]
        home: String,
    },
    /// Show eviction set size and stats.
    Status {
        #[arg(long, default_value = "~/.origin/relay")]
        home: String,
    },
}

fn expand_home(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(s)
}

fn eviction_path(home: &std::path::Path) -> PathBuf {
    home.join("eviction.bin")
}

fn relay_seed_path(home: &std::path::Path) -> PathBuf {
    home.join("relay.seed")
}

/// Load a JSONL allowlist of PeerKeys records into the resolver.
/// Blank lines are skipped; a malformed line is a startup error so the
/// operator fixes the file instead of silently running without peers.
fn load_allowlist(path: &str, resolver: &mut StaticResolver) -> Result<usize, String> {
    let path = expand_home(path);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("read allowlist {}: {e}", path.display()))?;
    let mut count = 0;
    for (n, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: PeerKeys = serde_json::from_str(line)
            .map_err(|e| format!("allowlist {}: line {}: {e}", path.display(), n + 1))?;
        resolver.add(rec);
        count += 1;
    }
    Ok(count)
}

fn load_or_create_seed(home: &PathBuf) -> Result<[u8; 32], String> {
    let path = relay_seed_path(home);
    if path.exists() {
        let bytes = std::fs::read(&path).map_err(|e| format!("read seed: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("seed file must be 32 bytes, got {}", bytes.len()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        return Ok(seed);
    }
    std::fs::create_dir_all(home).map_err(|e| format!("create home: {e}"))?;
    let mut seed = [0u8; 32];
    origin_crypto_sdk::fill_random(&mut seed).map_err(|e| format!("CSPRNG: {e}"))?;
    std::fs::write(&path, seed).map_err(|e| format!("write seed: {e}"))?;
    Ok(seed)
}

fn parse_fp(s: &str) -> Result<origin_network::Fingerprint, String> {
    origin_network::Fingerprint::from_hex(s).map_err(|e| e.to_string())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Serve {
            listen,
            home,
            max_forwardings,
            allowlist,
            external_addr,
            no_sandbox,
        } => serve(listen, home, max_forwardings, allowlist, external_addr, no_sandbox).await,
        Commands::Evict { fingerprint, home } => {
            let fp = parse_fp(&fingerprint);
            let home = expand_home(&home);
            match fp {
                Ok(fp) => {
                    let ev = EvictionSet::load(&eviction_path(&home)).await;
                    match ev {
                        Ok(ev) => {
                            ev.revoke(&fp).await;
                            match ev.save(&eviction_path(&home)).await {
                                Ok(()) => {
                                    println!("evicted: {}", fp.to_hex());
                                    Ok(())
                                }
                                Err(e) => Err(e.to_string()),
                            }
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
                Err(e) => Err(e),
            }
        }
        Commands::Pardon { fingerprint, home } => {
            let fp = parse_fp(&fingerprint);
            let home = expand_home(&home);
            match fp {
                Ok(fp) => {
                    let ev = EvictionSet::load(&eviction_path(&home)).await;
                    match ev {
                        Ok(ev) => {
                            ev.pardon(&fp).await;
                            match ev.save(&eviction_path(&home)).await {
                                Ok(()) => {
                                    println!("pardoned: {}", fp.to_hex());
                                    Ok(())
                                }
                                Err(e) => Err(e.to_string()),
                            }
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
                Err(e) => Err(e),
            }
        }
        Commands::Status { home } => {
            let home = expand_home(&home);
            match EvictionSet::load(&eviction_path(&home)).await {
                Ok(ev) => {
                    let count = ev.len().await;
                    println!("eviction set: {count} entries");
                    if count > 0 {
                        println!("  (revoked peers cannot register)");
                    }
                    Ok(())
                }
                Err(e) => Err(e.to_string()),
            }
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn serve(
    listen: String,
    home: String,
    max_forwardings: usize,
    allowlist: Option<String>,
    external_addr: Option<String>,
    no_sandbox: bool,
) -> Result<(), String> {
    let home = expand_home(&home);
    let seed = load_or_create_seed(&home)?;
    let eviction = EvictionSet::load(&eviction_path(&home))
        .await
        .map_err(|e| e.to_string())?;
    let state = RelayState::new(max_forwardings);
    let mut resolver = StaticResolver::new();
    let mut allowlist_count = 0usize;
    if let Some(path) = allowlist {
        allowlist_count = load_allowlist(&path, &mut resolver)?;
    }
    let resolver = Arc::new(resolver);
    let server = Arc::new(
        RelayServer::new(state, eviction, resolver, seed)
            .map_err(|e| e.to_string())?,
    );

    let addr: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| format!("bad listen: {e}"))?;
    let transport = TcpTransport::listen(addr)
        .await
        .map_err(|e| e.to_string())?;

    println!(
        "origin-relay {} listening on {}",
        server.fingerprint().to_hex(),
        transport.local_addr().unwrap()
    );
    if let Some(ext) = &external_addr {
        println!("  external: {ext}");
    }
    println!("max_forwardings={max_forwardings} allowlist={allowlist_count}");

    // Landlock privilege drop (spec §5.5): the relay parses hostile
    // traffic; after bind + state load it needs only its home dir.
    // Best-effort: kernels without Landlock log a warning and run on.
    if no_sandbox {
        println!("sandbox: disabled (--no-sandbox)");
    } else {
        match origin_network::sandbox::restrict_to_home(&home) {
            Ok(origin_network::sandbox::SandboxStatus::Enforced) => {
                println!("sandbox: landlock enforced (home only)");
            }
            Ok(origin_network::sandbox::SandboxStatus::NotEnforced(reason)) => {
                eprintln!("warning: landlock not enforced: {reason}");
            }
            Err(e) => {
                eprintln!("warning: sandbox setup failed: {e}");
            }
        }
    }

    // Periodic eviction persistence (evict/pardon save immediately;
    // this covers in-process revocations made via future admin frames).
    let save_server = Arc::clone(&server);
    let save_path = eviction_path(&home);
    let persist = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let _ = save_server.eviction().save(&save_path).await;
        }
    });

    // Background cleanup of expired inbox frames.
    let cleanup_server = Arc::clone(&server);
    let ttl = std::time::Duration::from_secs(server.state().inbox_ttl_secs());
    let cleaner = tokio::spawn(async move {
        let mut interval = tokio::time::interval(ttl / 2);
        loop {
            interval.tick().await;
            let n = cleanup_server.state().cleanup_expired().await;
            if n > 0 {
                println!("cleanup: purged {n} expired inbox frame(s)");
            }
        }
    });

    // Run the server's accept loop with graceful shutdown.
    // On Unix, we select between the serve loop and a signal wait.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let shutdown_ev = server.eviction().clone();
        let shutdown_save = eviction_path(&home);
        let shutdown_signal = async move {
            let mut sigterm = signal(SignalKind::terminate())
                .expect("SIGTERM handler");
            let mut sigint = signal(SignalKind::interrupt())
                .expect("SIGINT handler");
            tokio::select! {
                _ = sigterm.recv() => {
                    println!("\nsignal: SIGTERM — shutting down");
                }
                _ = sigint.recv() => {
                    println!("\nsignal: SIGINT — shutting down");
                }
            }
            // Persist final eviction state.
            if let Err(e) = shutdown_ev.save(&shutdown_save).await {
                eprintln!("warning: final eviction save failed: {e}");
            }
            println!("origin-relay stopped");
        };

        tokio::select! {
            result = server.serve(transport) => {
                match result {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        persist.abort();
                        cleaner.abort();
                        Err(e.to_string())
                    }
                }
            }
            _ = shutdown_signal => {
                persist.abort();
                cleaner.abort();
                Ok(())
            }
        }
    }

    #[cfg(not(unix))]
    {
        let shutdown_ev = server.eviction().clone();
        let shutdown_save = eviction_path(&home);
        let shutdown_signal = async move {
            tokio::signal::ctrl_c().await.expect("ctrl_c handler");
            if let Err(e) = shutdown_ev.save(&shutdown_save).await {
                eprintln!("warning: final eviction save failed: {e}");
            }
            println!("origin-relay stopped");
        };

        tokio::select! {
            result = server.serve(transport) => {
                match result {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        persist.abort();
                        cleaner.abort();
                        Err(e.to_string())
                    }
                }
            }
            _ = shutdown_signal => {
                persist.abort();
                cleaner.abort();
                Ok(())
            }
        }
    }
}
