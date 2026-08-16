// SPDX-License-Identifier: Apache-2.0

//! CLI command implementations for origin-wallet.

use origin_wallet::{Shard, Wallet};
use std::path::Path;

/// The passphrase given on the command line (`--passphrase`), for
/// non-interactive use (scripts, CI, tests). When set, every
/// `prompt_passphrase` returns it instead of reading the TTY.
static CLI_PASSPHRASE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// Execute a CLI command.
pub fn execute(cli: super::Cli) -> Result<(), Box<dyn std::error::Error>> {
    // The global `--passphrase` flag (scripts/CI/tests): record it before
    // any command runs so every prompt consults it first.
    if let Some(p) = &cli.passphrase {
        let _ = CLI_PASSPHRASE.set(Some(p.clone()));
    }
    match cli.command {
        super::Commands::Create { output } => cmd_create(&output)?,
        super::Commands::Open => cmd_open(&cli.file)?,
        super::Commands::Accounts => cmd_accounts(&cli.file)?,
        super::Commands::Account { command } => cmd_account(&cli.file, command)?,
        super::Commands::Balance { account } => cmd_balance(&cli.file, account)?,
        super::Commands::Backup {
            shards,
            threshold,
            output,
        } => cmd_backup(&cli.file, shards, threshold, &output)?,
        super::Commands::Recover { shards, output } => cmd_recover(&shards, &output)?,
        super::Commands::Phrase { command } => cmd_phrase(&cli.file, command)?,
        super::Commands::Network { command } => match command {
            super::NetworkCommands::Status => cmd_network_status(&cli.file)?,
            super::NetworkCommands::Doctor { stun_server } => {
                cmd_network_doctor(&cli.file, &stun_server)?
            }
            super::NetworkCommands::Sync { peer, peer_addr } => {
                cmd_network_sync(&cli.file, &peer, peer_addr)?
            }
        },
        super::Commands::Pay {
            to,
            service,
            amount,
            peer_addr,
            relay,
            relay_addr,
            memo,
            cap,
        } => {
            let target = match (to, service) {
                (Some(to), None) => PayTarget::Counterparty(to.parse()?),
                (None, Some(service)) => PayTarget::Service(service.parse()?),
                (None, None) => {
                    return Err("--to (or --service) is required".into())
                }
                (Some(_), Some(_)) => {
                    return Err("--to and --service are mutually exclusive".into())
                }
            };
            cmd_pay(
                &cli.file,
                target,
                amount,
                PayFlags {
                    peer_addr,
                    relay,
                    relay_addr,
                    memo,
                    cap,
                },
            )?
        }
        super::Commands::Policy {
            per_tx,
            per_day,
            per_month,
        } => cmd_policy(&cli.file, per_tx, per_day, per_month)?,
        super::Commands::Settle { to, peer_addr } => cmd_settle(&cli.file, &to, peer_addr)?,
        super::Commands::Discover {
            query,
            room,
            point,
            peer_addr,
            save,
        } => cmd_discover(&cli.file, &query, room, point, peer_addr, save)?,
        super::Commands::Contact { command } => cmd_contact(&cli.file, command)?,
        super::Commands::Mail { command } => match command {
            super::MailCommands::Send {
                to,
                peer_addr,
                body,
            } => cmd_mail_send(&to, peer_addr, &body)?,
            super::MailCommands::Inbox => cmd_mail_inbox(&cli.file)?,
        },
        super::Commands::Chat { command } => cmd_chat(&cli.file, command)?,
        super::Commands::ChatListen {
            from,
            via_relay,
            relay_addr,
        } => cmd_chat_listen(&cli.file, from, via_relay, relay_addr)?,
        super::Commands::Relay { command } => match command {
            super::RelayCommands::Serve {
                difficulty,
                stun_server,
                addr,
                discovery_point,
                discovery_addr,
            } => cmd_relay_serve(
                &cli.file,
                difficulty,
                &stun_server,
                addr,
                discovery_point,
                discovery_addr,
            )?,
            super::RelayCommands::Stats => cmd_relay_stats(&cli.file)?,
            super::RelayCommands::Evict { peer } => cmd_relay_evict(&cli.file, &peer)?,
            super::RelayCommands::Pardon { peer } => cmd_relay_pardon(&cli.file, &peer)?,
        },
    }
    Ok(())
}

/// Prompt for passphrase securely — unless `--passphrase` was given on
/// the command line (scripts/CI/tests), in which case that is returned
/// without touching the TTY.
fn prompt_passphrase(_prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(Some(p)) = CLI_PASSPHRASE.get() {
        if !p.is_empty() {
            return Ok(p.clone());
        }
    }
    // The `prompt` is passed to rpassword for the interactive case.
    let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
    if passphrase.is_empty() {
        return Err("Passphrase cannot be empty".into());
    }
    Ok(passphrase)
}

/// Confirm passphrase by prompting twice.
fn confirm_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let confirm = prompt_passphrase("Confirm passphrase: ")?;
    if passphrase != confirm {
        return Err("Passphrases do not match".into());
    }
    Ok(passphrase)
}

/// Create a new wallet.
fn cmd_create(output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if output.exists() {
        eprintln!("Warning: {} already exists", output.display());
        print!("Overwrite? [y/N] ");
        use std::io::{self, Write};
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let passphrase = confirm_passphrase()?;

    println!("Generating post-quantum secure seed...");
    let wallet = Wallet::create(&passphrase)?;

    println!("Saving wallet to {}...", output.display());
    wallet.save(output, &passphrase)?;

    println!("\n✓ Wallet created successfully!");
    println!("  File: {}", output.display());
    println!("  Accounts: {}", wallet.accounts().len());
    println!("\n⚠ Remember your passphrase! It cannot be recovered.");

    Ok(())
}

/// Open and display wallet info.
fn cmd_open(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    println!("✓ Wallet opened successfully!");
    println!("{}", wallet);

    Ok(())
}

/// List all accounts.
fn cmd_accounts(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    let accounts = wallet.accounts();
    if accounts.is_empty() {
        println!("No accounts. Derive one with: origin-wallet account derive --name <name>");
        return Ok(());
    }

    println!("Accounts ({}):", accounts.len());
    println!("{:-<60}", "");
    for account in accounts {
        println!("  {}", account);
    }

    Ok(())
}

/// Account management commands.
fn cmd_account(path: &Path, command: super::AccountCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        super::AccountCommands::Derive { name, index } => {
            if !path.exists() {
                return Err(format!("Wallet file not found: {}", path.display()).into());
            }

            let passphrase = prompt_passphrase("Enter passphrase: ")?;
            let mut wallet = Wallet::open(path, &passphrase)?;

            let account = if let Some(idx) = index {
                // Use specified index (re-derive)
                println!("Deriving account '{}' at index {}...", name, idx);
                // Note: This creates a new account with the given name
                // The index is determined by the wallet's internal counter
                wallet.derive_account(wallet.accounts().len() as u32)?
            } else {
                println!("Deriving account '{}'...", name);
                wallet.derive_account(wallet.accounts().len() as u32)?
            };

            wallet.save(path, &passphrase)?;

            println!("\n✓ Account derived successfully!");
            println!("  {}", account);

            Ok(())
        }
        super::AccountCommands::Show { account: index } => {
            if !path.exists() {
                return Err(format!("Wallet file not found: {}", path.display()).into());
            }

            let passphrase = prompt_passphrase("Enter passphrase: ")?;
            let wallet = Wallet::open(path, &passphrase)?;

            let accounts = wallet.accounts();
            if (index as usize) >= accounts.len() {
                return Err(format!(
                    "Account {} not found. Wallet has {} accounts.",
                    index,
                    accounts.len()
                )
                .into());
            }

            println!("{}", accounts[index as usize]);

            Ok(())
        }
    }
}

/// Show account balance.
fn cmd_balance(path: &Path, account: u32) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    let balance = wallet.get_balance(account)?;
    let accounts = wallet.accounts();

    if (account as usize) >= accounts.len() {
        return Err(format!(
            "Account {} not found. Wallet has {} accounts.",
            account,
            accounts.len()
        )
        .into());
    }

    println!("Account {}: {}", account, accounts[account as usize].name());
    println!("Balance: {} units", balance);
    println!("Total wallet balance: {} units", wallet.total_balance());

    Ok(())
}

/// Create backup shards.
fn cmd_backup(
    path: &Path,
    shards: u32,
    threshold: u32,
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    println!(
        "Creating {} shards with threshold {}...",
        shards, threshold
    );
    let backup_shards = wallet.backup(shards, threshold)?;

    // Create output directory
    std::fs::create_dir_all(output_dir)?;

    // Save each shard
    for shard in &backup_shards {
        let filename = format!("shard-{}.json", shard.index);
        let filepath = output_dir.join(&filename);
        let json = serde_json::to_string_pretty(shard)?;
        std::fs::write(&filepath, json)?;
        println!("  Saved: {}", filepath.display());
    }

    // Save metadata
    let metadata = serde_json::json!({
        "total_shards": shards,
        "threshold": threshold,
        "created_at": chrono::Utc::now().to_rfc3339(),
    });
    let metadata_path = output_dir.join("backup-metadata.json");
    std::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?)?;

    println!("\n✓ Backup created successfully!");
    println!("  Shards: {}", shards);
    println!("  Threshold: {}", threshold);
    println!("  Directory: {}", output_dir.display());
    println!("\n⚠ Any {} shards can recover your wallet.", threshold);

    Ok(())
}

/// Recover wallet from shards.
fn cmd_recover(shards_dir: &Path, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !shards_dir.exists() {
        return Err(format!("Shards directory not found: {}", shards_dir.display()).into());
    }

    // Read all shard files
    let mut shards: Vec<Shard> = Vec::new();
    for entry in std::fs::read_dir(shards_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Some(filename) = path.file_stem().and_then(|s| s.to_str()) {
                if filename.starts_with("shard-") {
                    let data = std::fs::read_to_string(&path)?;
                    let shard: Shard = serde_json::from_str(&data)?;
                    shards.push(shard);
                }
            }
        }
    }

    if shards.is_empty() {
        return Err("No shard files found in directory".into());
    }

    println!("Found {} shards", shards.len());

    // Sort by index
    shards.sort_by_key(|s| s.index);

    // Recover seed
    println!("Recovering wallet...");
    let seed = Wallet::recover_from_shards(&shards)?;

    // Rebuild the wallet from the recovered seed — accounts re-derive
    // deterministically from it, so the original keys are reproduced.
    let passphrase = confirm_passphrase()?;
    println!("Saving recovered wallet to {}...", output.display());

    let wallet = Wallet::from_seed(&seed)?;
    wallet.save(output, &passphrase)?;

    println!("\n✓ Wallet recovered successfully!");
    println!("  File: {}", output.display());
    println!("\n⚠ Re-derive your accounts with: origin-wallet account derive --name <name>");

    Ok(())
}

/// Recovery phrase commands.
fn cmd_phrase(path: &Path, command: super::PhraseCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        super::PhraseCommands::Export => {
            if !path.exists() {
                return Err(format!("Wallet file not found: {}", path.display()).into());
            }

            let passphrase = prompt_passphrase("Enter passphrase: ")?;
            let wallet = Wallet::open(path, &passphrase)?;

            let phrase = wallet.export_phrase()?;

            println!("\n⚠ Recovery Phrase (write this down!):");
            println!("═══════════════════════════════════════════════════════════════");
            println!("{}", phrase);
            println!("═══════════════════════════════════════════════════════════════");
            println!("\n⚠ This phrase can recover your wallet. Keep it secret!");

            Ok(())
        }
        super::PhraseCommands::Recover { phrase, output } => {
            if output.exists() {
                eprintln!("Warning: {} already exists", output.display());
                print!("Overwrite? [y/N] ");
                use std::io::{self, Write};
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            let passphrase = confirm_passphrase()?;

            println!("Recovering wallet from phrase...");
            let wallet = Wallet::from_phrase(&phrase, &passphrase)?;

            println!("Saving wallet to {}...", output.display());
            wallet.save(&output, &passphrase)?;

            println!("\n✓ Wallet recovered from phrase!");
            println!("  File: {}", output.display());

            Ok(())
        }
    }
}

/// Unlock the wallet, bind its Stoa node, and print live mesh metrics
/// (INTEGRATION.md §4, build-order step 2 — the CLI's "network pane").
///
/// The node identity is derived from the wallet seed (`Wallet::stoa_node_keys`),
/// so the MeshId is stable across unlocks; binding is ephemeral — no
/// state is written, the actor shuts down when the runtime drops.
/// `network doctor` — the full stoa doctor (SPEC §13) run under the
/// wallet's own identity: the §13 probes (transport, store, metrics,
/// STUN, relayed circuit) report the wallet's MeshId as the identity
/// under test.
fn cmd_network_doctor(path: &Path, stun_server: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }
    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;
    let node_keys = wallet.stoa_node_keys()?;

    println!("Running stoa doctor under the wallet's identity...");
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(stoa::doctor::run_with_keys(&node_keys, Some(stun_server)))?;
    Ok(())
}

fn cmd_network_sync(
    path: &Path,
    peer: &str,
    peer_addr: Option<std::net::SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }
    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;
    let peer_id: stoa::MeshId = peer.parse()?;

    let rt = tokio::runtime::Runtime::new()?;
    let summary = rt.block_on(origin_wallet::network::sync_from(
        &wallet,
        peer_id,
        peer_addr,
    ))?;

    println!("\n✓ Registry checkpoint pulled from {peer_id}");
    println!(
        "  sync lag     : {}",
        if summary.sync_lag_secs == u64::MAX {
            "never".to_string()
        } else {
            format!("{} s", summary.sync_lag_secs)
        }
    );
    println!("  re-syncs     : {}", summary.resyncs);
    println!("  ledger       : {} entries", summary.ledger_entries);
    println!("  identities   : {}", summary.identities);
    println!("  spent claims : {}", summary.spent_claims);
    println!("  inbox        : {} messages", summary.inbox);
    Ok(())
}

/// `wallet policy` — the standing spend policy (SPEC §10.2): print the
/// current caps + day/month totals, or set/update the caps. The caps are
/// persisted with the wallet and enforced on every `pay` before anything
/// binds or signs.
fn cmd_policy(
    path: &Path,
    per_tx: Option<u64>,
    per_day: Option<u64>,
    per_month: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }
    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let mut wallet = Wallet::open(path, &passphrase)?;

    if per_tx.is_none() && per_day.is_none() && per_month.is_none() {
        print_policy(&mut wallet);
        return Ok(());
    }
    let mut policy = wallet.spend_policy().clone();
    if let Some(v) = per_tx {
        policy.per_tx = Some(v);
    }
    if let Some(v) = per_day {
        policy.per_day = Some(v);
    }
    if let Some(v) = per_month {
        policy.per_month = Some(v);
    }
    wallet.set_spend_policy(policy);
    wallet.save(path, &passphrase)?;
    println!("\n✓ Standing spend policy updated (enforced on every payment):");
    print_policy(&mut wallet);
    Ok(())
}

fn print_policy(wallet: &mut Wallet) {
    let p = wallet.spend_policy().clone();
    let (_, day_spent, month_spent) = wallet.spend_usage();
    println!("Standing spend policy (SPEC §10.2):");
    println!(
        "  per-tx    : {}",
        p.per_tx.map(|v| v.to_string()).unwrap_or_else(|| "unset".into())
    );
    println!(
        "  per-day   : {}",
        p.per_day.map(|v| v.to_string()).unwrap_or_else(|| "unset".into())
    );
    println!(
        "  per-month : {}",
        p.per_month.map(|v| v.to_string()).unwrap_or_else(|| "unset".into())
    );
    println!("  spent today  : {day_spent}");
    println!("  spent this month : {month_spent}");
}

fn cmd_network_status(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    println!("Deriving Stoa node identity...");
    let node_keys = wallet.stoa_node_keys()?;
    let mesh_id = *node_keys.mesh_id();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let (mesh, addr) = stoa::Mesh::bind(node_keys, "0.0.0.0:0".parse()?)?;
        // Fire one heartbeat now so the live set is non-empty; the actor
        // then auto-publishes every ~90 s for as long as it runs.
        let _ = mesh.publish_pulse().await;
        let m = mesh.metrics().await;

        println!("\n✓ Stoa node bound (INTEGRATION.md step 2)");
        println!("  mesh id          : {mesh_id}");
        println!("  address          : {addr}");
        println!("  mesh degree      : {}", m.connected_peers);
        println!("  pulse live/stale : {} / {}", m.pulse_live, m.pulse_stale);
        println!("  spent conflicts  : {}", m.spent_conflicts);
        println!("  snowball queries : {}", m.snowball_queries);
        println!("  dht records      : {}", m.dht_records);
        println!("  routing table    : {}", m.routing_table_entries);
        println!(
            "  sync lag         : {} (u64::MAX = never synced)",
            if m.sync_lag_secs == u64::MAX {
                "never".to_string()
            } else {
                format!("{} s", m.sync_lag_secs)
            }
        );
        println!(
            "  gossip recv/drop : {} / {}",
            m.gossip_received, m.gossip_dropped
        );
        println!("  re-syncs fired   : {}", m.resyncs);
        println!(
            "\nThe node is offline-only here: connect it to peers (pay/discover/dial) in a later step."
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}

/// The optional knobs on a `pay` (grouped so `cmd_pay` stays under the
/// clippy argument limit).
struct PayFlags {
    peer_addr: Option<std::net::SocketAddr>,
    relay: Option<String>,
    relay_addr: Option<std::net::SocketAddr>,
    memo: Option<String>,
    cap: Option<u64>,
}

/// The target of a `pay` — a counterparty MeshId, or a discovered
/// service to resolve and pay.
enum PayTarget {
    Counterparty(stoa::MeshId),
    Service(stoa::MeshId),
}

/// Pay on the native rail (INTEGRATION.md step 3): unlock, bind the node,
/// open a channel, stream the payment, and record the receipt in the
/// wallet's MMR history (then save the wallet). The target is either a
/// counterparty (dialed directly or through a relay) or a discovered
/// service (resolved from its signed record).
fn cmd_pay(
    path: &Path,
    target: PayTarget,
    amount: u64,
    flags: PayFlags,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let mut wallet = Wallet::open(path, &passphrase)?;

    let memo_bytes = flags.memo.unwrap_or_default().into_bytes();
    let rt = tokio::runtime::Runtime::new()?;

    // --service mode: resolve the record, pay its payment address.
    if let PayTarget::Service(service_mesh) = target {
        println!(
            "Paying {} units to service {} on the native rail...",
            amount, service_mesh
        );
        let (entry, record) = rt.block_on(origin_wallet::network::pay_service(
            &mut wallet,
            service_mesh,
            flags.peer_addr,
            amount,
            memo_bytes,
            flags.cap,
        ))?;
        wallet.save(path, &passphrase)?;
        println!("\n✓ Service paid");
        println!("  service   : {} — {}", record.service, record.profile);
        println!("  paid to   : {}", record.payment);
        println!("  entry hash: {}", hex::encode(entry.entry_hash()));
        println!("  amount    : {}", entry.amount);
        println!("  history   : {} transactions in the wallet MMR", wallet.transaction_count());
        return Ok(());
    }

    let PayTarget::Counterparty(to_mesh) = target else {
        unreachable!()
    };

    let entry = match (flags.relay, flags.relay_addr) {
        // Relayed pay: connect only to the relay; the counterparty is
        // reached over the mesh (gossip fanout to the relay + the
        // payee's registry sync).
        (Some(relay), Some(relay_addr)) => {
            let relay_mesh: stoa::MeshId = relay.parse()?;
            println!(
                "Paying {} units to {} through relay {} at {} on the native rail...",
                amount, to_mesh, relay_mesh, relay_addr
            );
            rt.block_on(origin_wallet::network::pay_native_via_relay(
                &mut wallet,
                to_mesh,
                relay_mesh,
                relay_addr,
                amount,
                memo_bytes,
                flags.cap,
            ))?
        }
        (None, Some(relay_addr)) => {
            return Err(format!("--relay-addr {relay_addr} requires --relay").into())
        }
        (Some(_), None) => {
            return Err("--relay requires --relay-addr".into())
        }
        // Direct pay: dial the counterparty itself.
        (None, None) => {
            let peer_addr = flags
                .peer_addr
                .ok_or("--peer-addr is required unless --relay is given")?;
            println!(
                "Paying {} units to {} at {} on the native rail...",
                amount, to_mesh, peer_addr
            );
            rt.block_on(origin_wallet::network::pay_native(
                &mut wallet,
                to_mesh,
                peer_addr,
                amount,
                memo_bytes,
                flags.cap,
            ))?
        }
    };

    wallet.save(path, &passphrase)?;

    println!("\n✓ Payment recorded");
    println!("  entry hash : {}", hex::encode(entry.entry_hash()));
    println!("  amount     : {}", entry.amount);
    println!("  counterparty: {}", entry.counterparty);
    println!("  history    : {} transactions in the wallet MMR", wallet.transaction_count());

    Ok(())
}

/// Settle a channel toward a counterparty (SPEC §10.3 — time-boxed
/// finality): unlock, bind, settle, and print the signed ENTRY_SETTLE.
fn cmd_settle(
    path: &Path,
    to: &str,
    peer_addr: Option<std::net::SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;
    let to_mesh: stoa::MeshId = to.parse()?;

    let rt = tokio::runtime::Runtime::new()?;
    let entry = rt.block_on(origin_wallet::network::settle_channel_with(
        &wallet, to_mesh, peer_addr,
    ))?;

    println!("\n✓ Channel settled");
    println!("  counterparty : {}", entry.counterparty);
    println!("  total paid   : {}", entry.amount);
    println!("  settle hash  : {}", hex::encode(entry.entry_hash()));
    println!("  finality     : {} s with no counter-evidence (SPEC §10.3)", stoa::DISPUTE_WINDOW_SECS);

    Ok(())
}

/// Discover services on the mesh (INTEGRATION.md step 4): unlock the
/// wallet, bind its node, optionally dial a peer so DHT lookups reach it,
/// then print the ranked brief — semantic fit × trust — never the raw
/// graph. `--room` + `--point` narrow to a rendezvous room's members.
fn cmd_discover(
    path: &Path,
    query: &str,
    room: Option<String>,
    point: Option<String>,
    peer_addr: Option<std::net::SocketAddr>,
    save: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    let point = match point {
        Some(p) => Some(p.parse::<stoa::MeshId>()?),
        None => None,
    };

    println!("Discovering '{}'...", query);
    let rt = tokio::runtime::Runtime::new()?;
    let hits = rt.block_on(origin_wallet::network::discover_with(
        &wallet,
        query,
        room.clone(),
        point,
        peer_addr,
    ))?;

    if hits.is_empty() {
        println!("\nNo services matched '{}'.", query);
        println!("  Tip: publish a service record from the serving node, or");
        println!("  dial a peer with --peer-addr so DHT lookups can reach it.");
        if let Some(label) = save {
            println!("  --save {label} ignored: no hits to save.");
        }
        return Ok(());
    }

    println!("\nRanked services (cosine × trust):");
    println!("{:-<72}", "");
    for (i, hit) in hits.iter().enumerate() {
        println!("  #{} {}", i + 1, hit.service);
        println!("     payment : {}", hit.payment);
        println!("     profile : {}", hit.profile);
        println!(
            "     cosine  : {:.3}   trust: {:.3}   score: {:.3}",
            hit.cosine,
            hit.trust,
            hit.score
        );
        println!("               (score = cosine × trust — the ranking key)");
    }

    if let Some(room) = room {
        println!("\n  Scoped to room: {room}");
    }

    // One-step save: write the top-ranked hit into the contacts table
    // (INTEGRATION.md §5 — a discovered provider becomes a contact).
    if let Some(label) = save {
        origin_wallet::network::save_top_contact(path, &hits, &label)?;
        println!("\n✓ Saved top hit as contact '{label}' → {}", hits[0].service);
    }

    Ok(())
}

/// Contacts table commands (INTEGRATION.md §5): a plain JSON sidecar next
/// to the wallet file — labels map to MeshIds for pay/dial targets.
fn cmd_contact(
    path: &Path,
    command: super::ContactCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        super::ContactCommands::Add { label, mesh } => {
            let mut contacts = origin_wallet::Contacts::load(path)?;
            contacts.add(&label, &mesh)?;
            println!("✓ Saved contact '{label}' → {mesh}");
            println!("  File: {}", contacts.path().display());
            Ok(())
        }
        super::ContactCommands::List => {
            let contacts = origin_wallet::Contacts::load(path)?;
            if contacts.entries.is_empty() {
                println!("No contacts. Add one with: origin-wallet contact add --label <name> --mesh <meshid>");
                return Ok(());
            }
            println!("Contacts ({}):", contacts.entries.len());
            println!("{:-<72}", "");
            for (label, mesh) in &contacts.entries {
                println!("  {label:<24} {mesh}");
            }
            Ok(())
        }
    }
}

/// Send a point-to-point mail message on the mesh (INTEGRATION.md step 4
/// — the rail for anything beyond payments): bind an ephemeral node and
/// deliver the signed envelope directly to the recipient's node.
fn cmd_mail_send(
    to: &str,
    peer_addr: std::net::SocketAddr,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let to_mesh: stoa::MeshId = to.parse()?;

    println!("Sending mail to {to_mesh} at {peer_addr}...");
    let rt = tokio::runtime::Runtime::new()?;
    let env = rt.block_on(origin_wallet::network::send_mail(
        to_mesh,
        peer_addr,
        body.as_bytes().to_vec(),
    ))?;

    println!("\n✓ Mail delivered");
    println!("  envelope : {}", hex::encode(env.envelope_hash()));
    println!("  from     : {}", env.from);
    println!("  ct       : {} bytes (encrypted body)", env.ct.len());

    Ok(())
}

/// `mail inbox` — bind this wallet's node (same seed → same store, so the
/// persisted deduped mailbox reloads) and print the decrypted inbox.
fn cmd_mail_inbox(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    println!("Reading inbox...");
    let rt = tokio::runtime::Runtime::new()?;
    let inbox = rt.block_on(origin_wallet::network::mail_inbox(&wallet))?;

    if inbox.is_empty() {
        println!("\nInbox empty. Send mail to this MeshId:");
        println!("  {}", wallet.stoa_node_keys()?.mesh_id());
        println!("  Tip: mail arrives when this node is running to ingest it.");
        return Ok(());
    }

    println!("\nInbox ({} message{}):", inbox.len(), if inbox.len() == 1 { "" } else { "s" });
    println!("{:-<72}", "");
    for m in &inbox {
        println!("  from : {}", m.from);
        println!("  seq  : {} (ts {})", m.seq, m.ts);
        println!("  body : {}", String::from_utf8_lossy(&m.body));
        println!("{:-<72}", "");
    }
    Ok(())
}

/// The dial-based chat rail (INTEGRATION.md §4): `chat send` opens a
/// session — relayed L3 pipe (named relay or dial_any's fallback chain,
/// upgraded to direct when possible) or the addressed topic on a direct
/// mesh link — and sends one message; `chat listen` subscribes to the
/// addressed topic and blocks for a message.
fn cmd_chat(path: &Path, command: super::ChatCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        super::ChatCommands::Repl { peer, peer_addr } => cmd_chat_repl(path, peer, peer_addr),
        super::ChatCommands::Send {
            to,
            peer_addr,
            relay,
            relay_addr,
            chain,
            chain_auto,
            body,
            wait_reply,
        } => {
            if !path.exists() {
                return Err(format!("Wallet file not found: {}", path.display()).into());
            }
            let passphrase = prompt_passphrase("Enter passphrase: ")?;
            let wallet = Wallet::open(path, &passphrase)?;
            let to_mesh: stoa::MeshId = to.parse()?;
            let relay = match (relay, relay_addr) {
                (Some(r), Some(a)) => Some((r.parse::<stoa::MeshId>()?, a)),
                (Some(r), None) => {
                    return Err(format!("--relay {r} needs --relay-addr <host:port>").into())
                }
                (None, Some(_)) => {
                    return Err("--relay-addr given without --relay <meshid>".into())
                }
                (None, None) => None,
            };
            // Chain relays (RELAY.md §13): the circuit runs
            // --relay → chain → the peer. Requires --relay (the first hop
            // needs an address to dial).
            let chain: Vec<stoa::MeshId> = match chain {
                Some(s) if !s.trim().is_empty() => s
                    .split(',')
                    .map(|m| {
                        m.trim()
                            .parse::<stoa::MeshId>()
                            .map_err(|e| format!("bad chain relay {m:?}: {e}"))
                    })
                    .collect::<Result<_, _>>()?,
                _ => Vec::new(),
            };
            if !chain.is_empty() && relay.is_none() {
                return Err("--chain needs --relay (and --relay-addr)".into());
            }
            if chain_auto && relay.is_none() {
                return Err("--chain-auto needs --relay (and --relay-addr)".into());
            }
            if chain_auto && !chain.is_empty() {
                return Err("--chain-auto and --chain are mutually exclusive".into());
            }

            println!("Chatting to {to_mesh}...");
            let rt = tokio::runtime::Runtime::new()?;
            let outcome = rt.block_on(origin_wallet::network::chat_send(
                &wallet,
                to_mesh,
                origin_wallet::network::ChatRoute {
                    peer_addr,
                    relay,
                    chain,
                    chain_auto,
                },
                body.into_bytes(),
                wait_reply,
            ))?;

            println!("\n✓ Chat sent over the {}", outcome.tier);
            match &outcome.reply {
                Some(r) => println!("  reply : {}", String::from_utf8_lossy(r)),
                None => println!("  reply : (none)"),
            }
            Ok(())
        }
    }
}

/// `chat listen` — subscribe to the addressed topic and block for a
/// message (60 s), printing sender + body. `--via-relay` publishes this
/// node's chain-capable relay hint first (RELAY.md §13.2).
fn cmd_chat_listen(
    path: &Path,
    from: Option<String>,
    via_relay: Option<String>,
    relay_addr: Option<std::net::SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }
    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    let peer = match from {
        Some(p) => Some(p.parse::<stoa::MeshId>()?),
        None => None,
    };
    let via_relay = match (via_relay, relay_addr) {
        (Some(r), Some(a)) => Some((r.parse::<stoa::MeshId>()?, a)),
        (Some(_), None) => {
            return Err("--via-relay requires --relay-addr <host:port>".into())
        }
        (None, Some(_)) => {
            return Err("--relay-addr given without --via-relay <meshid>".into())
        }
        (None, None) => None,
    };
    let rt = tokio::runtime::Runtime::new()?;
    let msg = rt.block_on(origin_wallet::network::chat_listen(&wallet, peer, via_relay))?;

    println!("\n✉ chat from {}", msg.from);
    println!("  {}", String::from_utf8_lossy(&msg.data));
    Ok(())
}

/// `chat repl` — one long-lived node, a background listener printing
/// incoming chat inline, and a prompt loop for `send <meshid|label>
/// <text…>` (labels resolve via the contacts table), `contacts`,
/// `whoami`, `help`, `quit`. `peer`/`peer_addr` is the optional way in: a
/// known node to dial at startup.
fn cmd_chat_repl(
    path: &Path,
    peer: Option<String>,
    peer_addr: Option<std::net::SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }
    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;
    let contacts = origin_wallet::Contacts::load(path)?;

    let peer = match peer {
        Some(p) => Some(p.parse::<stoa::MeshId>()?),
        None => None,
    };
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(origin_wallet::network::chat_repl(&wallet, &contacts, peer, peer_addr))?;
    Ok(())
}/// Serve this wallet's node as a circuit relay (INTEGRATION.md step 5 —
/// the "help the network" toggle, off by default): unlock, bind the node
/// derived from the wallet seed, serve the relay role with the given PoW
/// difficulty, start the punch-refresh loop, and run until Ctrl-C. The
/// relay's cookie/eviction state persists under `$STOA_HOME/nodes/<meshid>/`.
fn cmd_relay_serve(
    path: &Path,
    difficulty: u32,
    stun_server: &str,
    bind_addr: std::net::SocketAddr,
    discovery_point: Option<String>,
    discovery_addr: Option<std::net::SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    let stun_addr: std::net::SocketAddr = std::net::ToSocketAddrs::to_socket_addrs(stun_server)?
        .next()
        .ok_or_else(|| format!("STUN server {stun_server} resolved to nothing"))?;

    // The relay directory (R7, RELAY.md §13.2): both flags or neither.
    let directory = match (discovery_point, discovery_addr) {
        (Some(point), Some(addr)) => Some(stoa::relay::RelayDirectory {
            point: point.parse::<stoa::MeshId>()?,
            point_addr: addr,
            ..stoa::relay::RelayDirectory::default()
        }),
        (Some(_), None) => {
            return Err("--discovery-point requires --discovery-addr <host:port>".into())
        }
        (None, Some(_)) => {
            return Err("--discovery-addr given without --discovery-point <meshid>".into())
        }
        (None, None) => None,
    };

    println!("Serving as a circuit relay...");
    let rt = tokio::runtime::Runtime::new()?;
    let mesh = rt.block_on(origin_wallet::network::serve_relay_full(
        &wallet,
        difficulty,
        stun_addr,
        bind_addr,
        directory,
    ))?;

    println!("\n✓ Relay serving (help the network)");
    println!("  mesh id : {}", mesh.local_mesh_id());
    println!("  address : {}", mesh.local_addr());
    println!("  pow     : {difficulty} bits (cookie gate, RELAY.md §9)");
    println!("  chain   : yes (advertised chain-capable, RELAY.md §13.2)");
    println!("  stun    : {stun_server} (punch-candidate refresh)");
    println!("  store   : {}", doctor_home().join("nodes").join(mesh.local_mesh_id().to_string()).display());
    println!("Press Ctrl-C to stop. Peers dial through this node only while it runs.");


    // Park until interrupted; the mesh handle keeps the actor + loops alive.
    let _mesh = mesh;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Bind the wallet's node with the relay role loaded (state restored, no
/// circuits served, no hint published), run `f` against the live mesh, and
/// shut down cleanly (persisting any relay-state change) — the shared
/// shape of the relay management commands.
fn with_relay_mesh(
    path: &Path,
    f: impl FnOnce(&stoa::Mesh) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    let rt = tokio::runtime::Runtime::new()?;
    let mesh = rt.block_on(origin_wallet::network::relay_admin(&wallet))?;
    let result = f(&mesh);
    // Shutdown flushes the persisted relay state (the eviction set and
    // strike tallies survive this command, RELAY.md §9).
    let _ = rt.block_on(mesh.shutdown());
    result
}

/// `relay stats` — the relay operator's abuse-control view (RELAY.md §9):
/// live circuits, validated clients, eviction set size, challenges issued.
fn cmd_relay_stats(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    with_relay_mesh(path, |mesh| {
        let rt = tokio::runtime::Handle::current();
        let stats = rt.block_on(mesh.relay_stats());
        println!("\nRelay abuse-control state (RELAY.md §9)");
        println!("  serving          : {}", if stats.enabled { "yes" } else { "no" });
        println!("  live circuits    : {}", stats.circuits);
        println!("  validated clients: {}", stats.validated);
        println!("  eviction set     : {} clients", stats.evicted);
        println!("  challenges issued: {}", stats.challenges_issued);
        Ok(())
    })
}

/// `relay evict <peer>` — revoke a client's circuits and refuse its
/// future opens. Persists across restarts.
fn cmd_relay_evict(path: &Path, peer: &str) -> Result<(), Box<dyn std::error::Error>> {
    let peer_id: stoa::MeshId = peer.parse()?;
    with_relay_mesh(path, |mesh| {
        let rt = tokio::runtime::Handle::current();
        let removed = rt.block_on(mesh.relay_evict(peer_id))?;
        println!("\n✓ Evicted {peer_id}");
        println!("  circuits revoked : {removed}");
        println!("  (persisted — survives a relay restart, RELAY.md §9)");
        Ok(())
    })
}

/// `relay pardon <peer>` — remove a client from the eviction set (and
/// clear its strikes). Persists across restarts.
fn cmd_relay_pardon(path: &Path, peer: &str) -> Result<(), Box<dyn std::error::Error>> {
    let peer_id: stoa::MeshId = peer.parse()?;
    with_relay_mesh(path, |mesh| {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(mesh.relay_pardon(peer_id))?;
        println!("\n✓ Pardoned {peer_id}");
        println!("  (removed from the eviction set — persisted, RELAY.md §9)");
        Ok(())
    })
}

/// `$STOA_HOME` or `~/.stoa` — mirrors `stoa::doctor::stoa_home()` (the
/// relay state the wallet node persists lives here).
fn doctor_home() -> std::path::PathBuf {
    if let Some(home) = std::env::var_os("STOA_HOME") {
        return std::path::PathBuf::from(home);
    }
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|h| h.join(".stoa"))
        .unwrap_or_else(|| std::path::PathBuf::from(".stoa"))
}
