// SPDX-License-Identifier: Apache-2.0

//! `origin-wallet` — Post-quantum secure Digital Wallet CLI
//!
//! A wallet with hybrid signatures (Ed25519 + Falcon-1024), stealth addresses,
//! and Reed-Solomon shard backup.
//!
//! ```bash
//! # Create a new wallet
//! origin-wallet create
//!
//! # Open existing wallet
//! origin-wallet open --file wallet.dat
//!
//! # List accounts
//! origin-wallet accounts --file wallet.dat
//!
//! # Derive new account
//! origin-wallet account derive --file wallet.dat --name "Savings"
//!
//! # Show balance
//! origin-wallet balance --file wallet.dat --account 0
//!
//! # Create backup shards
//! origin-wallet backup --file wallet.dat --shards 5 --threshold 3 --output ./shards/
//!
//! # Recover from shards
//! origin-wallet recover --shards ./shards/ --output recovered.dat
//!
//! # Export recovery phrase
//! origin-wallet phrase export --file wallet.dat
//!
//! # Recover from phrase
//! origin-wallet phrase recover --phrase "..." --output recovered.dat
//! ```

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

mod commands;

#[derive(Parser)]
#[command(
    name = "origin-wallet",
    version,
    about = "Post-quantum secure Digital Wallet",
    long_about = "A wallet with hybrid signatures (Ed25519 + Falcon-1024), stealth addresses,\n\
        and Reed-Solomon shard backup for the Origin crypto ecosystem."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Wallet file path (default: wallet.dat)
    #[arg(short, long, global = true, default_value = "wallet.dat")]
    file: PathBuf,

    /// Passphrase on the command line (non-interactive use: scripts, CI,
    /// tests). Omitted from shell history where possible; prefer the
    /// interactive prompt when a human is at the terminal.
    #[arg(short, long, global = true, hide_env_values = true)]
    passphrase: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new wallet with fresh seed
    Create {
        /// Output file path
        #[arg(short, long, default_value = "wallet.dat")]
        output: PathBuf,
    },

    /// Open an existing wallet and show info
    Open,

    /// List all accounts in the wallet
    Accounts,

    /// Account management
    Account {
        #[command(subcommand)]
        command: AccountCommands,
    },

    /// Show account balance
    Balance {
        /// Account index
        #[arg(short, long, default_value = "0")]
        account: u32,
    },

    /// Create backup shards using Reed-Solomon error correction
    Backup {
        /// Total number of shards
        #[arg(short, long, default_value_t = 5)]
        shards: u32,

        /// Minimum shards needed for recovery
        #[arg(short, long, default_value_t = 3)]
        threshold: u32,

        /// Output directory for shard files
        #[arg(short, long, default_value = "./shards")]
        output: PathBuf,
    },

    /// Recover wallet from backup shards
    Recover {
        /// Directory containing shard files
        #[arg(short, long)]
        shards: PathBuf,

        /// Output file for recovered wallet
        #[arg(short, long, default_value = "recovered.dat")]
        output: PathBuf,
    },

    /// Recovery phrase operations
    Phrase {
        #[command(subcommand)]
        command: PhraseCommands,
    },

    /// Pay an agent on the native rail (INTEGRATION.md step 3): bind the
    /// wallet's Stoa node, connect to the counterparty, open a channel,
    /// stream the payment, and record it in the wallet's MMR history.
    /// With --relay, pay through the relay instead of dialing the
    /// counterparty directly (A→relay→C). With --service, pay a
    /// discovered service's published payment address (the "call this
    /// provider" action).
    Pay {
        /// Counterparty MeshId (64 hex chars)
        #[arg(long)]
        to: Option<String>,
        /// A discovered service's MeshId — resolves its signed record
        /// (local cache or DHT) and pays its payment address
        #[arg(long)]
        service: Option<String>,
        /// Amount in the smallest unit
        #[arg(long)]
        amount: u64,
        /// The counterparty node's dial address (host:port) — required
        /// unless --relay is given
        #[arg(long)]
        peer_addr: Option<SocketAddr>,
        /// A relay to circuit the payment through (MeshId) — with
        /// --relay-addr. When set, the counterparty is never dialed
        /// directly; delivery rides gossip + registry sync through the
        /// relay.
        #[arg(long)]
        relay: Option<String>,
        /// The relay node's dial address (host:port)
        #[arg(long)]
        relay_addr: Option<SocketAddr>,
        /// Optional memo
        #[arg(long)]
        memo: Option<String>,    /// Per-transaction spend cap (SPEC §10.2 SpendPolicy narrowing):
    /// refuse the payment outright if the amount exceeds it
    #[arg(long)]
    cap: Option<u64>,
    },

    /// Standing spend policy (SPEC §10.2): per-transaction / per-day /
    /// per-month caps enforced on every payment. With no flags, prints
    /// the current policy and the day/month totals spent against it.
    /// Caps are persisted with the wallet.
    Policy {
        /// Per-transaction cap (max per single payment)
        #[arg(long)]
        per_tx: Option<u64>,
        /// Per-day cap (calendar day)
        #[arg(long)]
        per_day: Option<u64>,
        /// Per-month cap (calendar month)
        #[arg(long)]
        per_month: Option<u64>,
    },

    /// Settle a channel toward a counterparty (SPEC §10.3 — time-boxed
    /// finality): record the total paid out as an ENTRY_SETTLE. The
    /// peer's symmetric settle is the double-entry leg; finality is 60 s
    /// with no counter-evidence.
    Settle {
        /// Counterparty MeshId (64 hex chars)
        #[arg(long)]
        to: String,
        /// The counterparty node's dial address (host:port), optional —
        /// for the gossip + sync delivery of the settle entry
        #[arg(long)]
        peer_addr: Option<SocketAddr>,
    },

    /// Stoa network operations (the embedded P2P node, INTEGRATION.md §4)
    Network {
        #[command(subcommand)]
        command: NetworkCommands,
    },

    /// Listen for chat on the addressed topic (blocks until a message
    /// arrives or 60 s pass).
    ChatListen {
        /// Only messages addressed to this peer's topic (default: ours)
        #[arg(long)]
        from: Option<String>,
    },

    /// Relay operations: serve circuits (the "help the network" toggle),
    /// or manage the relay's abuse-control state — stats, evictions,
    /// pardons (RELAY.md §9).
    Relay {
        #[command(subcommand)]
        command: RelayCommands,
    },

    /// Discover services on the mesh, ranked by semantic fit × trust
    /// (INTEGRATION.md step 4).
    Discover {
        /// Free-text query for the semantic profile match
        #[arg(long)]
        query: String,
        /// Rendezvous room to scope discovery to (e.g. providers:inference)
        #[arg(long)]
        room: Option<String>,
        /// Rendezvous point MeshId for the room query
        #[arg(long)]
        point: Option<String>,
        /// Peer to dial first so DHT lookups reach it (host:port)
        #[arg(long)]
        peer_addr: Option<SocketAddr>,
        /// Save the top-ranked hit to the contacts table under this label
        #[arg(long)]
        save: Option<String>,
    },

    /// Contacts table: the label → MeshId phone book (INTEGRATION.md §5)
    Contact {
        #[command(subcommand)]
        command: ContactCommands,
    },

    /// Store-and-forward mail on the mesh (INTEGRATION.md §5a)
    Mail {
        #[command(subcommand)]
        command: MailCommands,
    },

    /// Dial-based chat (INTEGRATION.md §4 — the real-time rail, not
    /// store-and-forward mail): open a relayed session to the peer (or
    /// deliver over the addressed topic on a direct mesh link) and send
    /// one message.
    Chat {
        #[command(subcommand)]
        command: ChatCommands,
    },
}

#[derive(Subcommand)]
enum RelayCommands {
    /// Opt this wallet's node into serving as a circuit relay
    /// (INTEGRATION.md step 5 — "help the network", off by default).
    /// Serves until Ctrl-C.
    Serve {
        /// Stealth-PoW difficulty for the relay's cookie gate (RELAY.md §9)
        #[arg(long, default_value_t = 16)]
        difficulty: u32,
        /// STUN server for punch-candidate refresh (host:port)
        #[arg(long, default_value = "stun.l.google.com:19302")]
        stun_server: String,
        /// Bind address (default: an ephemeral port on all interfaces —
        /// pin one for automation/tests so the port is known in advance)
        #[arg(long, default_value = "0.0.0.0:0")]
        addr: std::net::SocketAddr,
    },
    /// Show the relay's abuse-control state: live circuits, validated
    /// clients, eviction set size, challenges issued (RELAY.md §9).
    Stats,
    /// Evict a client: revoke its circuits and refuse future opens.
    /// Persists across restarts.
    Evict {
        /// The client's MeshId (64 hex chars)
        #[arg(long)]
        peer: String,
    },
    /// Pardon a client: remove it from the eviction set (and clear its
    /// strikes). Persists across restarts.
    Pardon {
        /// The client's MeshId (64 hex chars)
        #[arg(long)]
        peer: String,
    },
}

#[derive(Subcommand)]
enum MailCommands {
    /// Send a point-to-point mail message on the mesh
    Send {
        /// Recipient MeshId (64 hex chars)
        #[arg(long)]
        to: String,
        /// The recipient node's dial address (host:port)
        #[arg(long)]
        peer_addr: SocketAddr,
        /// Message body
        #[arg(long)]
        body: String,
    },
    /// Read this wallet's decrypted inbox (persisted deduped mailbox —
    /// the receive side of the mail contract).
    Inbox,
}

#[derive(Subcommand)]
enum ChatCommands {
    /// Interactive REPL: one long-lived node, a background listener that
    /// prints incoming messages inline, and a prompt for
    /// `send <meshid> <text…>`, `whoami`, `help`, `quit`.
    Repl {
        /// A known node to dial at startup (the way in) — its MeshId
        #[arg(long)]
        peer: Option<String>,
        /// The known node's dial address (host:port)
        #[arg(long)]
        peer_addr: Option<SocketAddr>,
    },

    /// Send one chat message over a session to the peer
    Send {
        /// Recipient MeshId (64 hex chars)
        #[arg(long)]
        to: String,
        /// The recipient node's dial address (host:port)
        #[arg(long)]
        peer_addr: Option<SocketAddr>,
        /// A relay to circuit through (MeshId) — with --relay-addr
        #[arg(long)]
        relay: Option<String>,
        /// The relay node's dial address (host:port)
        #[arg(long)]
        relay_addr: Option<SocketAddr>,
        /// Extra chain relays (comma-separated MeshIds) — with --relay,
        /// the circuit runs --relay → these → the peer, so no single
        /// relay on the path learns both endpoints (RELAY.md §13).
        #[arg(long)]
        chain: Option<String>,
        /// Message body
        #[arg(long)]
        body: String,
        /// Await the peer's reply frame on the session (relayed tier)
        #[arg(long)]
        wait_reply: bool,
    },
}

#[derive(Subcommand)]
enum ContactCommands {
    /// Add or replace a contact (label → MeshId)
    Add {
        /// Contact label
        #[arg(long)]
        label: String,
        /// MeshId (64 hex chars)
        #[arg(long)]
        mesh: String,
    },

    /// List all contacts
    List,
}

#[derive(Subcommand)]
enum NetworkCommands {
    /// Unlock the wallet, bind its Stoa node, and print live mesh metrics
    /// (mesh degree, pulse liveness, sync lag, gossip drop rate).
    Status,

    /// Run the full stoa doctor (SPEC §13 probes) under the wallet's own
    /// identity: data home, key derivation, transport self-test, store,
    /// live metrics, STUN reachability, and the relayed-circuit
    /// self-test — the wallet's MeshId is the identity under test.
    Doctor {
        /// STUN server for the reachability probe (default: the public
        /// Google server; point at a LAN server for offline networks)
        #[arg(long, default_value = "stun.l.google.com:19302")]
        stun_server: String,
    },

    /// Bind this wallet's node and pull the registry checkpoint from a
    /// known peer NOW — the manual "pull now" for a payment or mail
    /// already sitting on the mesh (the automatic cadence is 60 s,
    /// SPEC §6.2).
    Sync {
        /// The peer's MeshId (64 hex chars) — the transport is
        /// identity-pinned, so this is the trust anchor
        #[arg(long)]
        peer: String,
        /// Optional direct address (omit to resolve via the transport
        /// fallback: punch candidates, then the peer's relay record)
        #[arg(long)]
        peer_addr: Option<std::net::SocketAddr>,
    },
}

#[derive(Subcommand)]
enum AccountCommands {
    /// Derive a new account
    Derive {
        /// Account name/label
        #[arg(short, long)]
        name: String,

        /// Account index (optional, auto-assigned if not provided)
        #[arg(short, long)]
        index: Option<u32>,
    },

    /// Show account details
    Show {
        /// Account index
        #[arg(short, long, default_value = "0")]
        account: u32,
    },
}

#[derive(Subcommand)]
enum PhraseCommands {
    /// Export wallet as recovery phrase
    Export,

    /// Recover wallet from recovery phrase
    Recover {
        /// Recovery phrase
        #[arg(short, long)]
        phrase: String,

        /// Output file path
        #[arg(short, long, default_value = "recovered.dat")]
        output: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = commands::execute(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
