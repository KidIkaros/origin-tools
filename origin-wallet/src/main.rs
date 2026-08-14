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
