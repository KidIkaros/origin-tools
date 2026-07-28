// SPDX-License-Identifier: Apache-2.0

//! origin-seal — data operations CLI.
//!
//! Encrypt, decrypt, sign, verify, hash, MAC, and KDF over stdin/stdout,
//! built entirely on origin-crypto-sdk primitives.

mod cli;
mod commands;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Hash(args) => commands::cmd_hash(args),
        Commands::Encrypt(args) => commands::cmd_encrypt(args),
        Commands::Decrypt(args) => commands::cmd_decrypt(args),
        Commands::Sign(args) => commands::cmd_sign(args),
        Commands::Verify(args) => commands::cmd_verify(args),
        Commands::Kdf(args) => commands::cmd_kdf(args),
        Commands::Mac(args) => commands::cmd_mac(args),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
