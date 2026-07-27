// SPDX-License-Identifier: Apache-2.0

//! origin-identity — Identity key management.
//!
//! Generate master seeds, hybrid sign/verify with Ed25519 + Falcon-1024,
//! manage encrypted identity blobs, and restore from a recovery phrase.
//!
//! # Subcommands
//!
//! | Subcommand | Purpose |
//! |------------|---------|
//! | `keygen`   | Generate a new identity (with optional recovery phrase) |
//! | `sign`     | Hybrid-sign a message (literal, @file, or --hex bytes) |
//! | `verify`   | Verify a hybrid signature (JSON file or --hex raw bytes) |
//! | `list`     | List identities in the default directory (fingerprint-based) |
//! | `import`   | Restore an identity from a 24-word Unicode recovery phrase |
//!
//! # Example
//!
//! ```bash
//! origin-identity keygen --name personal
//! origin-identity list
//! origin-identity sign --name personal --message @file.txt
//! origin-identity verify --name personal --message @file.txt --signature sig.json
//! origin-identity import --name recovered --phrase "α β γ … ω"
//! ```

mod cli;
mod commands;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();

    let result = match cli.command {
        cli::Commands::Keygen(args) => commands::cmd_keygen(args),
        cli::Commands::Sign(args) => commands::cmd_sign(args),
        cli::Commands::Verify(args) => commands::cmd_verify(args),
        cli::Commands::List(args) => commands::cmd_list(args),
        cli::Commands::Import(args) => commands::cmd_import(args),
        cli::Commands::Show(args) => commands::cmd_show(args),
        cli::Commands::Rename(args) => commands::cmd_rename(args),
        cli::Commands::Delete(args) => commands::cmd_delete(args),
        cli::Commands::ExportPubkey(args) => commands::cmd_export_pubkey(args),
        cli::Commands::RotatePassphrase(args) => commands::cmd_rotate_passphrase(args),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
