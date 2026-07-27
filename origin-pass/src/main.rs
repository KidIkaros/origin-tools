// SPDX-License-Identifier: Apache-2.0

//! `origin-pass` — encrypted password vault + 2FA authenticator (TOTP/HOTP).
//!
//! Built on `origin-crypto-sdk` using the same vault format documented in
//! `origin-crypto-sdk/docs/tools/DESIGN.md` §4 (OVLT header, ChaCha20-BLAKE3
//! per-entry AEAD, Argon2id-derived master key).
//!
//! # v0.1.0 (this scaffold)
//!
//! The CLI surface and module skeleton are in place but the cmd_*
//! implementations are stubs returning `todo!()` so that `cargo check`
//! resolves cleanly. Each stub will be replaced per the implementation
//! sequencing in `origin-tools/DESIGN.md` §6.
//!
//! # Subcommands
//!
//! | Subcommand      | Purpose                                                        |
//! |-----------------|----------------------------------------------------------------|
//! | `init`          | Create a new vault                                             |
//! | `unlock`        | Unlock the vault into session memory                           |
//! | `lock`          | Drop the in-memory unlocked vault                              |
//! | `add`           | Add or update an entry (password or OTP)                       |
//! | `get`           | Retrieve a single entry                                        |
//! | `list`          | List entry names + types (no secrets)                          |
//! | `rm`            | Remove an entry                                                |
//! | `code`          | Compute and display a TOTP/HOTP code from a stored secret       |
//! | `export-qr`     | Print the `otpauth://` URI for QR provisioning                  |
//! | `import-qr`     | Add an entry by parsing an `otpauth://` URI                     |
//! | `change-passphrase` | Re-encrypt the vault header with a new master passphrase    |
//!
//! See `origin-tools/DESIGN.md` for the threat model + CLI conventions.

mod cli;
mod commands;
mod vault;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();

    let result = match cli.command {
        cli::Commands::Init(args) => commands::cmd_init(args),
        cli::Commands::Unlock(args) => commands::cmd_unlock(args),
        cli::Commands::Lock(args) => commands::cmd_lock(args),
        cli::Commands::Add(args) => commands::cmd_add(args),
        cli::Commands::Get(args) => commands::cmd_get(args),
        cli::Commands::List(args) => commands::cmd_list(args),
        cli::Commands::Rm(args) => commands::cmd_rm(args),
        cli::Commands::Code(args) => commands::cmd_code(args),
        cli::Commands::ExportQr(args) => commands::cmd_export_qr(args),
        cli::Commands::ImportQr(args) => commands::cmd_import_qr(args),
        cli::Commands::ChangePassphrase(args) => commands::cmd_change_passphrase(args),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
