//! # Origin Secrets
//!
//! Threshold secrets management CLI — K-of-N recovery, post-quantum verification.
//!
//! ## Commands
//!
//! - `init`: Initialize vault with Argon2id KDF
//! - `shard`: Shard master key via Reed-Solomon (K-of-N)
//! - `export-share`: Export share to encrypted file
//! - `recover`: Recover master key from threshold shares
//! - `verify`: Verify signatures/integrity
//! - `audit`: View/export audit logs (SOC2, PCI-DSS, HIPAA)
//!
//! ## Architecture
//!
//! - Vault: Encrypted master seed + metadata (XChaCha20-Poly1305)
//! - Shares: Reed-Solomon K-of-N with hybrid signatures (Ed25519 + Falcon-1024)
//! - Audit: Append-only log with compliance export

use clap::Parser;
use origin_secrets::cli::{Cli, Commands};
use origin_secrets::observability;
use serde_json::json;

/// Human-readable command name for the failure journal.
fn command_name(cmd: &Commands) -> &'static str {
    match cmd {
        Commands::Init(_) => "init",
        Commands::Shard(_) => "shard",
        Commands::ExportShare(_) => "export-share",
        Commands::Recover(_) => "recover",
        Commands::Verify(_) => "verify",
        Commands::Audit(_) => "audit",
        Commands::RotatePassphrase(_) => "rotate-passphrase",
        Commands::ListKeys(_) => "list-keys",
        Commands::ListShares(_) => "list-shares",
        Commands::Completions(_) => "completions",
    }
}

fn main() {
    // Handle --version without requiring a subcommand (clap still treats the
    // subcommand as mandatory even with an exclusive flag present).
    if std::env::args().any(|a| a == "--version") {
        println!("origin-secrets {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let cli = Cli::parse();
    let json = cli.json;
    let cmd_name = command_name(&cli.command);

    let result = origin_secrets::dispatch(cli);
    if result.is_ok() {
        return;
    }

    let e = result.unwrap_err();
    observability::record_failure(&e, cmd_name);
    if json {
        println!(
            "{}",
            json!({
                "ok": false,
                "code": e.code(),
                "severity": e.severity(),
                "message": e.to_string(),
            })
        );
    } else {
        eprintln!("Error: {}", e);
    }
    std::process::exit(e.exit_code());
}
