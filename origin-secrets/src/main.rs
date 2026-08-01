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
use origin_secrets::cli::Cli;

fn main() {
    let cli = Cli::parse();

    if let Err(e) = origin_secrets::dispatch(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
