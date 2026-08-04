// SPDX-License-Identifier: Apache-2.0

//! `origin` — unified CLI for the origin-tools cryptographic suite.
//!
//! A single entry point that dispatches to each tool as a subcommand:
//!
//! ```bash
//! origin identity keygen --name personal
//! origin seed generate
//! origin seal encrypt --input file.txt
//! origin shard split --input file.txt --total 6 --data 4
//! ```
//!
//! Each subcommand reuses the exact same CLI definitions and command
//! implementations as the standalone `origin-*` binaries, so behavior
//! is identical. The standalone binaries remain available for scripting.

use clap::{Parser, Subcommand};

mod doctor;

#[derive(Parser)]
#[command(
    name = "origin",
    version,
    about = "Unified CLI for the origin-tools cryptographic suite",
    long_about = "One identity, one home, tools that compose.\n\n\
        Each subcommand maps to a standalone origin-* tool. Run \
        `origin <tool> --help` for tool-specific options."
)]
struct Cli {
    #[command(subcommand)]
    command: Tool,
}

#[derive(Subcommand)]
enum Tool {
    /// Identity key management (keygen, sign, verify, list, import)
    Identity(origin_identity::cli::Cli),
    /// Encrypted password vault + 2FA (TOTP/HOTP)
    Pass(origin_pass::cli::Cli),
    /// Data operations (encrypt, decrypt, sign, verify, hash, mac, kdf)
    Seal(origin_seal::cli::Cli),
    /// Seed lifecycle (generate, derive, blob create/recover)
    Seed(origin_seed::cli::Cli),
    /// Reed-Solomon secret sharing (split, recover)
    Shard(origin_shard::cli::Cli),
    /// MMR integrity proofs (append, root, prove, verify)
    Proof(origin_proof::cli::Cli),
    /// Stealth addresses + proof-of-work
    Stealth(origin_stealth::cli::Cli),
    /// Entropy analysis and quality gates
    Entropy(origin_entropy::cli::Cli),
    /// EC-Schnorr zero-knowledge proofs
    Schnorr(origin_schnorr::cli::Cli),
    /// Encrypted sessions (Noise handshake, ratchet, AEAD messaging)
    Channel(origin_channel::cli::Cli),
    /// File provenance (stamps, manifests, watermarks, verification)
    Provenance(origin_provenance::cli::Cli),
    /// Health-check your ~/.origin setup
    Doctor,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Tool::Identity(sub) => origin_identity::commands::dispatch(sub),
        Tool::Pass(sub) => origin_pass::commands::dispatch(sub),
        Tool::Seal(sub) => origin_seal::commands::dispatch(sub),
        Tool::Seed(sub) => origin_seed::commands::dispatch(sub),
        Tool::Shard(sub) => origin_shard::commands::dispatch(sub),
        Tool::Proof(sub) => origin_proof::commands::dispatch(sub),
        Tool::Stealth(sub) => origin_stealth::commands::dispatch(sub),
        Tool::Entropy(sub) => origin_entropy::commands::dispatch(sub),
        Tool::Schnorr(sub) => origin_schnorr::commands::dispatch(sub),
        Tool::Channel(sub) => origin_channel::commands::dispatch(sub),
        Tool::Provenance(sub) => origin_provenance::commands::dispatch(sub),
        Tool::Doctor => doctor::run(),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
