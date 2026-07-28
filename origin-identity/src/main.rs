// SPDX-License-Identifier: Apache-2.0

//! origin-identity — Identity key management.
//!
//! Generate master seeds, hybrid sign/verify with Ed25519 + Falcon-1024,
//! manage encrypted identity blobs, and restore from a recovery phrase.

use clap::Parser;

fn main() {
    let cli = origin_identity::cli::Cli::parse();
    if let Err(e) = origin_identity::commands::dispatch(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
