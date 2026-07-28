// SPDX-License-Identifier: Apache-2.0

//! origin-seal — data operations CLI.
//!
//! Encrypt, decrypt, sign, verify, hash, MAC, and KDF over stdin/stdout,
//! built entirely on origin-crypto-sdk primitives.

use clap::Parser;

fn main() {
    let cli = origin_seal::cli::Cli::parse();
    if let Err(e) = origin_seal::commands::dispatch(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
