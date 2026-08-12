// SPDX-License-Identifier: Apache-2.0

//! origin-archive — atomic compress-then-encrypt CLI.
//!
//! Compress (Zstd/DEFLATE) then encrypt (ChaCha20-BLAKE3 with STREAM nonce
//! construction) in one all-or-nothing operation. The inverse `unarchive`
//! verifies all AEAD tags before decompressing.

use clap::Parser;

fn main() {
    let cli = origin_archive::cli::Cli::parse();
    if let Err(e) = origin_archive::commands::dispatch(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
