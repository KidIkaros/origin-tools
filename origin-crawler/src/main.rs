// SPDX-License-Identifier: Apache-2.0

//! origin-crawler — polite BFS web crawler CLI.
//!
//! Crawls breadth-first from seed URLs with a URL frontier that enforces
//! per-host politeness delays, honors robots.txt, de-duplicates content by
//! BLAKE3 hash (via origin-crypto-sdk), and guards against spider traps.
//! Emits a JSON crawl report on stdout.

use clap::Parser;

fn main() {
    let cli = origin_crawler::cli::Cli::parse();
    if let Err(e) = origin_crawler::commands::dispatch(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
