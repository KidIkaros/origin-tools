// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use origin_memory::cli::Cli;

fn main() {
    let cli = Cli::parse();
    match origin_memory::commands::dispatch(cli) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
