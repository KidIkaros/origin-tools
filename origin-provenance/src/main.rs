// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use origin_provenance::cli::Cli;

fn main() {
    let cli = Cli::parse();
    match origin_provenance::commands::dispatch(cli) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
