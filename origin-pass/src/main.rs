// SPDX-License-Identifier: Apache-2.0

//! `origin-pass` — encrypted password vault + 2FA authenticator (TOTP/HOTP).

use clap::Parser;

fn main() {
    let cli = origin_pass::cli::Cli::parse();
    if let Err(e) = origin_pass::commands::dispatch(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
