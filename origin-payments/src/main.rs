// SPDX-License-Identifier: Apache-2.0

//! `origin-payments` CLI entry point.

use std::process::ExitCode;

use clap::Parser;

use origin_payments::cli::Cli;
use origin_payments::{commands, payments_root, Error};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;

    let result = (|| -> Result<(), Error> {
        let root = payments_root(cli.home.as_deref())?;
        commands::dispatch(cli, &root)
    })();

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if json {
                let payload = serde_json::json!({
                    "ok": false,
                    "code": e.code(),
                    "message": e.to_string(),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            } else {
                eprintln!("Error: {e}");
            }
            ExitCode::from(e.exit_code() as u8)
        }
    }
}
