// SPDX-License-Identifier: Apache-2.0

//! CLI implementations for origin-entropy — a thin shell over `crate::api`.

use crate::api::{self, EntropyStats};
use crate::cli::{AnalyzeArgs, CheckArgs, Commands};
use origin_common::read_input;

const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024; // 64 MiB hard cap

/// Read input from a file or stdin, rejecting oversized inputs before they can
/// blow the process's RSS.  This guard is the backstop; the SDK's
/// `compute_serial_correlation` was already rewritten to be allocation-free so
/// that even at the cap the process stays well within its means.
fn read_input_guarded(path: Option<&str>) -> Result<Vec<u8>, String> {
    let data = read_input(path)?;
    let len = data.len();
    if len > MAX_INPUT_BYTES {
        return Err(format!(
            "input too large: {len} bytes (hard cap {MAX_INPUT_BYTES} bytes / 64 MiB). \
             The entropy analysis is statistical and does not need gigabyte inputs — \
             sample down or stream the file first."
        ));
    }
    Ok(data)
}

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Analyze(args) => cmd_analyze(args),
        Commands::Check(args) => cmd_check(args),
    }
}

fn cmd_analyze(args: AnalyzeArgs) -> Result<(), String> {
    let data = read_input_guarded(args.input.as_deref())?;
    let stats = match EntropyStats::analyze(&data) {
        s => s,
    };

    // Chi-squared only meaningful with >= 256 bytes
    let chi_report = if data.len() >= 256 {
        Some((stats.chi_squared * 1e4).round() / 1e4)
    } else {
        None
    };
    let me_report = if data.len() >= 32 {
        Some((stats.min_entropy * 1e6).round() / 1e6)
    } else {
        None
    };

    match args.format.as_str() {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "length": data.len(),
                    "shannon_entropy": (stats.shannon * 1e6).round() / 1e6,
                    "min_entropy": me_report,
                    "chi_squared": chi_report,
                    "is_random": stats.is_random(),
                }))
                .unwrap()
            );
        }
        _ => {
            println!("length:           {}", data.len());
            println!("shannon_entropy:  {:.6}", stats.shannon);
            if let Some(me) = me_report {
                println!("min_entropy:      {:.6}", me);
            }
            if let Some(chi) = chi_report {
                println!("chi_squared:      {:.4}", chi);
            }
            println!("is_random:        {}", stats.is_random());
        }
    }
    Ok(())
}

fn cmd_check(args: CheckArgs) -> Result<(), String> {
    let data = read_input_guarded(args.input.as_deref())?;
    let report = match api::quality_check(&data, args.bits) {
        Ok(r) => r,
        Err(e) => return Err(e.to_string()),
    };

    match args.format.as_str() {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "passed": report.passed,
                    "issues": report.issues,
                    "bits": args.bits,
                }))
                .unwrap()
            );
        }
        _ => {
            println!(
                "quality_check: {}",
                if report.passed { "PASS" } else { "FAIL" }
            );
            println!("target_bits:   {}", args.bits);
            if !report.issues.is_empty() {
                println!("issues:");
                for issue in &report.issues {
                    println!("  - {issue}");
                }
            }
        }
    }
    if !report.passed {
        std::process::exit(1);
    }
    Ok(())
}
