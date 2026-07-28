// SPDX-License-Identifier: Apache-2.0

use origin_common::read_input;
use crate::cli::{AnalyzeArgs, CheckArgs, Commands};

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Analyze(args) => cmd_analyze(args),
        Commands::Check(args) => cmd_check(args),
    }
}

/// Shannon entropy in bits per byte.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Chi-squared statistic for byte uniformity.
fn chi_squared(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let expected = data.len() as f64 / 256.0;
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let mut chi = 0.0;
    for &c in &counts {
        let diff = c as f64 - expected;
        chi += diff * diff / expected;
    }
    chi
}

/// Minimum entropy estimate (conservative, based on most frequent byte).
fn min_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let max_count = *counts.iter().max().unwrap() as f64;
    let len = data.len() as f64;
    if max_count == len { return 0.0; }
    let p = max_count / len; // all same byte
    -p.log2()
}

fn cmd_analyze(args: AnalyzeArgs) -> Result<(), String> {
    let data = read_input(args.input.as_deref())?;
    let h = shannon_entropy(&data);
    let chi = chi_squared(&data);
    let me = min_entropy(&data);

    // Chi-squared only meaningful with >= 256 bytes
    let chi_report = if data.len() >= 256 { Some((chi * 1e4).round() / 1e4) } else { None };
    let me_report = if data.len() >= 32 { Some((me * 1e6).round() / 1e6) } else { None };

    match args.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "length": data.len(),
                "shannon_entropy": (h * 1e6).round() / 1e6,
                "min_entropy": me_report,
                "chi_squared": chi_report,
                "is_random": h > 7.5,
            })).unwrap());
        }
        _ => {
            println!("length:           {}", data.len());
            println!("shannon_entropy:  {:.6}", h);
            if let Some(me) = me_report {
                println!("min_entropy:      {:.6}", me);
            }
            if let Some(chi) = chi_report {
                println!("chi_squared:      {:.4}", chi);
            }
            println!("is_random:        {}", h > 7.5);
        }
    }
    Ok(())
}

fn cmd_check(args: CheckArgs) -> Result<(), String> {
    let data = read_input(args.input.as_deref())?;
    let h = shannon_entropy(&data);
    let me = min_entropy(&data);

    let expected_bytes = (args.bits as usize + 7) / 8;
    let mut issues = Vec::new();
    let mut passed = true;

    // Length check
    if data.len() < expected_bytes {
        issues.push(format!(
            "input too short: {} bytes, expected >= {} for {} bits",
            data.len(), expected_bytes, args.bits
        ));
        passed = false;
    }

    // Shannon entropy (skip for very small samples — statistical tests are unreliable)
    if data.len() >= 256 {
        if h < 7.5 {
            issues.push(format!("Shannon entropy too low: {:.4} bits/byte (need >= 7.5)", h));
            passed = false;
        }
        if me < 6.0 {
            issues.push(format!("Min-entropy too low: {:.4} (need >= 6.0)", me));
            passed = false;
        }
        // Chi-squared only meaningful with enough data
        let chi = chi_squared(&data);
        if chi > 350.0 {
            issues.push(format!("Chi-squared too high: {:.2} (distribution is non-uniform)", chi));
            passed = false;
        }
    } else {
        // For small samples, warn but don't fail on entropy alone
        eprintln!("note: sample size {} is too small for statistical tests (need >= 256)", data.len());
    }

    match args.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "passed": passed,
                "issues": issues,
                "bits": args.bits,
            })).unwrap());
        }
        _ => {
            println!("quality_check: {}", if passed { "PASS" } else { "FAIL" });
            println!("target_bits:   {}", args.bits);
            if !issues.is_empty() {
                println!("issues:");
                for issue in &issues {
                    println!("  - {issue}");
                }
            }
        }
    }
    if !passed {
        std::process::exit(1);
    }
    Ok(())
}
