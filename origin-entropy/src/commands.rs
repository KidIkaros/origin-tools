// SPDX-License-Identifier: Apache-2.0

use crate::cli::{AnalyzeArgs, CheckArgs, Commands};
use origin_common::read_input;

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Analyze(args) => cmd_analyze(args),
        Commands::Check(args) => cmd_check(args),
    }
}

/// Shannon entropy in bits per byte.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
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
    if data.is_empty() {
        return 0.0;
    }
    let expected = data.len() as f64 / 256.0;
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut chi = 0.0;
    for &c in &counts {
        let diff = c as f64 - expected;
        chi += diff * diff / expected;
    }
    chi
}

/// Minimum entropy estimate (conservative, based on most frequent byte).
fn min_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let max_count = *counts.iter().max().unwrap() as f64;
    let len = data.len() as f64;
    if max_count == len {
        return 0.0;
    }
    let p = max_count / len; // all same byte
    -p.log2()
}

fn cmd_analyze(args: AnalyzeArgs) -> Result<(), String> {
    let data = read_input(args.input.as_deref())?;
    let h = shannon_entropy(&data);
    let chi = chi_squared(&data);
    let me = min_entropy(&data);

    // Chi-squared only meaningful with >= 256 bytes
    let chi_report = if data.len() >= 256 {
        Some((chi * 1e4).round() / 1e4)
    } else {
        None
    };
    let me_report = if data.len() >= 32 {
        Some((me * 1e6).round() / 1e6)
    } else {
        None
    };

    match args.format.as_str() {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "length": data.len(),
                    "shannon_entropy": (h * 1e6).round() / 1e6,
                    "min_entropy": me_report,
                    "chi_squared": chi_report,
                    "is_random": h > 7.5,
                }))
                .unwrap()
            );
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

    let expected_bytes = (args.bits as usize).div_ceil(8);
    let mut issues = Vec::new();
    let mut passed = true;

    // Length check
    if data.len() < expected_bytes {
        issues.push(format!(
            "input too short: {} bytes, expected >= {} for {} bits",
            data.len(),
            expected_bytes,
            args.bits
        ));
        passed = false;
    }

    // Shannon entropy (skip for very small samples — statistical tests are unreliable)
    if data.len() >= 256 {
        if h < 7.5 {
            issues.push(format!(
                "Shannon entropy too low: {:.4} bits/byte (need >= 7.5)",
                h
            ));
            passed = false;
        }
        if me < 6.0 {
            issues.push(format!("Min-entropy too low: {:.4} (need >= 6.0)", me));
            passed = false;
        }
        // Chi-squared only meaningful with enough data
        let chi = chi_squared(&data);
        if chi > 350.0 {
            issues.push(format!(
                "Chi-squared too high: {:.2} (distribution is non-uniform)",
                chi
            ));
            passed = false;
        }
    } else {
        // For small samples, warn but don't fail on entropy alone
        eprintln!(
            "note: sample size {} is too small for statistical tests (need >= 256)",
            data.len()
        );
    }

    match args.format.as_str() {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "passed": passed,
                    "issues": issues,
                    "bits": args.bits,
                }))
                .unwrap()
            );
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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_zero_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(chi_squared(&[]), 0.0);
        assert_eq!(min_entropy(&[]), 0.0);
    }

    #[test]
    fn single_byte_zero_entropy() {
        let data = [0x42u8];
        assert_eq!(shannon_entropy(&data), 0.0);
        assert_eq!(min_entropy(&data), 0.0);
        // Chi-squared for single byte: expected = 1/256, one bin has 1, rest 0
        // chi = (1 - 1/256)^2 / (1/256) + 255 * (0 - 1/256)^2 / (1/256)
        // = (255/256)^2 * 256 + 255 * (1/256)^2 * 256
        // = 255^2/256 + 255/256 = (255^2 + 255)/256 = 255*256/256 = 255
        let chi = chi_squared(&data);
        assert!((chi - 255.0).abs() < 0.01, "chi = {chi}");
    }

    #[test]
    fn all_same_byte_zero_entropy() {
        let data = vec![0xAAu8; 1000];
        assert_eq!(shannon_entropy(&data), 0.0);
        assert_eq!(min_entropy(&data), 0.0);
        // Chi-squared should be very high (all in one bin)
        let chi = chi_squared(&data);
        assert!(chi > 100000.0, "chi = {chi}");
    }

    #[test]
    fn two_equally_likely_bytes() {
        // 50/50 split → entropy = 1 bit/byte
        let mut data = vec![0u8; 500];
        data.extend(vec![1u8; 500]);
        let h = shannon_entropy(&data);
        assert!((h - 1.0).abs() < 0.001, "h = {h}");
    }

    #[test]
    fn four_equally_likely_bytes() {
        // 25% each → entropy = 2 bits/byte
        let mut data = Vec::new();
        for b in [0u8, 1, 2, 3] {
            data.extend(vec![b; 250]);
        }
        let h = shannon_entropy(&data);
        assert!((h - 2.0).abs() < 0.001, "h = {h}");
    }

    #[test]
    fn perfect_uniform_256_bytes() {
        // Each byte value appears exactly once → entropy = 8 bits/byte
        let data: Vec<u8> = (0..=255).collect();
        let h = shannon_entropy(&data);
        assert!((h - 8.0).abs() < 0.0001, "h = {h}");
        // Chi-squared should be 0 (perfect uniformity)
        let chi = chi_squared(&data);
        assert!(chi.abs() < 0.0001, "chi = {chi}");
    }

    #[test]
    fn min_entropy_dominant_byte() {
        // 90% one byte, 10% another → min_entropy = -log2(0.9) ≈ 0.152
        let mut data = vec![0u8; 900];
        data.extend(vec![1u8; 100]);
        let me = min_entropy(&data);
        let expected = -(0.9f64).log2();
        assert!(
            (me - expected).abs() < 0.001,
            "me = {me}, expected = {expected}"
        );
    }

    #[test]
    fn chi_squared_uniform_large() {
        // Large uniform sample should have low chi-squared
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let chi = chi_squared(&data);
        // Expected chi for uniform: ~255 (degrees of freedom)
        // With perfect uniformity: 0
        assert!(chi < 1.0, "chi = {chi}");
    }

    #[test]
    fn chi_squared_biased() {
        // Heavily biased distribution → high chi-squared
        let mut data = vec![0u8; 9000];
        data.extend(vec![1u8; 1000]);
        let chi = chi_squared(&data);
        assert!(chi > 5000.0, "chi = {chi}");
    }

    #[test]
    fn shannon_entropy_upper_bound() {
        // Entropy can never exceed 8 bits/byte
        let data: Vec<u8> = (0..10000).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let h = shannon_entropy(&data);
        assert!(h <= 8.0, "h = {h}");
        assert!(h > 7.0, "h = {h}"); // should be high for pseudo-random
    }

    #[test]
    fn min_entropy_upper_bound() {
        // Min-entropy can never exceed Shannon entropy
        let data: Vec<u8> = (0..1000).map(|i| ((i * 11 + 5) % 256) as u8).collect();
        let h = shannon_entropy(&data);
        let me = min_entropy(&data);
        assert!(me <= h + 0.001, "me = {me}, h = {h}");
    }

    #[test]
    fn quality_gate_random_data_passes() {
        // Simulate random data (high entropy)
        let data: Vec<u8> = (0..1024).map(|i| ((i * 137 + 43) % 256) as u8).collect();
        let h = shannon_entropy(&data);
        let me = min_entropy(&data);
        let chi = chi_squared(&data);
        // This pseudo-random sequence should pass quality gates
        assert!(h > 7.5, "h = {h}");
        assert!(me > 6.0, "me = {me}");
        assert!(chi < 350.0, "chi = {chi}");
    }

    #[test]
    fn quality_gate_low_entropy_fails() {
        // Low entropy data should fail
        let data = vec![0u8; 512];
        let h = shannon_entropy(&data);
        assert!(h < 7.5, "h = {h}");
    }

    #[test]
    fn small_sample_no_panic() {
        // Very small samples should not panic
        for size in [0, 1, 2, 10, 100, 255] {
            let data = vec![0x42u8; size];
            let _ = shannon_entropy(&data);
            let _ = chi_squared(&data);
            let _ = min_entropy(&data);
        }
    }

    #[test]
    fn entropy_monotonic_with_diversity() {
        // More diverse data → higher entropy
        let uniform = vec![0u8; 1000];
        let two_vals = {
            let mut d = vec![0u8; 500];
            d.extend(vec![1u8; 500]);
            d
        };
        let four_vals = {
            let mut d = Vec::new();
            for b in [0u8, 1, 2, 3] {
                d.extend(vec![b; 250]);
            }
            d
        };
        let h0 = shannon_entropy(&uniform);
        let h1 = shannon_entropy(&two_vals);
        let h2 = shannon_entropy(&four_vals);
        assert!(h0 < h1, "h0={h0}, h1={h1}");
        assert!(h1 < h2, "h1={h1}, h2={h2}");
    }
}
