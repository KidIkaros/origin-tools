// SPDX-License-Identifier: Apache-2.0

//! api — the typed library surface for origin-entropy.
//!
//! Entropy statistics and quality gates as plain function calls over
//! in-memory bytes. The CLI (`commands.rs`) is a thin shell over this.
//!
//! Design rules (see ARCHITECTURE.md):
//! - Pure statistics — no crypto, no I/O; callers supply the bytes.
//! - Errors are typed (`EntropyError`), never `String`.

use crate::error::{Result, EntropyError};

/// Entropy statistics for a byte sample.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyStats {
    /// Shannon entropy in bits per byte (0.0 – 8.0).
    pub shannon: f64,
    /// Chi-squared statistic for byte uniformity.
    pub chi_squared: f64,
    /// Minimum entropy estimate (conservative, based on most frequent byte).
    pub min_entropy: f64,
}

impl EntropyStats {
    /// Analyze a byte sample. All statistics are well-defined for any
    /// input length (empty input yields zeros).
    pub fn analyze(data: &[u8]) -> Self {
        Self {
            shannon: shannon_entropy(data),
            chi_squared: chi_squared(data),
            min_entropy: min_entropy(data),
        }
    }

    /// Heuristic randomness verdict (Shannon > 7.5 bits/byte).
    pub fn is_random(&self) -> bool {
        self.shannon > 7.5
    }
}

/// Result of a quality-gate check against a target bit size.
#[derive(Debug, Clone, PartialEq)]
pub struct QualityReport {
    /// Whether the sample passed all applicable gates.
    pub passed: bool,
    /// Human-readable issues found (empty when passed).
    pub issues: Vec<String>,
}

/// Run the quality gates on `data` for a `bits`-bit secret.
///
/// Gates (skipped for samples < 256 bytes, where statistics are unreliable):
/// - length >= ceil(bits / 8) bytes,
/// - Shannon entropy >= 7.5 bits/byte,
/// - min-entropy >= 6.0,
/// - chi-squared <= 350.
pub fn quality_check(data: &[u8], bits: u32) -> Result<QualityReport> {
    if bits == 0 {
        return Err(EntropyError::Validation("bits must be >= 1".into()));
    }

    let expected_bytes = (bits as usize).div_ceil(8);
    let mut issues = Vec::new();
    let mut passed = true;

    if data.len() < expected_bytes {
        issues.push(format!(
            "input too short: {} bytes, expected >= {} for {} bits",
            data.len(),
            expected_bytes,
            bits
        ));
        passed = false;
    }

    if data.len() >= 256 {
        let h = shannon_entropy(data);
        let me = min_entropy(data);
        let chi = chi_squared(data);

        if h < 7.5 {
            issues.push(format!(
                "Shannon entropy too low: {h:.4} bits/byte (need >= 7.5)"
            ));
            passed = false;
        }
        if me < 6.0 {
            issues.push(format!("Min-entropy too low: {me:.4} (need >= 6.0)"));
            passed = false;
        }
        if chi > 350.0 {
            issues.push(format!(
                "Chi-squared too high: {chi:.2} (distribution is non-uniform)"
            ));
            passed = false;
        }
    }

    Ok(QualityReport { passed, issues })
}

/// Shannon entropy in bits per byte.
pub fn shannon_entropy(data: &[u8]) -> f64 {
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
pub fn chi_squared(data: &[u8]) -> f64 {
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
pub fn min_entropy(data: &[u8]) -> f64 {
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
    let p = max_count / len;
    -p.log2()
}

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
    fn perfect_uniform_is_8_bits() {
        let data: Vec<u8> = (0..=255).collect();
        let stats = EntropyStats::analyze(&data);
        assert!((stats.shannon - 8.0).abs() < 0.0001);
        assert!(stats.chi_squared.abs() < 0.0001);
    }

    #[test]
    fn all_same_byte_is_zero() {
        let stats = EntropyStats::analyze(&[0xAAu8; 1000]);
        assert_eq!(stats.shannon, 0.0);
        assert_eq!(stats.min_entropy, 0.0);
        assert!(!stats.is_random());
    }

    #[test]
    fn pseudo_random_passes_gates() {
        let data: Vec<u8> = (0..1024).map(|i| ((i * 137 + 43) % 256) as u8).collect();
        let report = quality_check(&data, 256).unwrap();
        assert!(report.passed, "issues: {:?}", report.issues);
    }

    #[test]
    fn low_entropy_fails_gates() {
        let report = quality_check(&[0u8; 512], 256).unwrap();
        assert!(!report.passed);
        assert!(!report.issues.is_empty());
    }

    #[test]
    fn too_short_fails_length_gate() {
        let report = quality_check(&[0u8; 4], 256).unwrap();
        assert!(!report.passed);
        assert!(report.issues[0].contains("too short"));
    }

    #[test]
    fn small_sample_skips_statistical_gates() {
        // 16 bytes < 32-byte minimum for 256 bits, and below the 256-byte
        // threshold, so only the length gate applies.
        let report = quality_check(&[0x42u8; 16], 256).unwrap();
        assert!(!report.passed, "16 bytes < 32-byte minimum only fails on length");
        assert_eq!(report.issues.len(), 1);
    }

    #[test]
    fn zero_bits_rejected() {
        assert!(quality_check(&[0u8; 32], 0).is_err());
    }
}
