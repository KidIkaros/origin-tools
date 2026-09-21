// SPDX-License-Identifier: Apache-2.0

//! api — the typed library surface for origin-entropy.
//!
//! Delegates to `origin_crypto_sdk::entropy` — the authoritative entropy
//! analysis with comprehensive metrics (Shannon, min-entropy, collision entropy,
//! chi-squared p-value, serial correlation, bit bias, longest run, unique bytes)
//! and per-bit-length quality gates.
//!
//! Design rules (see ARCHITECTURE.md):
//! - Pure statistics — no crypto, no I/O; callers supply the bytes.
//! - Errors are typed (`EntropyError`), never `String`.

use crate::error::{EntropyError, Result};
use origin_crypto_sdk::entropy;

/// Entropy statistics for a byte sample (delegated from SDK).
///
/// Subset of SDK metrics for backward compatibility. New code should use
/// `origin_crypto_sdk::entropy::EntropyMetrics` directly.
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
    /// Analyze a byte sample (delegates to SDK).
    ///
    /// All statistics are well-defined for any input length (empty input yields zeros).
    pub fn analyze(data: &[u8]) -> Self {
        let metrics = entropy::analyze(data);
        Self {
            shannon: metrics.shannon_entropy,
            chi_squared: metrics.chi_squared,
            min_entropy: metrics.min_entropy,
        }
    }

    /// Heuristic randomness verdict (Shannon > 7.5 bits/byte).
    pub fn is_random(&self) -> bool {
        self.shannon > 7.5
    }
}

/// Result of a quality-gate check against a target bit size.
///
/// Delegates to SDK's `entropy::check_quality` which provides per-bit-length
/// gates and more comprehensive checks (serial correlation, bit bias, longest run).
#[derive(Debug, Clone, PartialEq)]
pub struct QualityReport {
    /// Whether the sample passed all applicable gates.
    pub passed: bool,
    /// Human-readable issues found (empty when passed).
    pub issues: Vec<String>,
}

/// Run the quality gates on `data` for a `bits`-bit secret (delegates to SDK).
///
/// Gates (delegated to SDK; apply only for samples >= 256 bytes):
/// - length >= ceil(bits / 8) bytes,
/// - Shannon entropy >= bit-length-specific minimum,
/// - min-entropy >= bit-length-specific minimum,
/// - collision entropy >= bit-length-specific minimum,
/// - chi-squared p-value >= 0.0001,
/// - serial correlation <= bit-length-specific maximum,
/// - bit bias deviation <= bit-length-specific maximum,
/// - longest run <= bit-length-specific maximum.
///
/// For short samples (< 256 bytes), SDK only checks the length gate — this
/// mirrors the historical origin-entropy behavior.
pub fn quality_check(data: &[u8], bits: u32) -> Result<QualityReport> {
    if bits == 0 {
        return Err(EntropyError::Validation("bits must be >= 1".into()));
    }

    let expected_bytes = (bits as usize).div_ceil(8);

    // Length gate always applies (regardless of sample size)
    if data.len() < expected_bytes {
        return Ok(QualityReport {
            passed: false,
            issues: vec![format!(
                "input too short: {} bytes, expected >= {} for {} bits",
                data.len(),
                expected_bytes,
                bits
            )],
        });
    }

    // For short samples, SDK only checks length — matching historical behavior
    if data.len() < 256 {
        return Ok(QualityReport {
            passed: true,
            issues: vec![],
        });
    }

    // Delegate to SDK for full statistical analysis
    let metrics = entropy::analyze(data);
    let (passed, sdk_issues) = entropy::check_quality(&metrics, bits);

    Ok(QualityReport {
        passed,
        issues: sdk_issues,
    })
}

// ================================================================================
// Backward-compatible helpers (direct wrappers for SDK internals)
// ================================================================================

/// Shannon entropy in bits per byte (0.0 – 8.0).
///
/// Delegates to SDK implementation.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    entropy::analyze(data).shannon_entropy
}

/// Chi-squared statistic for byte uniformity.
///
/// Delegates to SDK implementation.
pub fn chi_squared(data: &[u8]) -> f64 {
    entropy::analyze(data).chi_squared
}

/// Min-entropy in bits per byte (conservative estimate).
///
/// Delegates to SDK implementation.
pub fn min_entropy(data: &[u8]) -> f64 {
    entropy::analyze(data).min_entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_data_yields_zero_stats() {
        let stats = EntropyStats::analyze(&[]);
        assert_eq!(stats.shannon, 0.0);
        assert_eq!(stats.min_entropy, 0.0);
        assert_eq!(stats.chi_squared, 0.0);
    }

    #[test]
    fn random_data_passes_quality_check() {
        // Real random data should pass
        use std::fs;
        if let Ok(data) = fs::read("/dev/urandom") {
            if data.len() >= 256 {
                let report = quality_check(&data[..256], 256).unwrap();
                assert!(report.passed, "random data should pass quality gates");
            }
        }
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