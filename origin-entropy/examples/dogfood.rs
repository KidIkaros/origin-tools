// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-entropy` as a foundational dependency.
//!
//! Entropy auditing through the typed library API (`origin_entropy::api`):
//! analyze a genuinely random sample (Shannon / chi-squared / min-entropy),
//! check it against the quality gate for a 256-bit seed, and confirm a
//! biased sample fails the same gate — all as plain function calls, no CLI.
//!
//! Run with: `cargo run -p origin-entropy --example dogfood`

use origin_entropy::api::{quality_check, EntropyStats};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A genuinely random sample from the SDK CSPRNG. 4096 bytes keeps the
    // statistical gates meaningful: at 256 bytes the Shannon estimate is
    // biased low and the 7.5 bits/byte gate flakes.
    let mut random = vec![0u8; 4096];
    origin_crypto_sdk::fill_random(&mut random).map_err(|e| e.to_string())?;

    // ── analyze: full metric set (Shannon / chi-squared / min-entropy) ─
    let stats = EntropyStats::analyze(&random);
    println!(
        "✓ analyze: shannon={:.4} bits/byte, chi²={:.2}, min-entropy={:.4}",
        stats.shannon, stats.chi_squared, stats.min_entropy
    );
    assert!(stats.is_random(), "CSPRNG sample must pass the heuristic verdict");

    // ── check: quality gate for a 256-bit seed ────────────────────────
    let report = quality_check(&random, 256)?;
    assert!(report.passed, "random sample must pass: {:?}", report.issues);
    assert!(report.issues.is_empty());
    println!("✓ quality_check passes for a random 4096-byte seed (256 bits)");

    // ── biased sample must fail the same gate ─────────────────────────
    let biased = vec![0x00u8; 4096];
    let report = quality_check(&biased, 256)?;
    assert!(!report.passed, "all-zero sample must fail the gate");
    assert!(!report.issues.is_empty(), "failure must list its issues");
    println!(
        "✓ biased sample correctly rejected ({} gate issue(s))",
        report.issues.len()
    );

    // ── typed error path: bits = 0 is a Validation error ──────────────
    let err = quality_check(&random, 0).unwrap_err();
    println!("✓ bits=0 rejected → EntropyError::Validation ({err})");

    println!("\norigin-entropy dogfood OK — usable as a foundational dependency");
    Ok(())
}
