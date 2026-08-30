// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-seed` as a foundational dependency.
//!
//! Seed lifecycle through the **typed library API** (`origin_seed::api`),
//! exactly as a downstream application would: generate → derive
//! (domain-separated) → hex round-trip → encrypted blob create → recover.
//! Negative paths prove typed errors (wrong passphrase, empty domain,
//! short hex).
//!
//! Run with: `cargo run -p origin-seed --example dogfood`

use origin_seed::api;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── generate: fresh 32-byte seed from the SDK CSPRNG ─────────────
    let fresh = api::generate()?;
    assert_ne!(fresh, [0u8; 32]);
    println!("✓ generate (random 32-byte seed)");

    // ── derive: deterministic child, domain-separated ────────────────
    let parent = [0x42u8; 32];
    let child1 = api::derive(&parent, "app:wallet:1")?;
    let child2 = api::derive(&parent, "app:wallet:2")?;
    assert_ne!(child1, child2, "different domains → unrelated children");
    assert_eq!(
        api::derive(&parent, "app:wallet:1")?,
        child1,
        "same parent + domain → same child"
    );
    println!("✓ derive (domain-separated child seeds)");

    // Empty domain rejected by the SDK — typed error.
    assert!(api::derive(&parent, "").is_err());
    println!("✓ empty domain rejected (typed SeedError)");

    // ── hex encode / decode round-trip ───────────────────────────────
    let hex_str = api::to_hex(&parent);
    assert_eq!(api::from_hex(&hex_str)?, parent);
    assert!(api::from_hex("0x42").is_err(), "0x prefix rejected");
    let short = hex::encode([0u8; 16]);
    assert!(api::from_hex(&short).is_err(), "16-byte seed rejected");
    println!("✓ encode → decode round-trip (short/0x-prefixed rejected)");

    // ── blob seal → recover (encrypted at rest) ──────────────────────
    let tier = api::parse_tier("nano")?;
    let blob = api::seal_blob(&parent, b"dogfood-seed-pass", tier)?;
    assert!(!blob.is_empty());

    let recovered = api::recover_blob(&blob, b"dogfood-seed-pass", tier)?;
    assert_eq!(recovered, parent);
    println!("✓ seal_blob → recover_blob (Argon2id-sealed seed)");

    // Wrong passphrase must fail recovery with a typed error.
    let err = api::recover_blob(&blob, b"wrong", tier).unwrap_err();
    assert!(matches!(err, origin_seed::SeedError::Blob(_)));
    println!("✓ wrong passphrase rejected (typed SeedError::Blob)");

    println!("\norigin-seed dogfood OK — typed library API usable as a foundational dependency");
    Ok(())
}
