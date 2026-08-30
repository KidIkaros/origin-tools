// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-shard` as a foundational dependency.
//!
//! Reed-Solomon K-of-N secret sharing through the typed library API
//! (`origin_shard::split` / `origin_shard::recover`): split a secret into
//! 5 shards, recover with only 3 of them, and confirm the degraded path
//! (2 shards) fails with the typed `ShardError::NotEnoughShards`.
//!
//! Run with: `cargo run -p origin-shard --example dogfood`

use origin_shard::{recover, split, ShardError};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = b"master-secret-material-0123456789abcdef";

    // ── split: 3 data shards + 2 parity shards (5 total) ─────────────
    let shards = split(secret, 3, 2)?;
    assert_eq!(shards.len(), 5, "split must produce 5 shards");
    println!("✓ split → 5 shards (3 data + 2 parity), in-memory");

    // ── recover with any 3 of 5: keep shards 2, 3, 4 ─────────────────
    let subset: Vec<Option<Vec<u8>>> = shards
        .iter()
        .enumerate()
        .map(|(i, s)| if i < 2 { None } else { Some(s.clone()) })
        .collect();
    let recovered = recover(&subset, 3, 2, secret.len())?;
    assert_eq!(recovered, secret, "3-of-5 shards must recover the secret");
    println!("✓ recover from a 3-of-5 subset (byte-exact)");

    // ── degraded path: only 2 shards must fail with a typed error ────
    let too_few: Vec<Option<Vec<u8>>> = shards
        .iter()
        .enumerate()
        .map(|(i, s)| if i < 3 { None } else { Some(s.clone()) })
        .collect();
    let err = recover(&too_few, 3, 2, secret.len()).unwrap_err();
    assert!(
        matches!(err, ShardError::NotEnoughShards(_)),
        "2-of-5 must fail with NotEnoughShards, got: {err}"
    );
    println!("✓ 2-of-5 subset correctly rejected → ShardError::NotEnoughShards");

    // ── config validation is typed too ───────────────────────────────
    let err = split(secret, 0, 2).unwrap_err();
    assert!(matches!(err, ShardError::InvalidConfig(_)));
    println!("✓ invalid config rejected → ShardError::InvalidConfig");

    println!("\norigin-shard dogfood OK — usable as a foundational dependency");
    Ok(())
}
