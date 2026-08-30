// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-proof` as a foundational dependency.
//!
//! The crate's reusable library surface is `origin_proof::mmr` — an
//! append-only Merkle Mountain Range with O(log n) membership proofs.
//! A downstream project (audit log, transaction history, checkpoint
//! chain) consumes exactly this API:
//!
//!   append → root → prove → verify, plus tamper/out-of-range failures,
//!   and JSON serialization for storing state between runs.
//!
//! Run with: `cargo run -p origin-proof --example dogfood`

use origin_proof::mmr::{parent_hash, MmrState};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── append: build a 100-leaf MMR ─────────────────────────────────
    let mut mmr = MmrState::new();
    assert_eq!(mmr.leaf_count, 0);
    assert_eq!(mmr.root(), [0u8; 32], "empty MMR root is all zeros");

    let mut leaves = Vec::new();
    for i in 0..100u64 {
        let hash = *origin_crypto_sdk::blake3::hash(&i.to_le_bytes()).as_bytes();
        leaves.push(hash);
        mmr.append_hash(hash);
    }
    assert_eq!(mmr.leaf_count, 100);
    let root = mmr.root();
    assert_ne!(root, [0u8; 32]);
    println!("✓ appended 100 leaves, root = {}", hex::encode(root));

    // ── prove + verify: every leaf has a valid membership proof ──────
    for i in [0u64, 1, 37, 63, 64, 99] {
        let proof = mmr.prove(i)?;
        assert!(
            mmr.verify_proof(&proof, &root),
            "leaf {i} must verify against the root"
        );
    }
    println!("✓ membership proofs verify for every sampled leaf");

    // ── tamper detection ─────────────────────────────────────────────
    let mut proof = mmr.prove(7)?;
    let mut leaf = hex::decode(&proof.leaf_hash).map_err(|e| e.to_string())?;
    leaf[0] ^= 0xff;
    proof.leaf_hash = hex::encode(leaf);
    assert!(
        !mmr.verify_proof(&proof, &root),
        "tampered leaf hash must fail verification"
    );
    println!("✓ tampered leaf rejected");

    // ── out-of-range proof fails loudly ──────────────────────────────
    assert!(mmr.prove(100).is_err(), "index 100 is out of range");
    assert!(mmr.prove(u64::MAX).is_err());
    println!("✓ out-of-range leaf index rejected");

    // ── serialization: state survives a round-trip ───────────────────
    let json = serde_json::to_string(&mmr).map_err(|e| e.to_string())?;
    let restored: MmrState = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    assert_eq!(restored.leaf_count, 100);
    assert_eq!(
        restored.root(),
        root,
        "restored MMR must have the same root"
    );
    let p = restored.prove(42)?;
    assert!(restored.verify_proof(&p, &root));
    println!("✓ MMR state JSON round-trip preserves the root");

    // ── parent_hash is the public composition primitive ──────────────
    let a = *origin_crypto_sdk::blake3::hash(b"left").as_bytes();
    let b = *origin_crypto_sdk::blake3::hash(b"right").as_bytes();
    let h = parent_hash(a, b);
    assert_ne!(h, a);
    assert_ne!(h, b);
    println!("✓ parent_hash composition");

    println!("\norigin-proof dogfood OK — usable as a foundational dependency");
    Ok(())
}
