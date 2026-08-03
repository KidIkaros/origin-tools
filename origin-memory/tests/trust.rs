// SPDX-License-Identifier: Apache-2.0

//! P5: multi-agent attribution — every node records its signer; trust between
//! signers propagates via origin-attest's TrustGraph (personalized PageRank).

use origin_memory::Memory;
use origin_memory::MemoryNode;

const SEED_A: [u8; 32] = [42u8; 32];
const SEED_B: [u8; 32] = [99u8; 32];

#[test]
fn signer_fingerprint_is_attributable() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p5-fp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED_A, "agent-a").expect("open");

    // The memory has a fingerprint — it's the Ed25519 public key hex.
    let fp = mem.fingerprint();
    assert!(!fp.is_empty(), "fingerprint is non-empty");
    assert!(hex::decode(fp).is_ok(), "fingerprint is valid hex");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn endorsement_propagates_trust() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p5-trust-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED_A, "agent-a").expect("open");

    // Agent A's own fingerprint scores 1.0 (seed node in its own graph).
    let self_fp = mem.fingerprint().to_string();
    let self_score = mem.trust_score(&self_fp, "memory-write");
    assert!(self_score >= 0.99, "self-trust is max: got {}", self_score);

    // Agent B's fingerprint (unknown) scores 0.0 — not endorsed yet.
    // Derive B's fingerprint from its seed the same way.
    let bundle_b = origin_memory::sign::derive_bundle(&SEED_B, "agent-b");
    let fp_b = hex::encode(bundle_b.ed25519_pk().as_bytes());
    let untrusted = mem.trust_score(&fp_b, "memory-write");
    assert!(
        untrusted < 0.1,
        "unendorsed agent has near-zero trust: got {}",
        untrusted
    );

    // A endorses B in the "memory-write" domain.
    mem.endorse(&fp_b, "memory-write", 0.9);
    let trusted = mem.trust_score(&fp_b, "memory-write");
    assert!(
        trusted > 0.3,
        "endorsed agent has propagated trust: got {}",
        trusted
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn trust_differs_across_domains() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p5-domain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED_A, "agent-a").expect("open");

    let bundle_b = origin_memory::sign::derive_bundle(&SEED_B, "agent-b");
    let fp_b = hex::encode(bundle_b.ed25519_pk().as_bytes());

    // Endorse B in "memory-write" but NOT in "memory-delete".
    mem.endorse(&fp_b, "memory-write", 0.9);

    let write_score = mem.trust_score(&fp_b, "memory-write");
    let delete_score = mem.trust_score(&fp_b, "memory-delete");
    assert!(
        write_score > delete_score,
        "trust is domain-specific: write={} delete={}",
        write_score,
        delete_score
    );

    let _ = std::fs::remove_dir_all(&dir);
}
