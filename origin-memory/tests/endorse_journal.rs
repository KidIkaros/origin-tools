// SPDX-License-Identifier: Apache-2.0

//! R1: endorsement journal — signed, chained, persisted, replayed on open.
//! Closes M1 (trust lost on reload) and M2 (unsigned/unchained endorsements).

use origin_memory::sign::derive_bundle;
use origin_memory::{Memory, MemoryNode};

const SEED: [u8; 32] = [7u8; 32];

fn fresh_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("origin-memory-r1-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn endorsement_survives_reload() {
    let dir = fresh_dir("reload");
    let target_fp = {
        let other = derive_bundle(&[9u8; 32], "other-agent");
        hex::encode(other.ed25519_pk().as_bytes())
    };

    {
        let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");
        mem.endorse(&target_fp, "memory-write", 0.8);
        assert!(
            mem.trust_score(&target_fp, "memory-write") > 0.0,
            "scored before reload"
        );
    }

    // Reload: the journal must be replayed into the trust graph (M1 closed).
    let mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("reopen");
    assert!(
        mem.trust_score(&target_fp, "memory-write") > 0.0,
        "endorsement lost on reload — journal replay broken"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn endorsement_is_falcon_signed_and_chained() {
    let dir = fresh_dir("signed");
    let target_fp = {
        let other = derive_bundle(&[9u8; 32], "other-agent");
        hex::encode(other.ed25519_pk().as_bytes())
    };

    {
        let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");
        mem.endorse(&target_fp, "memory-write", 0.8);
        mem.endorse(&target_fp, "memory-read", 0.5);
    }

    // Journal on disk: chain integrity + own Falcon signatures verify (M2 closed).
    let raw = std::fs::read_to_string(dir.join("endorsements.json")).expect("journal exists");
    let chain: origin_attest::types::EndorsementChain = serde_json::from_str(&raw).expect("parse");
    assert_eq!(chain.len(), 2);
    chain.verify_integrity().expect("hash chain intact");
    // Second endorsement chains to the first.
    assert_eq!(
        chain.endorsements[1].prev_hash,
        chain.endorsements[0].hash()
    );
    // Every endorsement carries a non-empty Falcon-1024 signature.
    for e in &chain.endorsements {
        assert!(
            !e.falcon_signature.is_empty(),
            "unsigned endorsement persisted"
        );
    }

    // Signature actually verifies against the signer's Falcon pubkey.
    let mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("reopen");
    assert!(mem.store_endorsements_verified(), "own signatures verify");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tampered_journal_is_detected() {
    let dir = fresh_dir("tamper");
    let target_fp = {
        let other = derive_bundle(&[9u8; 32], "other-agent");
        hex::encode(other.ed25519_pk().as_bytes())
    };

    {
        let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");
        mem.endorse(&target_fp, "memory-write", 0.8);
    }

    // Attacker rewrites the confidence directly in the journal.
    let path = dir.join("endorsements.json");
    let raw = std::fs::read_to_string(&path).unwrap();
    let tampered = raw.replacen("\"confidence\": 0.8", "\"confidence\": 0.99", 1);
    assert_ne!(raw, tampered, "test setup: confidence field present");
    std::fs::write(&path, tampered).unwrap();

    let mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("reopen");
    // Chain integrity breaks (confidence is inside signable_bytes → hash shifts).
    assert!(
        !mem.store_endorsements_verified(),
        "tampered journal must not verify"
    );
    // And the load-time check surfaced it (R2).
    assert!(
        mem.journal_tampered()
            .iter()
            .any(|p| p.starts_with("endorsements")),
        "tampered endorsement journal must be surfaced at load"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tampered_revocation_journal_is_surfaced_at_load() {
    let dir = fresh_dir("rev-tamper");
    let node = MemoryNode::from_markdown(
        "evt",
        "---\ntitle: E\ntime: 2004-06-01\ntopic: [x]\nevidence: documented\n---\nE.\n",
    )
    .unwrap();

    {
        let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");
        mem.add(node).expect("add");
        mem.revoke("evt", "retract").expect("revoke");
        assert!(mem.revocations_verified(), "journal clean before tamper");
        assert!(mem.journal_tampered().is_empty());
    }

    // Attacker edits the revocation reason in the journal.
    let path = dir.join("revocations.json");
    let raw = std::fs::read_to_string(&path).unwrap();
    let tampered = raw.replacen(
        "\"reason\": \"retract\"",
        "\"reason\": \"never happened\"",
        1,
    );
    assert_ne!(raw, tampered, "test setup: reason field present");
    std::fs::write(&path, tampered).unwrap();

    let mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("reopen");
    assert!(
        mem.journal_tampered()
            .iter()
            .any(|p| p.starts_with("revocations")),
        "tampered revocation journal must be surfaced at load"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
