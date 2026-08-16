// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Origin Contributors

//! Phase 2 tests — signed commitments (hybrid Ed25519 + Falcon-1024).

use origin_canary::commitment::{
    self, CommitmentPayload, SignedCommitment, Verification, COMMITMENT_VERSION,
};
use origin_canary::manifest::CanaryManifest;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_manifest() -> CanaryManifest {
    CanaryManifest {
        project_id: 42,
        distribution_id: "v2.1.0".to_string(),
        salt: "aabbccddeeff".to_string(),
        source_tree_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_string(),
        token_count: 6,
        canary_tokens: vec![],
        merkle_root: Some(
            "c0e8adb71ffa2234c79c8eaa9af1f8fe39a9b4efa52f4cfb7d985b29727c56ef".to_string(),
        ),
    }
}

fn test_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8;
    }
    seed
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[test]
fn commitment_signs_and_verifies() {
    let manifest = test_manifest();
    let signed = commitment::sign_commitment(&manifest, &test_seed(), now()).unwrap();
    assert_eq!(signed.verify().unwrap(), Verification::Valid);
}

#[test]
fn commitment_json_roundtrip_still_verifies() {
    // Write → RELOAD → re-verify (reload-tamper pattern from the skill).
    let manifest = test_manifest();
    let signed = commitment::sign_commitment(&manifest, &test_seed(), now()).unwrap();

    let json = serde_json::to_string_pretty(&signed).unwrap();
    let reloaded: SignedCommitment = serde_json::from_str(&json).unwrap();

    assert_eq!(reloaded.verify().unwrap(), Verification::Valid);
    assert_eq!(reloaded.payload, signed.payload);
    assert_eq!(reloaded.domain, signed.domain);
}

#[test]
fn commitment_is_deterministic_same_seed_same_timestamp() {
    // Falcon signing is randomized, so signature BYTES differ between runs —
    // determinism here means: same payload bytes, same keys, both verify.
    let manifest = test_manifest();
    let a = commitment::sign_commitment(&manifest, &test_seed(), 1_700_000_000).unwrap();
    let b = commitment::sign_commitment(&manifest, &test_seed(), 1_700_000_000).unwrap();

    assert_eq!(a.payload, b.payload);
    assert_eq!(a.ed25519_pk, b.ed25519_pk);
    assert_eq!(a.falcon1024_pk, b.falcon1024_pk);
    assert_eq!(a.domain, b.domain);
    assert_eq!(a.ed25519_sig, b.ed25519_sig, "Ed25519 is deterministic");
    assert_eq!(a.verify().unwrap(), Verification::Valid);
    assert_eq!(b.verify().unwrap(), Verification::Valid);
}

#[test]
fn different_project_ids_sign_different_keys() {
    let mut manifest = test_manifest();
    manifest.project_id = 7;
    let a = commitment::sign_commitment(&manifest, &test_seed(), now()).unwrap();

    let mut manifest_b = test_manifest();
    manifest_b.project_id = 999;
    let b = commitment::sign_commitment(&manifest_b, &test_seed(), now()).unwrap();

    assert_ne!(a.ed25519_pk, b.ed25519_pk);
    assert_ne!(a.falcon1024_pk, b.falcon1024_pk);
}

#[test]
fn tampered_payload_is_invalid() {
    let manifest = test_manifest();
    let mut signed = commitment::sign_commitment(&manifest, &test_seed(), now()).unwrap();

    // Flip one payload field after signing.
    signed.payload.token_count += 1;
    assert_ne!(signed.verify().unwrap(), Verification::Valid);
}

#[test]
fn tampered_merkle_root_is_invalid() {
    let manifest = test_manifest();
    let mut signed = commitment::sign_commitment(&manifest, &test_seed(), now()).unwrap();

    signed.payload.merkle_root = "ff".repeat(32);
    assert_ne!(signed.verify().unwrap(), Verification::Valid);
}

#[test]
fn tampered_timestamp_is_invalid() {
    let manifest = test_manifest();
    let mut signed = commitment::sign_commitment(&manifest, &test_seed(), now()).unwrap();

    signed.payload.timestamp += 1;
    assert_ne!(signed.verify().unwrap(), Verification::Valid);
}

#[test]
fn foreign_key_signature_is_invalid() {
    // Sign with seed A, then swap the embedded pks to seed B's — the
    // signatures must NOT verify against the foreign keys.
    let manifest = test_manifest();
    let signed = commitment::sign_commitment(&manifest, &test_seed(), now()).unwrap();

    let mut seed_b = [0u8; 32];
    for b in seed_b.iter_mut() {
        *b = 0xAB;
    }
    let bundle_b = commitment::derive_bundle(&seed_b, manifest.project_id).unwrap();

    let mut forged = signed.clone();
    forged.ed25519_pk = hex::encode(bundle_b.ed25519_pk().as_bytes());
    forged.falcon1024_pk = hex::encode(bundle_b.falcon1024_pk().as_bytes());
    assert_ne!(forged.verify().unwrap(), Verification::Valid);
}

#[test]
fn manifest_without_merkle_root_errors_cleanly() {
    let mut manifest = test_manifest();
    manifest.merkle_root = None;
    let err = commitment::sign_commitment(&manifest, &test_seed(), now()).unwrap_err();
    assert!(err.contains("merkle_root"), "got: {err}");
}

#[test]
fn canonical_bytes_are_key_sorted_and_stable() {
    let payload = CommitmentPayload {
        version: COMMITMENT_VERSION.to_string(),
        merkle_root: "aa".repeat(32),
        structure: "bb".repeat(32),
        project_id: 1,
        distribution_id: "v1".to_string(),
        token_count: 3,
        timestamp: 1_700_000_000,
    };
    let bytes = payload.canonical_bytes();
    let text = String::from_utf8(bytes.clone()).unwrap();

    // Sorted keys: distribution_id < merkle_root < project_id < structure
    // < timestamp < token_count < version.
    let di = text.find("\"distribution_id\"").unwrap();
    let mr = text.find("\"merkle_root\"").unwrap();
    let pi = text.find("\"project_id\"").unwrap();
    let st = text.find("\"structure\"").unwrap();
    let ts = text.find("\"timestamp\"").unwrap();
    let tc = text.find("\"token_count\"").unwrap();
    let ve = text.find("\"version\"").unwrap();
    assert!(di < mr && mr < pi && pi < st && st < ts && ts < tc && tc < ve);

    // Stable: same payload → same bytes.
    let bytes2 = payload.canonical_bytes();
    assert_eq!(bytes, bytes2);
}
