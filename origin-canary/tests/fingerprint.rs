// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Origin Contributors

//! Phase 3 tests — release fingerprints (hybrid Ed25519 + Falcon-1024).

use origin_canary::commitment::{self, Verification};
use origin_canary::fingerprint::{self, FingerprintPayload, SignedFingerprint};
use origin_canary::manifest::CanaryManifest;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_manifest() -> CanaryManifest {
    CanaryManifest {
        project_id: 42,
        distribution_id: "v3.0.0".to_string(),
        salt: "aabbcc".to_string(),
        source_tree_hash: "11".repeat(32),
        token_count: 4,
        canary_tokens: vec![],
        merkle_root: Some("22".repeat(32)),
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

fn make_archive(dir: &std::path::Path) -> std::path::PathBuf {
    let archive = dir.join("release-v3.0.0.tar.gz");
    std::fs::write(&archive, b"fake tarball bytes for phase 3 testing").unwrap();
    archive
}

fn sign_pair(
    manifest: &CanaryManifest,
    archive: &std::path::Path,
    timestamp: u64,
) -> (commitment::SignedCommitment, SignedFingerprint) {
    let commitment = commitment::sign_commitment(manifest, &test_seed(), timestamp).unwrap();
    let fp = fingerprint::sign_fingerprint(manifest, &commitment, archive, &test_seed(), timestamp)
        .unwrap();
    (commitment, fp)
}

#[test]
fn fingerprint_signs_and_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());
    let (_, fp) = sign_pair(&manifest, &archive, now());
    assert_eq!(fp.verify().unwrap(), Verification::Valid);
}

#[test]
fn fingerprint_matches_original_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());
    let (_, fp) = sign_pair(&manifest, &archive, now());
    assert!(fp.matches_archive(&archive).unwrap());
}

#[test]
fn modified_archive_fails_hash_check() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());
    let (_, fp) = sign_pair(&manifest, &archive, now());

    let modified = tmp.path().join("modified.tar.gz");
    std::fs::write(&modified, b"fake tarball bytes for phase 3 testing EXTRA").unwrap();
    assert!(!fp.matches_archive(&modified).unwrap());

    // Truncated archive also fails (size + hash).
    let truncated = tmp.path().join("truncated.tar.gz");
    let orig = std::fs::read(&archive).unwrap();
    std::fs::write(&truncated, &orig[..orig.len() - 5]).unwrap();
    assert!(!fp.matches_archive(&truncated).unwrap());
}

#[test]
fn fingerprint_json_roundtrip_still_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());
    let (_, fp) = sign_pair(&manifest, &archive, now());

    let json = serde_json::to_string_pretty(&fp).unwrap();
    let reloaded: SignedFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(reloaded.verify().unwrap(), Verification::Valid);
    assert_eq!(reloaded.payload, fp.payload);
    assert!(reloaded.matches_archive(&archive).unwrap());
}

#[test]
fn tampered_payload_field_is_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());
    let (_, mut fp) = sign_pair(&manifest, &archive, now());

    fp.payload.archive_hash = "ff".repeat(32);
    assert_ne!(fp.verify().unwrap(), Verification::Valid);
}

#[test]
fn tampered_size_is_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());
    let (_, mut fp) = sign_pair(&manifest, &archive, now());

    fp.payload.archive_size += 1;
    assert_ne!(fp.verify().unwrap(), Verification::Valid);
}

#[test]
fn tampered_commitment_digest_is_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());
    let (_, mut fp) = sign_pair(&manifest, &archive, now());

    fp.payload.commitment_digest = "00".repeat(32);
    assert_ne!(fp.verify().unwrap(), Verification::Valid);
}

#[test]
fn fingerprint_binds_to_commitment() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());
    let (commitment, fp) = sign_pair(&manifest, &archive, now());
    assert!(fp.matches_commitment(&commitment).unwrap());
}

#[test]
fn foreign_commitment_does_not_match() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());
    let (_, fp) = sign_pair(&manifest, &archive, now());

    // Commitment for a DIFFERENT project → digest and ids differ.
    let mut other = test_manifest();
    other.project_id = 999;
    let other_commitment = commitment::sign_commitment(&other, &test_seed(), now()).unwrap();
    assert!(!fp.matches_commitment(&other_commitment).unwrap());
}

#[test]
fn signing_refuses_mismatched_manifest_commitment_pair() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());

    // Commitment over a different merkle root.
    let mut other = test_manifest();
    other.merkle_root = Some("33".repeat(32));
    let other_commitment = commitment::sign_commitment(&other, &test_seed(), now()).unwrap();

    let err =
        fingerprint::sign_fingerprint(&manifest, &other_commitment, &archive, &test_seed(), now())
            .unwrap_err();
    assert!(err.contains("merkle_root mismatch"), "got: {err}");
}

#[test]
fn signing_refuses_invalid_commitment() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());

    // Build a commitment then corrupt its signature.
    let mut commitment = commitment::sign_commitment(&manifest, &test_seed(), now()).unwrap();
    commitment.ed25519_sig = "00".repeat(64);

    let err = fingerprint::sign_fingerprint(&manifest, &commitment, &archive, &test_seed(), now())
        .unwrap_err();
    assert!(err.contains("refusing to fingerprint"), "got: {err}");
}

#[test]
fn archive_hashing_is_streaming_and_correct() {
    let tmp = tempfile::tempdir().unwrap();
    // > 64KB to cross the streaming buffer boundary.
    let big = tmp.path().join("big.tar");
    let data: Vec<u8> = (0..200_000)
        .map(|i| (i % 251) as u8)
        .cycle()
        .take(200_000)
        .collect();
    std::fs::write(&big, &data).unwrap();

    let (hash, size) = fingerprint::hash_archive(&big).unwrap();
    assert_eq!(size, 200_000);
    let expected = hex::encode(origin_crypto_sdk::blake3::hash(&data).as_bytes());
    assert_eq!(hash, expected);
}

#[test]
fn ledger_append_and_read_back() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());
    let ledger = tmp.path().join("ledger.jsonl");

    let (_, fp1) = sign_pair(&manifest, &archive, 1_700_000_000);
    let (_, fp2) = sign_pair(&manifest, &archive, 1_700_000_100);

    let idx1 = fingerprint::publish(&ledger, &fp1).unwrap();
    let idx2 = fingerprint::publish(&ledger, &fp2).unwrap();
    assert_eq!((idx1, idx2), (0, 1));

    let records = fingerprint::read_ledger(&ledger).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].payload, fp1.payload);
    assert_eq!(records[1].payload, fp2.payload);
    assert_eq!(records[0].payload.timestamp, 1_700_000_000);
    assert_eq!(records[1].payload.timestamp, 1_700_000_100);
}

#[test]
fn publish_refuses_invalid_fingerprint() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = test_manifest();
    let archive = make_archive(tmp.path());
    let ledger = tmp.path().join("ledger.jsonl");

    let (_, mut fp) = sign_pair(&manifest, &archive, now());
    fp.payload.archive_name = "swapped.tar.gz".to_string();

    let err = fingerprint::publish(&ledger, &fp).unwrap_err();
    assert!(err.contains("refusing to publish"), "got: {err}");
    // Ledger was never created.
    assert!(!ledger.exists());
}

#[test]
fn malformed_ledger_line_fails_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let ledger = tmp.path().join("ledger.jsonl");
    std::fs::write(&ledger, b"not json at all\n").unwrap();
    let err = fingerprint::read_ledger(&ledger).unwrap_err();
    assert!(err.contains("malformed"), "got: {err}");
}

#[test]
fn canonical_bytes_key_sorted_and_stable() {
    let payload = FingerprintPayload {
        version: fingerprint::FINGERPRINT_VERSION.to_string(),
        archive_hash: "aa".repeat(32),
        archive_size: 12345,
        archive_name: "rel.tar.gz".to_string(),
        source_tree_hash: "bb".repeat(32),
        merkle_root: "cc".repeat(32),
        commitment_digest: "dd".repeat(32),
        project_id: 1,
        distribution_id: "v1".to_string(),
        timestamp: 1_700_000_000,
    };
    let bytes = payload.canonical_bytes();
    let text = String::from_utf8(bytes.clone()).unwrap();
    let ah = text.find("\"archive_hash\"").unwrap();
    let an = text.find("\"archive_name\"").unwrap();
    let as_ = text.find("\"archive_size\"").unwrap();
    let cd = text.find("\"commitment_digest\"").unwrap();
    let ve = text.find("\"version\"").unwrap();
    assert!(ah < an && an < as_ && as_ < cd && cd < ve);
    assert_eq!(bytes, payload.canonical_bytes());
}
