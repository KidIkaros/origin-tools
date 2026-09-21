// SPDX-License-Identifier: OPL-1.4
// Copyright (c) 2026 Origin Contributors

//! Release fingerprinting — Phase 3 of origin-canary.
//!
//! A fingerprint binds a distributed archive (tarball/zip) to a signed
//! commitment: the archive's BLAKE3 hash, the source-tree hash, and the
//! commitment digest are jointly signed with the same hybrid
//! Ed25519 + Falcon-1024 construction. Publishing appends the record to a
//! local JSONL ledger — no network.

use crate::commitment::{canonicalize, derive_bundle_domain, SignedCommitment, Verification};
use origin_crypto_sdk::{Ed25519Signature, Ed25519VerifyingKey};
use origin_crypto_sdk::blake3;
use origin_crypto_sdk::pqc::falcon1024::{FalconPublicKey, FalconSignature};
use origin_crypto_sdk::signing::hybrid::Ed25519Falcon1024;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;

/// Fingerprint format version. Bump on any canonical-bytes layout change.
pub const FINGERPRINT_VERSION: &str = "canary-fingerprint-v1";

/// The signed payload. Canonical JSON (sorted keys, no whitespace) of this
/// struct is exactly what both signatures cover.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FingerprintPayload {
    /// Format version tag (`canary-fingerprint-v1`).
    pub version: String,
    /// BLAKE3 hash of the distributed archive file (hex, 64 chars).
    pub archive_hash: String,
    /// Archive size in bytes.
    pub archive_size: u64,
    /// Archive file name (no directories).
    pub archive_name: String,
    /// Source-tree hash carried over from the manifest.
    pub source_tree_hash: String,
    /// Merkle root of the canary leaf set.
    pub merkle_root: String,
    /// BLAKE3 digest of the commitment's canonical payload bytes — ties this
    /// fingerprint to one specific signed commitment.
    pub commitment_digest: String,
    /// Arbitrary project identifier chosen by the creator.
    pub project_id: u64,
    /// Distribution identifier (e.g. release tag).
    pub distribution_id: String,
    /// Unix timestamp (seconds) when the fingerprint was made.
    pub timestamp: u64,
}

/// A signed fingerprint: payload + hybrid signature + verifying keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedFingerprint {
    /// The fingerprinted payload.
    pub payload: FingerprintPayload,
    /// Ed25519 signature over the canonical bytes (hex).
    pub ed25519_sig: String,
    /// Falcon-1024 signature over the canonical bytes (hex).
    pub falcon1024_sig: String,
    /// Ed25519 verifying key (hex).
    pub ed25519_pk: String,
    /// Falcon-1024 verifying key (hex).
    pub falcon1024_pk: String,
    /// Key-derivation domain (`canary-fingerprint-<project_id>`).
    pub domain: String,
}

impl FingerprintPayload {
    /// Canonical fingerprint bytes: JSON with sorted keys, no whitespace.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut value = serde_json::to_value(self)
            .expect("payload serializes (all fields are plain JSON types)");
        canonicalize(&mut value);
        serde_json::to_vec(&value).expect("canonical JSON encodes")
    }
}

impl SignedFingerprint {
    /// Verify BOTH signatures over the payload's canonical bytes.
    pub fn verify(&self) -> Result<Verification, String> {
        let ed_pk = parse_ed25519_pk(&self.ed25519_pk)?;
        let falcon_pk = parse_falcon_pk(&self.falcon1024_pk)?;
        let ed_sig = parse_ed25519_sig(&self.ed25519_sig)?;
        let falcon_sig = parse_falcon_sig(&self.falcon1024_sig)?;

        let combined = Ed25519Falcon1024 {
            ed25519_sig: ed_sig,
            falcon_sig,
        };
        match Ed25519Falcon1024::verify(
            &ed_pk,
            &falcon_pk,
            &self.payload.canonical_bytes(),
            &combined,
        ) {
            Ok(()) => Ok(Verification::Valid),
            Err(e) => Ok(Verification::Invalid(format!("{e}"))),
        }
    }

    /// Re-hash the archive file and compare against the payload's
    /// `archive_hash`/`archive_size`. True only for the exact original bytes.
    pub fn matches_archive(&self, archive: &Path) -> Result<bool, String> {
        let (hash, size) = hash_archive(archive)?;
        Ok(hash == self.payload.archive_hash && size == self.payload.archive_size)
    }

    /// Check this fingerprint against the commitment it claims to extend.
    /// True only if the commitment verifies AND its digest/ids/root match.
    pub fn matches_commitment(&self, commitment: &SignedCommitment) -> Result<bool, String> {
        if commitment.verify()? != Verification::Valid {
            return Ok(false);
        }
        Ok(
            self.payload.commitment_digest == commitment_digest(commitment)
                && self.payload.merkle_root == commitment.payload.merkle_root
                && self.payload.project_id == commitment.payload.project_id
                && self.payload.distribution_id == commitment.payload.distribution_id,
        )
    }
}

fn parse_ed25519_pk(hex_str: &str) -> Result<Ed25519VerifyingKey, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid ed25519_pk hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("ed25519_pk must be 32 bytes, got {}", v.len()))?;
    Ed25519VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid ed25519_pk bytes: {e}"))
}

fn parse_falcon_pk(hex_str: &str) -> Result<FalconPublicKey, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid falcon1024_pk hex: {e}"))?;
    FalconPublicKey::from_bytes(&bytes).map_err(|e| format!("invalid falcon1024_pk bytes: {e}"))
}

fn parse_ed25519_sig(hex_str: &str) -> Result<Ed25519Signature, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid ed25519_sig hex: {e}"))?;
    Ed25519Signature::from_slice(&bytes).map_err(|e| format!("invalid ed25519_sig bytes: {e}"))
}

fn parse_falcon_sig(hex_str: &str) -> Result<FalconSignature, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid falcon1024_sig hex: {e}"))?;
    FalconSignature::from_bytes(&bytes).map_err(|e| format!("invalid falcon1024_sig bytes: {e}"))
}

// ── Creation ───────────────────────────────────────────────────────────────

/// Streaming BLAKE3 of a file + its size. Reads in 64KB chunks.
pub fn hash_archive(archive: &Path) -> Result<(String, u64), String> {
    let mut file = std::fs::File::open(archive)
        .map_err(|e| format!("cannot open archive {}: {e}", archive.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 65536];
    let mut total: u64 = 0;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("cannot read archive: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize().as_bytes()), total))
}

/// BLAKE3 digest of a commitment's canonical payload bytes — the value the
/// fingerprint's `commitment_digest` field must equal.
pub fn commitment_digest(commitment: &SignedCommitment) -> String {
    hex::encode(blake3::hash(&commitment.payload.canonical_bytes()).as_bytes())
}

/// Sign a release fingerprint binding the archive to the commitment.
///
/// Cross-checks BEFORE signing: the commitment must verify, and its
/// merkle_root / project_id / distribution_id must match the manifest's.
/// A mismatched (manifest, commitment) pair never produces a signature.
pub fn sign_fingerprint(
    manifest: &crate::manifest::CanaryManifest,
    commitment: &SignedCommitment,
    archive: &Path,
    seed: &[u8; 32],
    timestamp: u64,
) -> Result<SignedFingerprint, String> {
    // Cross-bind: commitment must be valid and match the manifest.
    match commitment.verify()? {
        Verification::Valid => {}
        Verification::Invalid(reason) => {
            return Err(format!(
                "commitment is invalid — refusing to fingerprint: {reason}"
            ))
        }
    }
    let manifest_merkle = manifest
        .merkle_root
        .clone()
        .ok_or("manifest has no merkle_root")?;
    if manifest_merkle != commitment.payload.merkle_root {
        return Err(format!(
            "merkle_root mismatch: manifest has {}, commitment has {}",
            manifest_merkle, commitment.payload.merkle_root
        ));
    }
    if manifest.project_id != commitment.payload.project_id {
        return Err(format!(
            "project_id mismatch: manifest {}, commitment {}",
            manifest.project_id, commitment.payload.project_id
        ));
    }
    if manifest.distribution_id != commitment.payload.distribution_id {
        return Err(format!(
            "distribution_id mismatch: manifest '{}', commitment '{}'",
            manifest.distribution_id, commitment.payload.distribution_id
        ));
    }

    let (archive_hash, archive_size) = hash_archive(archive)?;
    let archive_name = archive
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("archive path has no file name")?
        .to_string();

    let payload = FingerprintPayload {
        version: FINGERPRINT_VERSION.to_string(),
        archive_hash,
        archive_size,
        archive_name,
        source_tree_hash: manifest.source_tree_hash.clone(),
        merkle_root: manifest_merkle,
        commitment_digest: commitment_digest(commitment),
        project_id: manifest.project_id,
        distribution_id: manifest.distribution_id.clone(),
        timestamp,
    };

    let domain = format!("canary-fingerprint-{}", manifest.project_id);
    let bundle = derive_bundle_domain(seed, &domain)?;
    let canonical = payload.canonical_bytes();
    let sig = bundle
        .try_sign_hybrid(&canonical)
        .map_err(|e| format!("signing failed: {e}"))?;

    Ok(SignedFingerprint {
        payload,
        ed25519_sig: hex::encode(sig.ed25519_sig.to_bytes()),
        falcon1024_sig: hex::encode(sig.falcon_sig.as_bytes()),
        ed25519_pk: hex::encode(bundle.ed25519_pk().as_bytes()),
        falcon1024_pk: hex::encode(bundle.falcon1024_pk().as_bytes()),
        domain,
    })
}

// ── Publish (local JSONL ledger) ───────────────────────────────────────────

/// Append a fingerprint record to a JSONL ledger file. Creates the ledger if
/// missing; appends one line otherwise. Returns the record's index (0-based)
/// in the ledger.
pub fn publish(ledger: &Path, fingerprint: &SignedFingerprint) -> Result<usize, String> {
    // Verify before publishing — never append an unverified record.
    match fingerprint.verify()? {
        Verification::Valid => {}
        Verification::Invalid(reason) => {
            return Err(format!("refusing to publish invalid fingerprint: {reason}"))
        }
    }

    let line = serde_json::to_string(fingerprint)
        .map_err(|e| format!("cannot serialize fingerprint: {e}"))?;

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger)
        .map_err(|e| format!("cannot open ledger {}: {e}", ledger.display()))?;
    writeln!(file, "{line}").map_err(|e| format!("cannot append to ledger: {e}"))?;
    file.flush()
        .map_err(|e| format!("cannot flush ledger: {e}"))?;

    // Count lines for the returned index.
    let content =
        std::fs::read_to_string(ledger).map_err(|e| format!("cannot read back ledger: {e}"))?;
    Ok(content.lines().filter(|l| !l.trim().is_empty()).count() - 1)
}

/// Read a ledger and return all records, failing on any malformed line.
pub fn read_ledger(ledger: &Path) -> Result<Vec<SignedFingerprint>, String> {
    let content = std::fs::read_to_string(ledger)
        .map_err(|e| format!("cannot read ledger {}: {e}", ledger.display()))?;
    let mut records = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: SignedFingerprint = serde_json::from_str(line).map_err(|e| {
            format!(
                "ledger {} line {} is malformed: {e}",
                ledger.display(),
                i + 1
            )
        })?;
        records.push(record);
    }
    Ok(records)
}
