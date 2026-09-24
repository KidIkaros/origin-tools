// SPDX-License-Identifier: OPL-1.4
// Copyright (c) 2026 Origin Contributors

//! Signed commitments — Phase 2 of origin-canary.
//!
//! A commitment binds a canary manifest to a creator identity via the
//! SDK's hybrid Ed25519 + Falcon-1024 signature (both must verify).
//! Commitment bytes are canonical JSON with sorted keys, so the exact
//! bytes signed are reproducible from the manifest alone.

use crate::manifest::CanaryManifest;
use origin_crypto_sdk::pqc::falcon1024::FalconPublicKey;
use origin_crypto_sdk::pqc::falcon1024::FalconSignature;
use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle};
use origin_crypto_sdk::{Ed25519Signature, Ed25519VerifyingKey};
use serde::{Deserialize, Serialize};

/// Return the exact canonical bytes that a commitment signs over.
///
/// Canonical = `serde_json` serialization with `BTreeMap`-equivalent key
/// ordering (sorted keys) and no whitespace. These bytes are reproducible
/// from the manifest + timestamp alone, which is the reproducibility
/// guarantee documented in GOVERNANCE.md.
pub fn canonical_bytes(payload: &CommitmentPayload) -> Vec<u8> {
    payload.canonical_bytes()
}

/// Commitment format version. Bump on any change to the canonical-bytes
/// layout.
pub const COMMITMENT_VERSION: &str = "canary-commitment-v1";

/// The signed payload: canonical JSON (sorted keys, no spaces) of this
/// struct. Field set: version + merkle_root + structure + ids + timestamp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitmentPayload {
    /// Format version tag (`canary-commitment-v1`).
    pub version: String,
    /// Merkle root of the canary leaf set (hex, 64 chars).
    pub merkle_root: String,
    /// BLAKE3 digest of the manifest's structural fields (hex).
    pub structure: String,
    /// Arbitrary project identifier chosen by the creator.
    pub project_id: u64,
    /// Distribution identifier (e.g. release tag).
    pub distribution_id: String,
    /// Number of canary tokens committed.
    pub token_count: usize,
    /// Unix timestamp (seconds) when the commitment was made.
    pub timestamp: u64,
}

/// A signed commitment: payload + hybrid signature + verifying keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCommitment {
    /// The committed payload.
    pub payload: CommitmentPayload,
    /// Ed25519 signature over the canonical bytes (hex).
    pub ed25519_sig: String,
    /// Falcon-1024 signature over the canonical bytes (hex).
    pub falcon1024_sig: String,
    /// Ed25519 verifying key (hex).
    pub ed25519_pk: String,
    /// Falcon-1024 verifying key (hex).
    pub falcon1024_pk: String,
    /// Key-derivation domain used to derive the signing bundle.
    pub domain: String,
}

/// Outcome of a commitment verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// Both signatures verify over the canonical bytes.
    Valid,
    /// One or both signatures failed (details inside).
    Invalid(String),
}

impl CommitmentPayload {
    /// Canonical commitment bytes: JSON with sorted keys, no whitespace.
    /// These are the EXACT bytes covered by both signatures.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut value = serde_json::to_value(self)
            .expect("payload serializes (all fields are plain JSON types)");
        canonicalize(&mut value);
        serde_json::to_vec(&value).expect("canonical JSON encodes")
    }
}

/// Recursively sort all object keys so serialization is deterministic.
pub(crate) fn canonicalize(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, serde_json::Value)> = map
                .iter()
                .map(|(k, val)| (k.clone(), val.clone()))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            map.clear();
            for (k, mut val) in entries {
                canonicalize(&mut val);
                map.insert(k, val);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                canonicalize(item);
            }
        }
        _ => {}
    }
}

impl SignedCommitment {
    /// Verify BOTH signatures over the payload's canonical bytes.
    ///
    /// Per the hybrid construction, verification requires BOTH Ed25519
    /// AND Falcon-1024 to pass — failure of either is a hard failure.
    pub fn verify(&self) -> Result<Verification, String> {
        // Parse the embedded verifying keys.
        let ed_pk = parse_ed25519_pk(&self.ed25519_pk)?;
        let falcon_pk = parse_falcon_pk(&self.falcon1024_pk)?;

        // Parse signatures.
        let ed_bytes =
            hex::decode(&self.ed25519_sig).map_err(|e| format!("invalid ed25519_sig hex: {e}"))?;
        let ed_sig = Ed25519Signature::from_slice(&ed_bytes)
            .map_err(|e| format!("invalid ed25519_sig bytes: {e}"))?;
        let falcon_bytes = hex::decode(&self.falcon1024_sig)
            .map_err(|e| format!("invalid falcon1024_sig hex: {e}"))?;
        let falcon_sig = FalconSignature::from_bytes(&falcon_bytes)
            .map_err(|e| format!("invalid falcon1024_sig bytes: {e}"))?;

        let canonical = self.payload.canonical_bytes();

        let combined = Ed25519Falcon1024 {
            ed25519_sig: ed_sig,
            falcon_sig,
        };

        match Ed25519Falcon1024::verify(&ed_pk, &falcon_pk, &canonical, &combined) {
            Ok(()) => Ok(Verification::Valid),
            Err(e) => Ok(Verification::Invalid(format!("{e}"))),
        }
    }
}

pub(crate) fn parse_ed25519_pk(hex_str: &str) -> Result<Ed25519VerifyingKey, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid ed25519_pk hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("ed25519_pk must be 32 bytes, got {}", v.len()))?;
    Ed25519VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid ed25519_pk bytes: {e}"))
}

pub(crate) fn parse_falcon_pk(hex_str: &str) -> Result<FalconPublicKey, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid falcon1024_pk hex: {e}"))?;
    FalconPublicKey::from_bytes(&bytes).map_err(|e| format!("invalid falcon1024_pk bytes: {e}"))
}

// ── Creation ───────────────────────────────────────────────────────────────

/// Structural digest of a manifest: BLAKE3 over the canonical JSON of its
/// non-secret structural fields. Binds the commitment to the manifest's
/// shape (ids, counts, roots) without embedding any token secrets.
pub fn manifest_structure_digest(manifest: &CanaryManifest) -> String {
    let structure = serde_json::json!({
        "project_id": manifest.project_id,
        "distribution_id": manifest.distribution_id,
        "token_count": manifest.token_count,
        "merkle_root": manifest.merkle_root,
        "source_tree_hash": manifest.source_tree_hash,
    });
    let mut value = structure;
    canonicalize(&mut value);
    let bytes = serde_json::to_vec(&value).expect("structure JSON encodes");
    hex::encode(origin_crypto_sdk::blake3::hash(&bytes).as_bytes())
}

/// Build the commitment payload for a manifest at a given time.
pub fn build_payload(
    manifest: &CanaryManifest,
    timestamp: u64,
) -> Result<CommitmentPayload, String> {
    let merkle_root = manifest
        .merkle_root
        .clone()
        .ok_or_else(|| "manifest has no merkle_root — embed canaries first".to_string())?;
    Ok(CommitmentPayload {
        version: COMMITMENT_VERSION.to_string(),
        merkle_root,
        structure: manifest_structure_digest(manifest),
        project_id: manifest.project_id,
        distribution_id: manifest.distribution_id.clone(),
        token_count: manifest.token_count,
        timestamp,
    })
}

/// Derive the hybrid signing bundle for a canary commitment.
///
/// Domain is `canary-commitment-<project_id>` — domain-separated from every
/// other use of the same master seed (attestations, delegation, etc.).
pub fn derive_bundle(seed: &[u8; 32], project_id: u64) -> Result<HybridSigningKeyBundle, String> {
    derive_bundle_domain(seed, &format!("canary-commitment-{project_id}"))
}

/// Derive a hybrid signing bundle for an explicit domain.
///
/// Shared by the commitment and fingerprint signers; each passes its own
/// domain string so keys are domain-separated per record type.
pub(crate) fn derive_bundle_domain(
    seed: &[u8; 32],
    domain: &str,
) -> Result<HybridSigningKeyBundle, String> {
    // Cached: Falcon-1024 keygen is expensive (~4s); repeated sign/verify
    // with the same (seed, domain) reuses the derived bundle.
    HybridSigningKeyBundle::from_seed_cached(seed, domain)
        .map(|arc| (*arc).clone())
        .map_err(|e| format!("key derivation failed: {e}"))
}

/// Sign a manifest commitment with a derived bundle.
pub fn sign_commitment(
    manifest: &CanaryManifest,
    seed: &[u8; 32],
    timestamp: u64,
) -> Result<SignedCommitment, String> {
    let payload = build_payload(manifest, timestamp)?;
    let bundle = derive_bundle(seed, manifest.project_id)?;
    let canonical = payload.canonical_bytes();
    let sig = bundle
        .try_sign_hybrid(&canonical)
        .map_err(|e| format!("signing failed: {e}"))?;

    Ok(SignedCommitment {
        payload,
        ed25519_sig: hex::encode(sig.ed25519_sig.to_bytes()),
        falcon1024_sig: hex::encode(sig.falcon_sig.as_bytes()),
        ed25519_pk: hex::encode(bundle.ed25519_pk().as_bytes()),
        falcon1024_pk: hex::encode(bundle.falcon1024_pk().as_bytes()),
        domain: format!("canary-commitment-{}", manifest.project_id),
    })
}
