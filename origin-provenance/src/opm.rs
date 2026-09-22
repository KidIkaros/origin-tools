// SPDX-License-Identifier: Apache-2.0

//! OPM manifest model — the `<asset>.opm` sidecar (spec §2, design §2).
//!
//! Construction APIs enforce the trust-path invariants so an invalid
//! manifest cannot be *authored* through this crate: edits strictly
//! increasing from index 0 (canonical order — rejected, never reordered),
//! monotonic checkpoint timestamps (strictly increasing; see
//! `Checkpoint::next_timestamp` for the sub-second-edit rule), every
//! checkpoint signed via `try_sign_hybrid`, attestations over the
//! recomputed `manifest_id`.
//!
//! Trust path exclusions (design B): `note`, `metadata`, `watermark_hint`
//! are never covered by any signature. Loading uses `deny_unknown_fields` —
//! the canonical-order and trust-path rules make unknown-field tolerance a
//! malleability risk; new fields mean a version bump.

use std::path::Path;

use origin_proof::mmr::MmrState;
use serde::{Deserialize, Serialize};

use crate::encoding::{edit_leaf, manifest_id, Action, CheckpointBasis, DEFAULT_CHUNK_SIZE};
use crate::error::{ProvenanceError, Result};
use crate::identity::Signer;

/// Version byte for OPM v1.
pub const OPM_VERSION: u8 = 1;

/// The OPM manifest (sidecar `<asset>.opm`, design D6).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Opm {
    pub version: u8,
    pub asset_id: String,
    pub chunk_size: u32,
    pub edits: Vec<Edit>,
    pub checkpoints: Vec<Checkpoint>,
    #[serde(default)]
    pub attestations: Vec<Attestation>,
    #[serde(default)]
    pub threshold: Option<Threshold>,
    #[serde(default)]
    pub watermark_hint: Option<WatermarkHint>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Issuer-requested attestation threshold (carried only — verifiers decide).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Threshold {
    pub k: u32,
}

/// Watermark rediscovery hint (design D4 — not a trust signal).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WatermarkHint {
    pub present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// One content-binding edit event (one MMR leaf).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Edit {
    pub index: u64,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub content: ContentBinding,
    pub leaf_hash: String,
    /// Per-chunk hashes in file order (P-03 schema amendment, bound by
    /// `content.chunk_tree_root`: the verifier recomputes the S2 tree from
    /// this list and requires it to equal the stored root). Optional for
    /// wire backward-compat; `create`/`append_edit` always populate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_hashes: Option<Vec<String>>,
}

/// Content binding at an edit: whole file + chunk tree.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContentBinding {
    /// BLAKE3 over the full file at this edit (design D2).
    pub whole_file_hash: String,
    /// Merkle root of per-chunk BLAKE3 hashes.
    pub chunk_tree_root: String,
}

/// A signed history checkpoint (design F — timestamp inside the signature).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub leaf_count: u64,
    pub mmr_root: String,
    pub timestamp: i64,
    pub signer_fingerprint: String,
    /// Signer public keys (P-03 schema amendment): the verifier recomputes
    /// the fingerprint over them — transitive authentication without an
    /// out-of-band pk map. Outside `checkpoint_payload`/`manifest_id`
    /// (authenticated by the fingerprint-binding check, ticket-08 pattern).
    /// Optional for wire backward-compat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<crate::identity::SignerKeys>,
    /// Base64 (S4) hybrid signature over the checkpoint payload.
    pub signature: String,
}

impl Checkpoint {
    /// Next checkpoint timestamp: `max(now, last + 1)` so rapid successive
    /// edits cannot author a manifest that fails amendment H's
    /// strictly-increasing check at verify time.
    pub fn next_timestamp(now: i64, last: Option<i64>) -> i64 {
        match last {
            Some(prev) if now <= prev => prev + 1,
            _ => now,
        }
    }
}

/// An independent attestation over the current manifest state (design D3).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub attestor_fingerprint: String,
    /// Attestor public keys (P-03 schema amendment, same rationale as
    /// `Checkpoint::keys`). Optional for wire backward-compat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<crate::identity::SignerKeys>,
    /// Base64 (S4) hybrid signature over the attestation payload.
    pub signature: String,
}

/// The publisher's signed head announcement (ticket T-RT1): binds a
/// `manifest_id` to its edit count and asset, signed by the manifest
/// signer. Published out-of-band (the publisher's site, a receipt, the
/// work itself) where an attacker cannot rewrite it; verifiers load it
/// to detect truncated or substituted histories. Progress semantics:
/// a manifest with MORE edits than announced passes (growth beyond a
/// stale announcement); fewer — or a different head — fails.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    /// The announced manifest head (hex of the recomputed manifest_id).
    pub manifest_id: String,
    /// Edit count at announcement time.
    pub edit_count: u64,
    /// Anchor signer fingerprint — expected to be the manifest signer.
    pub signer_fingerprint: String,
    /// Anchor signer public keys (fingerprint-recomputed at verify).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<crate::identity::SignerKeys>,
    /// Base64 (S4) hybrid signature over the anchor payload.
    pub signature: String,
}

/// Content hashing helpers (BLAKE3 family — design D2).
pub mod content {
    use origin_crypto_sdk::blake3;

    /// BLAKE3 over the whole file.
    pub fn whole_file_hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    /// Chunk tree root per spec S2 (delegates to the encoding recipe).
    pub fn chunk_tree(data: &[u8], chunk_size: u32) -> [u8; 32] {
        crate::encoding::chunk_tree_root(data, chunk_size)
    }
}

impl Opm {
    /// Create a new manifest binding the CURRENT bytes of `asset` as the
    /// first edit (`Capture` by default; callers pass the initial action).
    pub fn create(asset: &Path, signer: &Signer, action: Action, chunk_size: u32) -> Result<Self> {
        let data = std::fs::read(asset)?;
        Self::create_from_bytes(&data, signer, action, chunk_size)
    }

    /// Create a manifest binding the given bytes directly — the watermark-
    /// pre-enrollment flow (D4/D6): the distributed file is `original` plus
    /// the marker, and discovery later matches via the embedded original.
    pub fn create_from_bytes(
        data: &[u8],
        signer: &Signer,
        action: Action,
        chunk_size: u32,
    ) -> Result<Self> {
        let wfh = content::whole_file_hash(data);
        let asset_id = crate::encoding::asset_id(&wfh);
        let leaf = edit_leaf(
            0,
            u8::from(action),
            &content::chunk_tree(data, chunk_size),
            &wfh,
            &asset_id,
        );

        let mut mmr = MmrState::new();
        mmr.append_hash(leaf);
        let cp = Self::checkpoint(signer, &mmr)?;

        Ok(Self {
            version: OPM_VERSION,
            asset_id: hex::encode(asset_id),
            chunk_size: if chunk_size == 0 {
                DEFAULT_CHUNK_SIZE
            } else {
                chunk_size
            },
            edits: vec![Edit {
                index: 0,
                action,
                note: None,
                content: ContentBinding::from_hashes(data, chunk_size),
                leaf_hash: hex::encode(leaf),
                chunk_hashes: Some(chunk_hashes(data, chunk_size)),
            }],
            checkpoints: vec![cp],
            attestations: Vec::new(),
            threshold: None,
            watermark_hint: None,
            metadata: None,
        })
    }

    /// Append an edit binding the CURRENT (POST-edit) bytes of `asset`
    /// (review P4-a: the file is read and hashed after the edit lands).
    /// Attestations are structurally voided by any content change (design D):
    /// the caller must re-attest the new manifest state.
    pub fn append_edit(
        &mut self,
        asset: &Path,
        signer: &Signer,
        action: Action,
        note: Option<&str>,
    ) -> Result<()> {
        let index = self.edits.last().map(|e| e.index + 1).unwrap_or(0);
        let data = std::fs::read(asset)?;
        let asset_id = self.asset_id_bytes()?;
        let leaf = edit_leaf(
            index,
            u8::from(action),
            &content::chunk_tree(&data, self.chunk_size),
            &content::whole_file_hash(&data),
            &asset_id,
        );

        self.edits.push(Edit {
            index,
            action,
            note: note.map(str::to_string),
            content: ContentBinding::from_hashes(&data, self.chunk_size),
            leaf_hash: hex::encode(leaf),
            chunk_hashes: Some(chunk_hashes(&data, self.chunk_size)),
        });

        let mut mmr = MmrState::new();
        for e in &self.edits {
            mmr.append_hash(self_leaf_hash(e)?);
        }
        let last_ts = self.checkpoints.last().map(|c| c.timestamp);
        let now = unix_now()?;
        let ts = Checkpoint::next_timestamp(now, last_ts);
        let cp = Self::sign_checkpoint_at(signer, &mmr, ts)?;
        self.checkpoints.push(cp);
        self.attestations.clear();
        Ok(())
    }

    /// Add an independent attestation over the CURRENT manifest state
    /// (design D3): signs the recomputed `manifest_id`.
    pub fn attest(&mut self, attestor: &Signer) -> Result<()> {
        let id = self.manifest_id()?;
        let payload = crate::encoding::attestation_payload_input(
            &id,
            self.edits.len() as u64,
            &self.current_mmr_root()?,
        );
        let sig = attestor.sign(&payload)?;
        self.attestations.push(Attestation {
            attestor_fingerprint: attestor.fingerprint_hex(),
            keys: Some(attestor.public_keys()),
            signature: Signer::hybrid_sig_to_base64(&sig)?,
        });
        Ok(())
    }

    /// Recompute `manifest_id` over the manifest's own signable region
    /// (spec §4). The signature inputs are derived from the struct, never
    /// stored — a tampered struct recomputes to a different id.
    pub fn manifest_id(&self) -> Result<[u8; 32]> {
        let mut leaves = Vec::with_capacity(self.edits.len());
        for e in &self.edits {
            leaves.push(self_leaf_hash(e)?);
        }
        let mut cps = Vec::with_capacity(self.checkpoints.len());
        for cp in &self.checkpoints {
            cps.push(CheckpointBasis {
                leaf_count: cp.leaf_count,
                mmr_root: decode32(&cp.mmr_root)?,
                timestamp: cp.timestamp,
                signer_fingerprint_raw: decode32(&cp.signer_fingerprint)?,
            });
        }
        let asset_id = self.asset_id_bytes()?;
        let threshold = self.threshold.map(|t| t.k);
        Ok(manifest_id(
            self.version,
            &asset_id,
            self.chunk_size,
            &leaves,
            &cps,
            threshold,
        ))
    }

    /// Current MMR root over all edit leaves (recomputed, not stored).
    pub fn current_mmr_root(&self) -> Result<[u8; 32]> {
        let mut mmr = MmrState::new();
        for e in &self.edits {
            mmr.append_hash(self_leaf_hash(e)?);
        }
        Ok(mmr.root())
    }

    /// Author the head anchor (ticket T-RT1): signer's hybrid signature
    /// over `(edit_count, manifest_id, asset_id)` — call after the
    /// manifest is final and publish the result out-of-band.
    pub fn anchor(&self, signer: &Signer) -> Result<Anchor> {
        let id = self.manifest_id()?;
        let asset_id = self.asset_id_bytes()?;
        let payload =
            crate::encoding::anchor_payload_input(self.edits.len() as u64, &id, &asset_id);
        let sig = signer.sign(&payload)?;
        Ok(Anchor {
            manifest_id: hex::encode(id),
            edit_count: self.edits.len() as u64,
            signer_fingerprint: signer.fingerprint_hex(),
            keys: Some(signer.public_keys()),
            signature: Signer::hybrid_sig_to_base64(&sig)?,
        })
    }

    /// Recompute `manifest_id` as of the FIRST `n` edits (ticket T-RT1
    /// growth semantics): leaves 0..n plus every checkpoint whose
    /// `leaf_count` ≤ n. The threshold request is a creation-time
    /// property in v1 (nothing mutates it after `create`), so it is
    /// always included. Errors when `n` exceeds the present edit count.
    pub fn manifest_id_at(&self, n: u64) -> Result<[u8; 32]> {
        let count = n as usize;
        if count > self.edits.len() {
            return Err(ProvenanceError::InvalidManifest(
                "anchor count exceeds present edits".into(),
            ));
        }
        let mut leaves = Vec::with_capacity(count);
        for e in &self.edits[..count] {
            leaves.push(self_leaf_hash(e)?);
        }
        let mut cps = Vec::new();
        for cp in &self.checkpoints {
            if cp.leaf_count <= n {
                cps.push(CheckpointBasis {
                    leaf_count: cp.leaf_count,
                    mmr_root: decode32(&cp.mmr_root)?,
                    timestamp: cp.timestamp,
                    signer_fingerprint_raw: decode32(&cp.signer_fingerprint)?,
                });
            }
        }
        let asset_id = self.asset_id_bytes()?;
        Ok(manifest_id(
            self.version,
            &asset_id,
            self.chunk_size,
            &leaves,
            &cps,
            self.threshold.map(|t| t.k),
        ))
    }

    /// Verify an anchor against THIS manifest (ticket T-RT1):
    /// - the anchor signer's embedded keys must recompute to the anchor
    ///   fingerprint (transitive authentication, ticket-08 pattern);
    /// - head check (progress semantics):
    ///   · presented edits == announced count ⇒ the manifest head must
    ///     equal the announced `manifest_id`;
    ///   · presented edits > announced (growth beyond a stale
    ///     announcement) ⇒ the announced head must be a GENUINE PREFIX
    ///     of the presented history — the prefix id at the announced
    ///     count must equal the announced `manifest_id`;
    ///   · presented edits < announced ⇒ truncation ⇒ fail.
    /// Signature failures, key mismatches, and head mismatches are all
    /// just `false` — an anchor never upgrades a verdict, it only fails
    /// closed.
    pub fn verify_anchor(&self, anchor: &Anchor) -> Result<bool> {
        let presented = self.edits.len() as u64;
        let head_ok = if presented == anchor.edit_count {
            hex::encode(self.manifest_id()?) == anchor.manifest_id
        } else if presented > anchor.edit_count {
            hex::encode(self.manifest_id_at(anchor.edit_count)?) == anchor.manifest_id
        } else {
            false // presented < announced: the history shrank
        };
        if !head_ok {
            return Ok(false);
        }
        // Signature binds the ANNOUNCED head. In both pass branches the
        // prefix id at the announced count equals the announced head
        // (equality: the full head; growth: verified above), so this is
        // exactly the payload the publisher signed.
        let id = self.manifest_id_at(anchor.edit_count)?;
        let asset_id = self.asset_id_bytes()?;
        let payload = crate::encoding::anchor_payload_input(anchor.edit_count, &id, &asset_id);
        let keys = anchor
            .keys
            .as_ref()
            .ok_or_else(|| ProvenanceError::InvalidManifest("anchor missing keys".into()))?;
        let ed: [u8; 32] = hex::decode(&keys.ed25519_pk)
            .map_err(|e| ProvenanceError::InvalidManifest(format!("anchor ed pk: {e}")))?
            .try_into()
            .map_err(|_| {
                ProvenanceError::InvalidManifest("anchor ed pk: expected 32 bytes".into())
            })?;
        let falcon = hex::decode(&keys.falcon_pk)
            .map_err(|e| ProvenanceError::InvalidManifest(format!("anchor falcon pk: {e}")))?;
        let recomputed = crate::encoding::signer_fingerprint(&ed, &falcon)
            .map_err(|e| ProvenanceError::InvalidManifest(format!("anchor fp: {e}")))?;
        if hex::encode(recomputed) != anchor.signer_fingerprint {
            return Ok(false);
        }
        let sig = Signer::hybrid_sig_from_base64(&anchor.signature)?;
        Ok(sig.verify(&ed, &falcon, &payload).is_ok())
    }

    /// Sign and add a checkpoint over the current MMR state.
    fn checkpoint(signer: &Signer, mmr: &MmrState) -> Result<Checkpoint> {
        let ts = unix_now()?;
        Self::sign_checkpoint_at(signer, mmr, ts)
    }

    fn sign_checkpoint_at(signer: &Signer, mmr: &MmrState, ts: i64) -> Result<Checkpoint> {
        let root = mmr.root();
        let payload = crate::encoding::checkpoint_payload_input(
            mmr.leaf_count,
            &root,
            ts,
            &signer.fingerprint_raw(),
        );
        let sig = signer.sign(&payload)?;
        Ok(Checkpoint {
            leaf_count: mmr.leaf_count,
            mmr_root: hex::encode(root),
            timestamp: ts,
            signer_fingerprint: signer.fingerprint_hex(),
            keys: Some(signer.public_keys()),
            signature: Signer::hybrid_sig_to_base64(&sig)?,
        })
    }

    fn asset_id_bytes(&self) -> Result<[u8; 32]> {
        decode32(&self.asset_id)
    }
}

impl ContentBinding {
    fn from_hashes(data: &[u8], chunk_size: u32) -> Self {
        Self {
            whole_file_hash: hex::encode(content::whole_file_hash(data)),
            chunk_tree_root: hex::encode(content::chunk_tree(data, chunk_size)),
        }
    }
}

fn chunk_hashes(data: &[u8], chunk_size: u32) -> Vec<String> {
    let cs = chunk_size.max(1) as usize;
    data.chunks(cs)
        .map(|c| hex::encode(origin_crypto_sdk::blake3::hash(c).as_bytes()))
        .collect()
}

fn self_leaf_hash(e: &Edit) -> Result<[u8; 32]> {
    decode32(&e.leaf_hash)
}

fn decode32(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| ProvenanceError::InvalidManifest(format!("bad hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| ProvenanceError::InvalidManifest("expected 32-byte hex".into()))
}

fn unix_now() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| ProvenanceError::Other(format!("clock before epoch: {e}")))
}

/// Load an OPM manifest from `path` (strict: unknown fields reject).
pub fn load(path: &Path) -> Result<Opm> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text)
        .map_err(|e| ProvenanceError::InvalidManifest(format!("unparseable manifest: {e}")))
}

/// Save an OPM manifest to `path` (pretty JSON; field order is not
/// canonical — `signable_bytes` are).
pub fn save(opm: &Opm, path: &Path) -> Result<()> {
    let text = serde_json::to_string_pretty(opm)
        .map_err(|e| ProvenanceError::InvalidManifest(format!("serialize: {e}")))?;
    Ok(std::fs::write(path, text)?)
}

/// Default sidecar path (spec §6 pin): `<asset>.opm`.
pub fn sidecar_path(asset: &Path) -> std::path::PathBuf {
    let mut os = asset.as_os_str().to_os_string();
    os.push(".opm");
    std::path::PathBuf::from(os)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x42u8; 32];

    fn signer() -> Signer {
        Signer::from_seed(&SEED).expect("derive signer")
    }

    fn temp_file(dir: &tempfile::TempDir, name: &str, data: &[u8]) -> std::path::PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, data).unwrap();
        p
    }

    #[test]
    fn create_append_attest_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let s = signer();
        let file = temp_file(&dir, "doc.txt", b"first draft");

        let mut opm = Opm::create(&file, &s, Action::Capture, DEFAULT_CHUNK_SIZE).expect("create");
        std::fs::write(&file, b"second draft, edited").unwrap();
        opm.append_edit(&file, &s, Action::Edit, Some("rewrite"))
            .expect("append");
        opm.attest(&s).expect("attest");

        let sidecar = dir.path().join("doc.txt.opm");
        save(&opm, &sidecar).expect("save");
        let loaded = load(&sidecar).expect("load");

        // Signable region byte-identical across the roundtrip.
        assert_eq!(
            loaded.manifest_id().expect("id"),
            opm.manifest_id().expect("id")
        );
        assert_eq!(loaded.edits.len(), 2);
        assert_eq!(loaded.edits[1].index, 1);
        assert_eq!(loaded.edits[1].note.as_deref(), Some("rewrite"));
        assert_eq!(loaded.attestations.len(), 1);
        assert_eq!(loaded.checkpoints.len(), 2);
    }

    #[test]
    fn unknown_fields_rejected_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let s = signer();
        let file = temp_file(&dir, "u.txt", b"data");
        let mut opm = Opm::create(&file, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        opm.attest(&s).unwrap();
        let sidecar = dir.path().join("u.txt.opm");
        save(&opm, &sidecar).unwrap();

        // Inject an unknown field.
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&sidecar).unwrap()).unwrap();
        v["sneaky_field"] = serde_json::json!("injected");
        std::fs::write(&sidecar, serde_json::to_string(&v).unwrap()).unwrap();

        let err = load(&sidecar).unwrap_err();
        assert!(err.to_string().contains("unknown"), "got: {err}");
    }

    #[test]
    fn canonical_order_enforced_by_construction() {
        // Edits are strictly increasing from 0 by construction; the manifest
        // model has no out-of-order insert API (rejection, not reordering).
        let dir = tempfile::tempdir().unwrap();
        let s = signer();
        let file = temp_file(&dir, "c.txt", b"a");
        let mut opm = Opm::create(&file, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        std::fs::write(&file, b"b").unwrap();
        opm.append_edit(&file, &s, Action::Edit, None).unwrap();
        std::fs::write(&file, b"c").unwrap();
        opm.append_edit(&file, &s, Action::Edit, None).unwrap();
        for (i, e) in opm.edits.iter().enumerate() {
            assert_eq!(e.index, i as u64);
        }
    }

    #[test]
    fn append_edit_binds_post_edit_bytes_p4a() {
        let dir = tempfile::tempdir().unwrap();
        let s = signer();
        let file = temp_file(&dir, "p4a.txt", b"before");
        let mut opm = Opm::create(&file, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();

        std::fs::write(&file, b"after").unwrap();
        opm.append_edit(&file, &s, Action::Edit, None).unwrap();

        // The edit's whole_file_hash must be BLAKE3("after"), not "before".
        let expected = hex::encode(content::whole_file_hash(b"after"));
        assert_eq!(opm.edits[1].content.whole_file_hash, expected);
        // ...and different from the capture's binding.
        assert_ne!(
            opm.edits[0].content.whole_file_hash,
            opm.edits[1].content.whole_file_hash
        );
    }

    #[test]
    fn checkpoint_signature_verifies_with_timestamp_inside() {
        let dir = tempfile::tempdir().unwrap();
        let s = signer();
        let file = temp_file(&dir, "sig.txt", b"payload");
        let opm = Opm::create(&file, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        let cp = &opm.checkpoints[0];

        // Rebuild the payload FROM THE STRUCT and verify the signature.
        let payload = crate::encoding::checkpoint_payload_input(
            cp.leaf_count,
            &decode32(&cp.mmr_root).unwrap(),
            cp.timestamp,
            &decode32(&cp.signer_fingerprint).unwrap(),
        );
        let sig = Signer::hybrid_sig_from_base64(&cp.signature).expect("b64 sig");
        let (ed, falcon) = s.pk_bytes();
        sig.verify(&ed, &falcon, &payload)
            .expect("checkpoint sig verifies");

        // Tampered timestamp must break verification (timestamp is inside
        // the signature — design F).
        let tampered = crate::encoding::checkpoint_payload_input(
            cp.leaf_count,
            &decode32(&cp.mmr_root).unwrap(),
            cp.timestamp + 1,
            &decode32(&cp.signer_fingerprint).unwrap(),
        );
        assert!(sig.verify(&ed, &falcon, &tampered).is_err());
    }

    #[test]
    fn attestation_signs_recomputed_manifest_id_and_voids_on_append() {
        let dir = tempfile::tempdir().unwrap();
        let s = signer();
        let a = Signer::from_seed(&[7u8; 32]).unwrap(); // independent attestor
        let file = temp_file(&dir, "att.txt", b"one");
        let mut opm = Opm::create(&file, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();

        opm.attest(&a).unwrap();
        assert_eq!(opm.attestations.len(), 1);

        // Rebuild the attestation payload FROM THE STRUCT: the signature
        // must verify over the recomputed manifest_id (design D).
        let id = opm.manifest_id().unwrap();
        let cp = opm.checkpoints.last().unwrap();
        let payload = crate::encoding::attestation_payload_input(
            &id,
            opm.edits.len() as u64,
            &decode32(&cp.mmr_root).unwrap(),
        );
        let sig = Signer::hybrid_sig_from_base64(&opm.attestations[0].signature).unwrap();
        let (ed, falcon) = a.pk_bytes();
        sig.verify(&ed, &falcon, &payload)
            .expect("attestation verifies");

        // A content change voids the attestation set (design D).
        std::fs::write(&file, b"two").unwrap();
        opm.append_edit(&file, &s, Action::Edit, None).unwrap();
        assert!(opm.attestations.is_empty(), "append must void attestations");
    }

    #[test]
    fn rapid_edits_produce_strictly_increasing_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let s = signer();
        let file = temp_file(&dir, "rapid.txt", b"x");
        let mut opm = Opm::create(&file, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        for i in 0..5 {
            std::fs::write(&file, format!("edit {i}")).unwrap();
            opm.append_edit(&file, &s, Action::Edit, None).unwrap();
        }
        let ts: Vec<i64> = opm.checkpoints.iter().map(|c| c.timestamp).collect();
        for w in ts.windows(2) {
            assert!(w[1] > w[0], "timestamps strictly increasing: {ts:?}");
        }
    }
    #[test]
    fn manifest_id_sensitivity_matches_trust_path() {
        // manifest_id is a function of asset_id, chunk_size, leaf hashes,
        // checkpoints, and threshold (spec §2: content binds via leaf_hash).
        // History tampering moves it; content-field tampering does NOT move
        // it (that is caught at verify by the leaf-hash recompute) — this
        // documents the trust-path split, not a weakness.
        let dir = tempfile::tempdir().unwrap();
        let s = signer();
        let file = temp_file(&dir, "m.txt", b"data");
        let opm = Opm::create(&file, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        let id1 = opm.manifest_id().unwrap();

        let mut leaf_tampered = opm.clone();
        leaf_tampered.edits[0].leaf_hash = hex::encode([9u8; 32]);
        assert_ne!(id1, leaf_tampered.manifest_id().unwrap());

        let mut asset_tampered = opm.clone();
        asset_tampered.asset_id = hex::encode([8u8; 32]);
        assert_ne!(id1, asset_tampered.manifest_id().unwrap());

        let mut threshold_changed = opm.clone();
        threshold_changed.threshold = Some(Threshold { k: 2 });
        assert_ne!(id1, threshold_changed.manifest_id().unwrap());

        let mut content_tampered = opm.clone();
        content_tampered.edits[0].content.whole_file_hash = hex::encode([9u8; 32]);
        assert_eq!(
            id1,
            content_tampered.manifest_id().unwrap(),
            "content fields bind via leaf_hash recompute at verify, not via manifest_id"
        );
    }

    #[test]
    fn sidecar_path_convention() {
        let p = sidecar_path(Path::new("/tmp/movie.mp4"));
        assert_eq!(p, Path::new("/tmp/movie.mp4.opm"));
    }
}
