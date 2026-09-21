// SPDX-License-Identifier: Apache-2.0

//! The OPM verification engine — normative check order and honest output
//! contract (design §3; spec §5).
//!
//! Check order (normative — do not reorder):
//! 1. locate sidecar (watermark fallback lands in P-04)
//! 2. parse + structure; canonical edit order (strictly increasing index
//!    from 0 — rejected, never reordered). Checkpoint `leaf_count`
//!    monotonicity is deliberately NOT checked here (design H): a
//!    non-monotonic sequence is rejected at step 4 as `history-rewind`.
//! 3. content binding: whole-file hash + chunk tree + per-chunk report
//!    (partial failure is reportable, then fatal with chunk detail)
//! 4. MMR consistency: every checkpoint replayed (root match at its
//!    leaf_count + membership proof of its final leaf) + strictly
//!    increasing timestamps; `leaf_count` <= any earlier ⇒
//!    `history-rewind` (distinct reason, amendment H)
//! 5. checkpoint signature (Ed25519 AND Falcon — both must verify);
//!    keys come from the checkpoint's embedded `keys` recomputed to the
//!    fingerprint (transitive authentication, ticket-08 pattern) or the
//!    verifier roster; mismatch ⇒ `key-binding`
//! 6. timestamp sanity: no future checkpoints (verifier-local now)
//! 7. revocation: journal `is_revoked(signer fp)` (wired in P-05; stubbed
//!    here — journal dependency not yet in scope)
//! 8. threshold: every attestation verifies over the RECOMPUTED
//!    manifest_id (⇒ `attestation-binding` on mismatch); distinct valid
//!    non-revoked attestor fps ≥ authoritative K ⇒ degraded-intact
//!    `manifest-intact (unattested: k of K required valid)` on shortfall;
//!    signer ∈ attestors is FLAGGED, not rejected (design §3 step 8)
//! 9. local policy: verifier-owned (ZTNA) — this engine reports; policy
//!    layers decide.
//!
//! Output contract: `manifest-intact as of T` (T = latest checkpoint time),
//! `manifest-invalid: <reason>`, `no-manifest` — always with the
//! "what was checked / what was not" footer. Metadata ignored; watermark =
//! hint only; timestamps are signer-asserted, not TSA-attested. No
//! "Content Credentials" phrasing anywhere (voice rule).

use std::path::Path;

use origin_proof::mmr::MmrState;

use crate::encoding::{edit_leaf, Action};
use crate::identity::SignerKeys;
use crate::opm::content;
use crate::opm::{self, Opm};

/// Per-chunk integrity summary (design §3 step 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkReport {
    pub total: usize,
    pub matched: usize,
    /// Index of the first mismatched chunk, if any.
    pub first_mismatch: Option<usize>,
}

impl ChunkReport {
    /// Verbatim-worthy one-liner (kept stable for tests/output).
    pub fn summarize(&self) -> String {
        match (self.first_mismatch, self.total) {
            (None, 0) => "chunks: 0 (empty file)".to_string(),
            (None, _) => format!("chunks: {}/{} matched", self.matched, self.total),
            (Some(i), _) => format!(
                "chunks: {}/{} matched; first mismatch at chunk {i}",
                self.matched, self.total
            ),
        }
    }
}

/// Why a manifest was rejected (design §3 — distinct wordings are the point).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvalidReason {
    Unparseable,
    NonCanonical,
    ContentHash { chunk: Option<usize> },
    History,
    HistoryRewind,
    KeyBinding,
    SignerSignature,
    Timestamp,
    SignerRevoked { journal_tip: i64 },
    AttestationBinding,
}

impl InvalidReason {
    /// The exact `manifest-invalid (<label>)` fragment (design §3 step
    /// wordings; distinct per reason).
    pub fn label(&self) -> String {
        match self {
            InvalidReason::Unparseable => "manifest-invalid (unparseable)".into(),
            InvalidReason::NonCanonical => "manifest-invalid (non-canonical)".into(),
            InvalidReason::ContentHash { chunk } => match chunk {
                Some(i) => format!("manifest-invalid (content-hash: chunk {i})"),
                None => "manifest-invalid (content-hash)".into(),
            },
            InvalidReason::History => "manifest-invalid (history)".into(),
            InvalidReason::HistoryRewind => "manifest-invalid (history-rewind)".into(),
            InvalidReason::KeyBinding => "manifest-invalid (key-binding)".into(),
            InvalidReason::SignerSignature => "manifest-invalid (signer-signature)".into(),
            InvalidReason::Timestamp => "manifest-invalid (timestamp)".into(),
            InvalidReason::SignerRevoked { journal_tip } => {
                format!("manifest-invalid (signer-revoked, as of journal tip {journal_tip})")
            }
            InvalidReason::AttestationBinding => "manifest-invalid (attestation-binding)".into(),
        }
    }
}

/// The three-state output (design §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// History + content + signatures + threshold all verified.
    Intact {
        /// Latest checkpoint time (the "as of" instant; journal tip joins
        /// the min() in P-05 when revocation lands).
        as_of: i64,
        chunk_report: ChunkReport,
        /// Design §3 step 8: signer ∈ attestors is flagged, not rejected.
        self_attestation_flag: bool,
        /// Authoritative-K shortfall: `manifest-intact (unattested: k of K
        /// required valid)` — degraded-intact, never silently dropped.
        unattested: Option<(usize, u32)>,
        /// Issuer-requested vs authoritative K, shown when both present
        /// and different (design §3 step 8).
        k_discrepancy: Option<(u32, u32)>,
    },
    Invalid(InvalidReason),
    /// No sidecar found. (Watermark fallback lands in P-04.)
    NoManifest {
        sidecar_path: String,
    },
}

impl VerifyOutcome {
    /// One-line verdict (stable strings; tests pin them).
    pub fn headline(&self) -> String {
        match self {
            VerifyOutcome::Intact { as_of, .. } => format!("manifest-intact as of {as_of}"),
            VerifyOutcome::Invalid(r) => r.label(),
            VerifyOutcome::NoManifest { sidecar_path } => {
                format!("no-manifest (no sidecar at {sidecar_path})")
            }
        }
    }

    /// The mandatory "what was checked / what was not" footer (design §3).
    pub fn footer(&self) -> String {
        "checked: canonical edit order, content binding (whole file + chunks), \
MMR replay at every checkpoint, checkpoint signatures (Ed25519+Falcon), \
timestamp sanity, attestation binding. \
not checked: metadata (ignored), watermark (hint only), \
timestamps are signer-asserted not TSA-attested, revocation (wired in a later ticket)."
            .to_string()
    }
}

/// Verifier-owned policy (ZTNA — design §3 step 9). The tool supplies
/// structure; the verifier decides values.
#[derive(Clone, Debug, Default)]
pub struct VerifyPolicy {
    /// Verifier's `now` (unix seconds) for the future-timestamp check.
    /// `None` = use system time.
    pub now: Option<i64>,
    /// Authoritative attestation threshold K (verifier-side). `None` = no
    /// attestation requirement (attestations, if present, still must verify).
    pub required_k: Option<u32>,
    /// Verifier-supplied roster of trusted signer/attestor fingerprints.
    /// `None` = no roster constraint (keys come from embedded material).
    pub allow_roster: Option<Vec<String>>,
    /// Journal path — accepted here, consumed when revocation wires in P-05.
    pub journal_path: Option<std::path::PathBuf>,
}

/// Resolve the key material for a fingerprint: embedded `keys` must recompute
/// to `expected_fp` (transitive authentication); a verifier roster overrides
/// (verifier-local trust beats embedded material). Design §3 step 5 + ZTNA.
fn keys_for(
    expected_fp: &str,
    embedded: Option<&SignerKeys>,
    roster: Option<&Vec<String>>,
) -> Result<SignerKeys, InvalidReason> {
    if let Some(list) = roster {
        if let Some(fp) = list.iter().find(|f| *f == expected_fp) {
            let _ = fp; // roster carries fingerprints; keys still from embedded
        } else {
            return Err(InvalidReason::KeyBinding);
        }
    }
    match embedded {
        Some(keys) => {
            let ed: [u8; 32] = hex::decode(&keys.ed25519_pk)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or(InvalidReason::KeyBinding)?;
            let falcon = hex::decode(&keys.falcon_pk).map_err(|_| InvalidReason::KeyBinding)?;
            let recomputed = crate::encoding::signer_fingerprint(&ed, &falcon)
                .map_err(|_| InvalidReason::KeyBinding)?;
            if hex::encode(recomputed) == expected_fp {
                Ok(keys.clone())
            } else {
                Err(InvalidReason::KeyBinding)
            }
        }
        None => Err(InvalidReason::KeyBinding),
    }
}

/// Verify `asset` against its sidecar (or the explicit one given).
pub fn verify(asset: &Path, sidecar: Option<&Path>, policy: &VerifyPolicy) -> VerifyOutcome {
    // Step 1 — locate the manifest.
    let path: std::path::PathBuf = match sidecar {
        Some(p) => p.to_path_buf(),
        None => opm::sidecar_path(asset),
    };
    if !path.exists() {
        return VerifyOutcome::NoManifest {
            sidecar_path: path.to_string_lossy().into_owned(),
        };
    }

    // Step 2 — parse + structure.
    let opm = match opm::load(&path) {
        Ok(o) => o,
        Err(_) => return VerifyOutcome::Invalid(InvalidReason::Unparseable),
    };
    if opm.version != opm::OPM_VERSION {
        return VerifyOutcome::Invalid(InvalidReason::Unparseable);
    }
    if let Err(reason) = check_structure(&opm) {
        return VerifyOutcome::Invalid(reason);
    }

    // Step 3 — content binding (reportable per-chunk, then fatal).
    let (report, reason) = check_content(asset, &opm);
    if let Some(r) = reason {
        return VerifyOutcome::Invalid(r);
    }
    let report = report.expect("content check produced a report on success path");

    // Step 4 — MMR consistency for every checkpoint + rewind check (H).
    if let Err(reason) = check_mmr_history(&opm) {
        return VerifyOutcome::Invalid(reason);
    }

    // Step 5 — checkpoint signatures with embedded/roster keys.
    if let Err(reason) = check_checkpoint_signatures(&opm, policy.allow_roster.as_ref()) {
        return VerifyOutcome::Invalid(reason);
    }

    // Step 6 — timestamp sanity (verifier-local now).
    let now = policy.now.unwrap_or_else(unix_now);
    if opm.checkpoints.iter().any(|c| c.timestamp > now) {
        return VerifyOutcome::Invalid(InvalidReason::Timestamp);
    }

    // Step 7 — revocation: P-05 wires the journal; the policy already
    // accepts the path so callers are forward-compatible.

    // Step 8 — threshold.
    let threshold = match check_attestations(&opm, policy.required_k) {
        Ok(t) => t,
        Err(reason) => return VerifyOutcome::Invalid(reason),
    };

    VerifyOutcome::Intact {
        as_of: opm
            .checkpoints
            .last()
            .map(|c| c.timestamp)
            .unwrap_or_default(),
        chunk_report: report,
        self_attestation_flag: threshold.self_attestation,
        unattested: threshold.unattested,
        k_discrepancy: threshold.k_discrepancy,
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Step 2 structural rules: canonical edit order (reject, never reorder).
fn check_structure(opm: &Opm) -> Result<(), InvalidReason> {
    for (i, e) in opm.edits.iter().enumerate() {
        if e.index != i as u64 {
            return Err(InvalidReason::NonCanonical);
        }
    }
    Ok(())
}

/// Step 3: recompute whole-file hash + chunk tree; build the per-chunk
/// report against the stored `chunk_hashes` when present. The stored
/// `chunk_tree_root` binds the list: recompute-from-list must equal root.
fn check_content(asset: &Path, opm: &Opm) -> (Option<ChunkReport>, Option<InvalidReason>) {
    let data = match std::fs::read(asset) {
        Ok(d) => d,
        Err(_) => return (None, Some(InvalidReason::ContentHash { chunk: None })),
    };
    let edit = match opm.edits.last() {
        Some(e) => e,
        None => return (None, Some(InvalidReason::History)),
    };

    // Chunk-level analysis FIRST so the report can name the failing chunk;
    // whole-file binding is then either confirmed by the same comparison or
    // is the fallback when no per-chunk list exists (P-02-era manifests).
    let report = match &edit.chunk_hashes {
        Some(list) => {
            let cs = opm.chunk_size.max(1) as usize;
            let computed: Vec<[u8; 32]> = data
                .chunks(cs)
                .map(|c| *origin_crypto_sdk::blake3::hash(c).as_bytes())
                .collect();
            let first_mismatch = computed
                .iter()
                .zip(list.iter())
                .position(|(a, b)| hex::encode(a) != *b);
            let matched = computed
                .iter()
                .zip(list.iter())
                .filter(|(a, b)| hex::encode(a) == **b)
                .count();
            Some(ChunkReport {
                total: computed.len(),
                matched,
                first_mismatch,
            })
        }
        None => None,
    };

    if let Some(rep) = &report {
        // The stored root binds the stored list; the whole-file hash binds
        // the recomputed tree. Both must agree with the current file.
        let root_from_file = content::chunk_tree(&data, opm.chunk_size);
        if hex::encode(root_from_file) != edit.content.chunk_tree_root
            || hex::encode(content::whole_file_hash(&data)) != edit.content.whole_file_hash
        {
            let reason = rep
                .first_mismatch
                .map(|i| InvalidReason::ContentHash { chunk: Some(i) })
                .unwrap_or(InvalidReason::ContentHash { chunk: None });
            return (Some(rep.clone()), Some(reason));
        }
        // File matches the manifest exactly.
        return (Some(rep.clone()), None);
    }

    // No stored list: whole-file + tree checks only.
    if hex::encode(content::whole_file_hash(&data)) != edit.content.whole_file_hash
        || hex::encode(content::chunk_tree(&data, opm.chunk_size)) != edit.content.chunk_tree_root
    {
        return (None, Some(InvalidReason::ContentHash { chunk: None }));
    }
    (
        Some(ChunkReport {
            total: 0,
            matched: 0,
            first_mismatch: None,
        }),
        None,
    )
}

/// Step 4: replay the MMR at every checkpoint; require strictly increasing
/// timestamps; reject a checkpoint whose leaf_count does not exceed every
/// earlier one as `history-rewind` (amendment H).
fn check_mmr_history(opm: &Opm) -> Result<(), InvalidReason> {
    // Amendment H scan FIRST: a non-monotonic leaf_count sequence is the
    // distinct rewind reason and must not be masked by a replay failure.
    let mut last_leaf_count: Option<u64> = None;
    let mut last_ts: Option<i64> = None;
    for cp in &opm.checkpoints {
        if let Some(prev) = last_leaf_count {
            if cp.leaf_count <= prev {
                return Err(InvalidReason::HistoryRewind);
            }
        }
        if let Some(prev) = last_ts {
            if cp.timestamp <= prev {
                return Err(InvalidReason::History);
            }
        }
        last_leaf_count = Some(cp.leaf_count);
        last_ts = Some(cp.timestamp);
    }

    // asset_id is a MANIFEST-level constant (spec S1: derived from the
    // FIRST edit's whole-file hash) — recompute it once, not per-edit.
    let first_wfh: [u8; 32] = hex::decode(
        &opm.edits
            .first()
            .ok_or(InvalidReason::History)?
            .content
            .whole_file_hash,
    )
    .ok()
    .and_then(|b| b.try_into().ok())
    .ok_or(InvalidReason::History)?;
    let asset_id = crate::encoding::asset_id(&first_wfh);

    let mut mmr = MmrState::new();
    let mut replayed: u64 = 0;
    for e in &opm.edits {
        let ctr: [u8; 32] = hex::decode(&e.content.chunk_tree_root)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(InvalidReason::History)?;
        let wfh: [u8; 32] = hex::decode(&e.content.whole_file_hash)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(InvalidReason::History)?;
        mmr.append_hash(edit_leaf(
            e.index,
            u8::from(e.action),
            &ctr,
            &wfh,
            &asset_id,
        ));
        replayed += 1;

        // Any checkpoint anchored exactly at this prefix must replay to its
        // stored root.
        for cp in &opm.checkpoints {
            if cp.leaf_count == replayed && hex::encode(mmr.root()) != cp.mmr_root {
                return Err(InvalidReason::History);
            }
        }
    }

    for cp in &opm.checkpoints {
        if cp.leaf_count > replayed {
            return Err(InvalidReason::History);
        }
    }
    Ok(())
}

/// Step 5: every checkpoint's signature verifies (both halves) against the
/// fingerprint-recomputed embedded keys (or roster override).
fn check_checkpoint_signatures(
    opm: &Opm,
    roster: Option<&Vec<String>>,
) -> Result<(), InvalidReason> {
    for cp in &opm.checkpoints {
        let keys = keys_for(&cp.signer_fingerprint, cp.keys.as_ref(), roster)?;
        let ed: [u8; 32] = hex::decode(&keys.ed25519_pk)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(InvalidReason::KeyBinding)?;
        let falcon = hex::decode(&keys.falcon_pk).map_err(|_| InvalidReason::KeyBinding)?;
        let payload = crate::encoding::checkpoint_payload_input(
            cp.leaf_count,
            &decode32(&cp.mmr_root).ok_or(InvalidReason::History)?,
            cp.timestamp,
            &decode32(&cp.signer_fingerprint).ok_or(InvalidReason::History)?,
        );
        let sig = crate::identity::Signer::hybrid_sig_from_base64(&cp.signature)
            .map_err(|_| InvalidReason::SignerSignature)?;
        sig.verify(&ed, &falcon, &payload)
            .map_err(|_| InvalidReason::SignerSignature)?;
    }
    Ok(())
}

struct ThresholdResult {
    self_attestation: bool,
    unattested: Option<(usize, u32)>,
    k_discrepancy: Option<(u32, u32)>,
}

/// Step 8: attestation binding + distinct-count threshold.
fn check_attestations(
    opm: &Opm,
    required_k: Option<u32>,
) -> Result<ThresholdResult, InvalidReason> {
    if opm.attestations.is_empty() {
        let unattested = required_k.map(|k| (0, k));
        return Ok(ThresholdResult {
            self_attestation: false,
            unattested,
            k_discrepancy: None,
        });
    }

    let manifest_id = opm
        .manifest_id()
        .map_err(|_| InvalidReason::AttestationBinding)?;
    let mut distinct: Vec<String> = Vec::new();
    for att in &opm.attestations {
        let keys = keys_for(&att.attestor_fingerprint, att.keys.as_ref(), None)?;
        let ed: [u8; 32] = hex::decode(&keys.ed25519_pk)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(InvalidReason::AttestationBinding)?;
        let falcon = hex::decode(&keys.falcon_pk).map_err(|_| InvalidReason::AttestationBinding)?;
        let cp = opm.checkpoints.last().ok_or(InvalidReason::History)?;
        let payload = crate::encoding::attestation_payload_input(
            &manifest_id,
            cp.leaf_count,
            &decode32(&cp.mmr_root).ok_or(InvalidReason::History)?,
        );
        let sig = crate::identity::Signer::hybrid_sig_from_base64(&att.signature)
            .map_err(|_| InvalidReason::AttestationBinding)?;
        sig.verify(&ed, &falcon, &payload)
            .map_err(|_| InvalidReason::AttestationBinding)?;
        if !distinct.contains(&att.attestor_fingerprint) {
            distinct.push(att.attestor_fingerprint.clone());
        }
    }

    let self_attestation = opm
        .checkpoints
        .first()
        .map(|c| distinct.contains(&c.signer_fingerprint))
        .unwrap_or(false);

    let unattested = required_k
        .filter(|k| distinct.len() < *k as usize)
        .map(|k| (distinct.len(), k));
    let k_discrepancy = match (opm.threshold, required_k) {
        (Some(issuer), auth) if auth.is_some() && issuer.k != auth.unwrap() => {
            Some((issuer.k, auth.unwrap()))
        }
        _ => None,
    };
    Ok(ThresholdResult {
        self_attestation,
        unattested,
        k_discrepancy,
    })
}

fn decode32(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str).ok().and_then(|b| b.try_into().ok())
}

/// Shared helper for tests and P-04: which action is which byte.
#[allow(dead_code)]
pub(crate) fn action_byte(a: Action) -> u8 {
    u8::from(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::DEFAULT_CHUNK_SIZE;
    use crate::identity::Signer;
    use crate::opm::Opm;
    use origin_crypto_sdk::signing::wire::HybridSig;

    const SIGNER_SEED: [u8; 32] = [0x11u8; 32];
    const OTHER_SEED: [u8; 32] = [0x22u8; 32];
    const ATTESTOR_SEED: [u8; 32] = [0x33u8; 32];

    fn signer() -> Signer {
        Signer::from_seed(&SIGNER_SEED).unwrap()
    }

    fn enrolled_manifest(dir: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
        let file = dir.path().join("asset.bin");
        std::fs::write(&file, b"version one of the asset").unwrap();
        let s = signer();
        let mut opm = Opm::create(&file, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        opm.attest(&Signer::from_seed(&ATTESTOR_SEED).unwrap())
            .unwrap();
        let sidecar = crate::opm::sidecar_path(&file);
        opm::save(&opm, &sidecar).unwrap();
        (file, sidecar)
    }

    fn policy_now(now: i64) -> VerifyPolicy {
        VerifyPolicy {
            now: Some(now),
            required_k: None,
            allow_roster: None,
            journal_path: None,
        }
    }

    fn intact(outcome: &VerifyOutcome) -> bool {
        matches!(outcome, VerifyOutcome::Intact { .. })
    }

    // ---- construction helpers (tamper AFTER signing) ----

    /// Rebuild the manifest with a checkpoint timestamp `delta` seconds into
    /// the future, keeping the (now stale) signature — documents why the
    /// timestamp test instead moves the VERIFIER's clock (step 5 would fire
    /// first on a tampered ts; the untampered file + early clock isolates
    /// step 6).
    #[allow(dead_code)]
    fn future_date_checkpoint(opm: &Opm, delta: i64) -> Opm {
        let mut m = opm.clone();
        let last = m.checkpoints.last_mut().unwrap();
        last.timestamp += delta;
        m
    }

    fn flip_falcon_sig_byte(opm: &Opm) -> Opm {
        let mut m = opm.clone();
        let sig = crate::identity::Signer::hybrid_sig_from_base64(
            &m.checkpoints.last().unwrap().signature,
        )
        .unwrap();
        let mut wire = Vec::new();
        sig.encode(&mut wire).unwrap();
        let falcon_len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
        // Flip a byte inside the FALCON half only (Ed half stays intact).
        wire[4 + falcon_len / 2] ^= 0xff;
        let mut pos = 0usize;
        let tampered = HybridSig::decode(&wire, &mut pos).unwrap();
        m.checkpoints.last_mut().unwrap().signature =
            crate::identity::Signer::hybrid_sig_to_base64(&tampered).unwrap();
        m
    }

    fn tamper_chunk_n(file: &std::path::Path, opm: &Opm, n: usize) {
        let data = std::fs::read(file).unwrap();
        let cs = opm.chunk_size.max(1) as usize;
        assert!(n * cs < data.len(), "chunk {n} out of range");
        let mut tampered = data.clone();
        tampered[n * cs] ^= 0xff;
        std::fs::write(file, tampered).unwrap();
    }

    fn truncate_edits(opm: &Opm) -> Opm {
        let mut m = opm.clone();
        m.edits.truncate(m.edits.len() - 1);
        m
    }

    fn save_temp(opm: &Opm, dir: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
        let p = dir.path().join(name);
        opm::save(opm, &p).unwrap();
        p
    }

    // ---- the five honest-negative inputs (design gate 2), distinct wordings ----

    #[test]
    fn tampered_chunk_n_names_the_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let (file, _sidecar) = enrolled_manifest(&dir);
        // A second edit so the manifest has >1 chunk granularity.
        let opm = opm::load(&_sidecar).unwrap();
        tamper_chunk_n(&file, &opm, 0);

        let outcome = verify(&file, None, &policy_now(4_100_000_000));
        match &outcome {
            VerifyOutcome::Invalid(InvalidReason::ContentHash { chunk: Some(0) }) => {}
            other => panic!(
                "expected content-hash naming chunk 0, got {:?}",
                other.headline()
            ),
        }
        assert!(outcome
            .headline()
            .starts_with("manifest-invalid (content-hash"));
    }

    #[test]
    fn truncated_edit_list_is_history_failure() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let opm = opm::load(&sidecar).unwrap();
        let truncated = truncate_edits(&opm);
        let path = save_temp(&truncated, &dir, "trunc.opm");

        let outcome = verify(&file, Some(&path), &policy_now(4_100_000_000));
        // Truncation breaks the last checkpoint's replay (leaf_count >
        // remaining edits).
        assert_eq!(
            outcome.headline(),
            "manifest-invalid (history)",
            "got: {outcome:?}"
        );
    }

    #[test]
    fn flipped_falcon_byte_is_signer_signature_failure() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let opm = opm::load(&sidecar).unwrap();
        let tampered = flip_falcon_sig_byte(&opm);
        let path = save_temp(&tampered, &dir, "flip.opm");

        let outcome = verify(&file, Some(&path), &policy_now(4_100_000_000));
        assert_eq!(outcome.headline(), "manifest-invalid (signer-signature)");
    }

    #[test]
    fn future_dated_checkpoint_is_timestamp_failure() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let opm = opm::load(&sidecar).unwrap();
        // Untampered manifest, but the verifier's clock is set BEFORE the
        // last checkpoint was signed: step 6 catches a validly-signed
        // future-dated checkpoint (tampering the ts would instead fail
        // step 5's signature — a different reason).
        let now = opm.checkpoints.last().unwrap().timestamp - 60;
        let outcome = verify(&file, Some(&sidecar), &policy_now(now));
        assert_eq!(outcome.headline(), "manifest-invalid (timestamp)");
    }

    #[test]
    fn asset_without_sidecar_is_no_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let lonely = dir.path().join("nothing-here.bin");
        std::fs::write(&lonely, b"no sidecar for me").unwrap();
        let outcome = verify(&lonely, None, &policy_now(4_100_000_000));
        assert!(matches!(outcome, VerifyOutcome::NoManifest { .. }));
        assert!(outcome.headline().starts_with("no-manifest"));
        assert!(outcome.headline().contains(".opm"));
    }

    // ---- amendment H: history rewind ----

    #[test]
    fn shrunk_leaf_count_is_history_rewind_distinct_from_history() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let mut opm = opm::load(&sidecar).unwrap();
        // Second checkpoint (from append) then forge a SMALLER leaf_count on
        // the last checkpoint — a rewind attempt.
        std::fs::write(&file, b"version two of the asset").unwrap();
        let s = signer();
        opm.append_edit(&file, &s, Action::Edit, None).unwrap();
        let rewind = {
            let mut m = opm.clone();
            m.checkpoints.last_mut().unwrap().leaf_count = 1;
            m
        };
        let path = save_temp(&rewind, &dir, "rewind.opm");

        let outcome = verify(&file, Some(&path), &policy_now(4_100_000_000));
        assert_eq!(outcome.headline(), "manifest-invalid (history-rewind)");
        // Distinct from the generic history wording:
        assert_ne!(outcome.headline(), "manifest-invalid (history)");
    }

    // ---- step 3/4 details ----

    #[test]
    fn chunk_report_counts_and_partial_match() {
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big.bin");
        let cs = DEFAULT_CHUNK_SIZE as usize;
        let mut data = vec![0u8; cs * 3];
        data[0] = 1;
        std::fs::write(&big, &data).unwrap();
        let opm = Opm::create(&big, &signer(), Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        let sidecar = crate::opm::sidecar_path(&big);
        opm::save(&opm, &sidecar).unwrap();

        // Corrupt chunk 2 only (chunk 0 intact): report says 2/3, first
        // mismatch 2, and the verdict is fatal with the chunk named.
        data[cs * 2] ^= 0xff;
        std::fs::write(&big, &data).unwrap();
        let outcome = verify(&big, None, &policy_now(4_100_000_000));
        match &outcome {
            VerifyOutcome::Invalid(InvalidReason::ContentHash { chunk: Some(2) }) => {}
            other => panic!("expected chunk 2 mismatch, got {:?}", other.headline()),
        }
    }

    #[test]
    fn non_canonical_edit_order_rejected_not_reordered() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let mut opm = opm::load(&sidecar).unwrap();
        opm.edits[0].index = 5; // canonical order violated
        let path = save_temp(&opm, &dir, "nc.opm");
        let outcome = verify(&file, Some(&path), &policy_now(4_100_000_000));
        assert_eq!(outcome.headline(), "manifest-invalid (non-canonical)");
    }

    #[test]
    fn unparseable_manifest_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (file, _sidecar) = enrolled_manifest(&dir);
        let junk = dir.path().join("junk.opm");
        std::fs::write(&junk, b"not json at all {{{").unwrap();
        let outcome = verify(&file, Some(&junk), &policy_now(4_100_000_000));
        assert_eq!(outcome.headline(), "manifest-invalid (unparseable)");

        // Structurally valid JSON, wrong shape → also unparseable.
        let wrong = dir.path().join("wrong.opm");
        std::fs::write(&wrong, b"{\"hello\": 1}").unwrap();
        let outcome = verify(&file, Some(&wrong), &policy_now(4_100_000_000));
        assert_eq!(outcome.headline(), "manifest-invalid (unparseable)");
    }

    // ---- key binding (P-03 schema amendment) ----

    #[test]
    fn swapped_keys_rejected_as_key_binding() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let mut opm = opm::load(&sidecar).unwrap();
        // Embed DIFFERENT keys under the same fingerprint — the recompute
        // must catch the swap.
        let other = Signer::from_seed(&OTHER_SEED).unwrap();
        opm.checkpoints[0].keys = Some(other.public_keys());
        let path = save_temp(&opm, &dir, "swap.opm");
        let outcome = verify(&file, Some(&path), &policy_now(4_100_000_000));
        assert_eq!(outcome.headline(), "manifest-invalid (key-binding)");
    }

    #[test]
    fn roster_override_accepts_embedded_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let s = signer();
        let roster = vec![s.fingerprint_hex()];
        let policy = VerifyPolicy {
            now: Some(4_100_000_000),
            required_k: None,
            allow_roster: Some(roster),
            journal_path: None,
        };
        let outcome = verify(&file, Some(&sidecar), &policy);
        assert!(intact(&outcome), "got: {:?}", outcome.headline());

        // A peer NOT on the roster is rejected even with valid signatures.
        let policy = VerifyPolicy {
            now: Some(4_100_000_000),
            required_k: None,
            allow_roster: Some(vec!["deadbeef".repeat(8)]),
            journal_path: None,
        };
        let outcome = verify(&file, Some(&sidecar), &policy);
        assert_eq!(outcome.headline(), "manifest-invalid (key-binding)");
    }

    // ---- threshold matrix (design §3 step 8) ----

    #[test]
    fn attestation_binding_failure_is_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let mut opm = opm::load(&sidecar).unwrap();
        // Append AFTER attestation without voiding (bypassing the
        // constructor) — the verifier must catch the stale attestation.
        std::fs::write(&file, b"edited after attest").unwrap();
        let s = signer();
        opm.append_edit(&file, &s, Action::Edit, None).unwrap();
        // Manually restore the (now stale) attestation.
        let stale = crate::opm::Attestation {
            attestor_fingerprint: Signer::from_seed(&ATTESTOR_SEED).unwrap().fingerprint_hex(),
            signature: {
                let pre = opm::load(&sidecar).unwrap();
                pre.attestations[0].signature.clone()
            },
            keys: Some(Signer::from_seed(&ATTESTOR_SEED).unwrap().public_keys()),
        };
        opm.attestations = vec![stale];
        let path = save_temp(&opm, &dir, "stale.opm");

        let outcome = verify(&file, Some(&path), &policy_now(4_100_000_000));
        assert_eq!(outcome.headline(), "manifest-invalid (attestation-binding)");
    }

    #[test]
    fn threshold_shortfall_is_degraded_intact_with_both_k_shown() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        // 1 distinct attestor; authoritative K=3 ⇒ degraded-intact.
        let policy = VerifyPolicy {
            now: Some(4_100_000_000),
            required_k: Some(3),
            allow_roster: None,
            journal_path: None,
        };
        let outcome = verify(&file, Some(&sidecar), &policy);
        match &outcome {
            VerifyOutcome::Intact {
                unattested: Some((have, need)),
                ..
            } => {
                assert_eq!((*have, *need), (1, 3));
            }
            other => panic!("expected degraded-intact, got {:?}", other.headline()),
        }
        assert!(intact(&outcome), "degraded-intact is still Intact");
    }

    #[test]
    fn self_attestation_flagged_not_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("self.bin");
        std::fs::write(&file, b"self attested").unwrap();
        let s = signer();
        let mut opm = Opm::create(&file, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        opm.attest(&s).unwrap(); // signer attests own manifest (format-legal)
        let sidecar = crate::opm::sidecar_path(&file);
        opm::save(&opm, &sidecar).unwrap();

        let outcome = verify(&file, Some(&sidecar), &policy_now(4_100_000_000));
        match &outcome {
            VerifyOutcome::Intact {
                self_attestation_flag,
                ..
            } => assert!(*self_attestation_flag, "signer∈attestors must be flagged"),
            other => panic!("expected intact, got {:?}", other.headline()),
        }
    }

    #[test]
    fn swap_gate_second_signer_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("other.bin");
        std::fs::write(&file, b"other signer's asset").unwrap();
        let s2 = Signer::from_seed(&OTHER_SEED).unwrap();
        let opm = Opm::create(&file, &s2, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        let sidecar = crate::opm::sidecar_path(&file);
        opm::save(&opm, &sidecar).unwrap();

        let outcome = verify(&file, Some(&sidecar), &policy_now(4_100_000_000));
        assert!(
            intact(&outcome),
            "no signer hardcoding; got {:?}",
            outcome.headline()
        );
    }

    // ---- output contract ----

    #[test]
    fn intact_output_is_time_qualified_with_footer() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let expected_ts = opm::load(&sidecar)
            .unwrap()
            .checkpoints
            .last()
            .unwrap()
            .timestamp;

        let outcome = verify(&file, Some(&sidecar), &policy_now(4_100_000_000));
        assert_eq!(
            outcome.headline(),
            format!("manifest-intact as of {expected_ts}")
        );
        let footer = outcome.footer();
        assert!(!footer.contains("what was not") && footer.contains("not checked"));
        assert!(footer.contains("metadata"));
        assert!(footer.contains("TSA"));
    }

    #[test]
    fn p02_manifests_still_load_and_verify() {
        // Wire backward-compat: chunk_hashes/keys are optional.
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&sidecar).unwrap()).unwrap();
        // Strip the P-03 fields, as a P-02-era writer would.
        for e in v["edits"].as_array_mut().unwrap().iter_mut() {
            e.as_object_mut().unwrap().remove("chunk_hashes");
        }
        v["checkpoints"][0].as_object_mut().unwrap().remove("keys");
        v["attestations"][0].as_object_mut().unwrap().remove("keys");
        let old = dir.path().join("p02era.opm");
        std::fs::write(&old, serde_json::to_string(&v).unwrap()).unwrap();

        // Structure + history still verify; signature step reports
        // key-binding because NO key source exists without embedded keys
        // and no roster is configured — the honest refusal, not a crash.
        let outcome = verify(&file, Some(&old), &policy_now(4_100_000_000));
        assert_eq!(outcome.headline(), "manifest-invalid (key-binding)");
    }

    #[test]
    fn keys_for_roster_precedence_and_recompute() {
        let s = signer();
        let keys = s.public_keys();
        let fp = s.fingerprint_hex();

        // Consistent embedded keys pass with no roster.
        assert!(keys_for(&fp, Some(&keys), None).is_ok());

        // Wrong fingerprint for the keys fails.
        assert_eq!(
            keys_for(&"a".repeat(64), Some(&keys), None).unwrap_err(),
            InvalidReason::KeyBinding
        );

        // Roster containing the fingerprint passes.
        let roster = vec![fp.clone()];
        assert!(keys_for(&fp, Some(&keys), Some(&roster)).is_ok());

        // Roster without it fails even with valid embedded keys.
        let roster = vec!["b".repeat(64)];
        assert_eq!(
            keys_for(&fp, Some(&keys), Some(&roster)).unwrap_err(),
            InvalidReason::KeyBinding
        );
    }
}
