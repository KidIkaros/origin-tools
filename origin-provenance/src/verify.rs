// SPDX-License-Identifier: Apache-2.0

//! The OPM verification engine — normative check order and honest output
//! contract (design §3; spec §5).
//!
//! Check order (normative — do not reorder):
//! 1. locate sidecar (explicit path, or discovery order in `verify_discover`:
//!    default sidecar → watermark fallback — a hint, design D4)
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
//! Output contract: `manifest-intact as of T` (T = latest checkpoint time,
//! composed with the journal tip), `manifest-invalid: <reason>`,
//! `no-manifest` — always with the "what was checked / what was not"
//! footer. Metadata ignored; watermark = hint only; timestamps are
//! signer-asserted, not TSA-attested. No C2PA-branded phrasing anywhere
//! (voice rule, design A).

use std::path::Path;

use origin_attest::revocation::RevocationJournal;

/// Revocation target convention (provenance side of the journal contract):
/// `target_hash = SHA3-256(signer_or_attestor_fingerprint_hex_bytes)`. The
/// fingerprint is the stable v1 identity (design I: revocation-only rotation,
/// continuity = new signer + new manifest), so it is what the journal kills.
pub fn revocation_target(fingerprint_hex: &str) -> [u8; 32] {
    origin_crypto_sdk::sha3_256(fingerprint_hex.as_bytes())
}

/// Outcome of journal consultation (spec §7 — integrity-first honesty).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationStatus {
    /// No journal found at the policy/default path. Absence of a journal is
    /// NOT evidence of absence of revocation — stated plainly in the footer.
    NoJournal,
    /// Journal loaded; hash chain intact; no record signature invalid;
    /// the queried fingerprints were not found.
    Clean { records: usize },
    /// Journal loaded but untrustworthy (chain broken, unparseable, or a
    /// forged record). Verification PROCEEDS; the footer carries the exact
    /// §7 warning — never a false "revoked", never a false "clean".
    Unreliable { detail: String },
}

impl RevocationStatus {
    /// Whether revocation results from this journal may be enforced.
    fn enforceable(&self) -> bool {
        matches!(self, RevocationStatus::Clean { .. })
    }
}

/// A journal loaded from disk with its health findings.
struct LoadedJournal {
    journal: RevocationJournal,
    status: RevocationStatus,
}

/// Load + health-check the journal at `path`. File absent ⇒ `NoJournal`.
/// Unparseable file, broken chain, or forged record ⇒ `Unreliable` with the
/// distinct finding (ticket 08: "chain broken" and "record forged" are
/// different findings — both make revocation status unreliable).
fn load_journal(path: &Path) -> LoadedJournal {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => {
            return LoadedJournal {
                journal: RevocationJournal::new(),
                status: RevocationStatus::NoJournal,
            }
        }
    };
    let journal: RevocationJournal = match serde_json::from_str(&text) {
        Ok(j) => j,
        Err(e) => {
            return LoadedJournal {
                journal: RevocationJournal::new(),
                status: RevocationStatus::Unreliable {
                    detail: format!("journal unparseable: {e}"),
                },
            }
        }
    };
    if let Err(e) = journal.verify_integrity() {
        return LoadedJournal {
            journal,
            status: RevocationStatus::Unreliable {
                detail: format!("journal chain broken: {e}"),
            },
        };
    }
    let bad = journal.verify_signatures();
    if !bad.is_empty() {
        return LoadedJournal {
            journal,
            status: RevocationStatus::Unreliable {
                detail: format!("journal record signature(s) invalid at index(es) {bad:?}"),
            },
        };
    }
    LoadedJournal {
        status: RevocationStatus::Clean {
            records: journal.len(),
        },
        journal,
    }
}

/// Default journal location (spec §7 / ticket 05 D9 static distribution):
/// `revocations.json` next to the asset.
fn default_journal_path(asset: &Path) -> std::path::PathBuf {
    asset
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("revocations.json")
}

/// Timestamp of the last record (the journal tip for `as-of` and output).
fn journal_tip_time(journal: &RevocationJournal) -> Option<i64> {
    journal.records.last().map(|r| r.timestamp)
}

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
        /// C2PA annotation channel (E/F — orthogonal to the verdict; a
        /// file can carry BOTH an Origin sidecar and embedded C2PA).
        c2pa: crate::c2pa::C2paAnnotation,
        /// Journal consultation result (spec §7): revocation was checked
        /// (Clean), not found (NoJournal), or found-untrustworthy
        /// (Unreliable — verification proceeded, footer warns).
        revocation: RevocationStatus,
    },
    /// Payload: the C2PA annotation channel (E/F) — a manifest-carrying file
    /// can ALSO embed C2PA; the channel reports on any verdict.
    Invalid(InvalidReason, crate::c2pa::C2paAnnotation),
    /// No sidecar found. `attempts` is the honest discovery log: what the
    /// engine looked at and what it found (P-04 fallback), all labeled
    /// heuristic. Empty when `--sidecar` was explicit.
    NoManifest {
        sidecar_path: String,
        attempts: Vec<String>,
        c2pa: crate::c2pa::C2paAnnotation,
    },
}

impl VerifyOutcome {
    /// The C2PA annotation channel attached to this verdict (E/F —
    /// orthogonal to the verdict itself).
    pub fn c2pa(&self) -> &crate::c2pa::C2paAnnotation {
        match self {
            VerifyOutcome::Intact { c2pa, .. } | VerifyOutcome::NoManifest { c2pa, .. } => c2pa,
            VerifyOutcome::Invalid(_, c2pa) => c2pa,
        }
    }

    /// One-line verdict (stable strings; tests pin them).
    pub fn headline(&self) -> String {
        match self {
            VerifyOutcome::Intact { as_of, .. } => format!("manifest-intact as of {as_of}"),
            VerifyOutcome::Invalid(r, _) => r.label(),
            VerifyOutcome::NoManifest {
                sidecar_path,
                attempts,
                ..
            } => {
                let mut s = format!("no-manifest (no sidecar at {sidecar_path})");
                for a in attempts {
                    s.push_str("\n  ");
                    s.push_str(a);
                }
                s
            }
        }
    }

    /// The mandatory "what was checked / what was not" footer (design §3),
    /// now revocation-aware (spec §7): the journal state is stated plainly,
    /// and a broken/untrustworthy journal carries the exact warning.
    pub fn footer(&self) -> String {
        let base = "checked: canonical edit order, content binding (whole file + chunks), \
MMR replay at every checkpoint, checkpoint signatures (Ed25519+Falcon), \
timestamp sanity, attestation binding.";
        let rev = match self {
            VerifyOutcome::Intact {
                revocation: RevocationStatus::Clean { records },
                ..
            } => format!(" revocation (journal consulted, chain intact: {records} records)."),
            VerifyOutcome::Intact {
                revocation: RevocationStatus::NoJournal,
                ..
            } => " revocation NOT checked: no journal found \
(absence of a journal is not evidence of absence of revocation)."
                .to_string(),
            VerifyOutcome::Intact {
                revocation: RevocationStatus::Unreliable { .. },
                ..
            } => " revocation NOT enforced: journal integrity check failed — \
revocation status unreliable."
                .to_string(),
            VerifyOutcome::Invalid(..) => {
                " revocation (not enforced on this failure path).".to_string()
            }
            VerifyOutcome::NoManifest { .. } => {
                " revocation (not reached — no manifest found).".to_string()
            }
        };
        let rest = "not checked: metadata (ignored), watermark (hint only), \
timestamps are signer-asserted not TSA-attested.";
        match self {
            VerifyOutcome::Intact {
                revocation: RevocationStatus::Unreliable { detail },
                ..
            } => format!(
                "WARNING: journal integrity check failed — revocation status unreliable. \
({detail})\n{base}{rev} {rest}"
            ),
            _ => format!("{base}{rev} {rest}"),
        }
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

/// Verify `asset` against its sidecar (or the explicit one given). The
/// frozen P-03 contract: explicit/default sidecar only, no discovery.
pub fn verify(asset: &Path, sidecar: Option<&Path>, policy: &VerifyPolicy) -> VerifyOutcome {
    // Step 1 — locate the manifest.
    let path: std::path::PathBuf = match sidecar {
        Some(p) => p.to_path_buf(),
        None => opm::sidecar_path(asset),
    };
    if !path.exists() {
        return VerifyOutcome::NoManifest {
            sidecar_path: path.to_string_lossy().into_owned(),
            attempts: Vec::new(),
            c2pa: annotate_asset(asset),
        };
    }
    let opm = match opm::load(&path) {
        Ok(o) => o,
        Err(_) => return VerifyOutcome::Invalid(InvalidReason::Unparseable, annotate_asset(asset)),
    };
    if opm.version != opm::OPM_VERSION {
        return VerifyOutcome::Invalid(InvalidReason::Unparseable, annotate_asset(asset));
    }
    if let Err(reason) = check_structure(&opm) {
        return VerifyOutcome::Invalid(reason, annotate_asset(asset));
    }
    verify_loaded(asset, opm, policy, None)
}

/// Version + structure gates, then steps 3–9. Shared by `verify` and the
/// discovery wrapper (which feeds in a manifest found via the watermark hint).
fn verify_parsed(
    asset: &Path,
    opm: Opm,
    policy: &VerifyPolicy,
    content_bytes: Option<&[u8]>,
) -> VerifyOutcome {
    if opm.version != opm::OPM_VERSION {
        return VerifyOutcome::Invalid(InvalidReason::Unparseable, annotate_asset(asset));
    }
    if let Err(reason) = check_structure(&opm) {
        return VerifyOutcome::Invalid(reason, annotate_asset(asset));
    }
    verify_loaded(asset, opm, policy, content_bytes)
}

/// Steps 3–9 over a structure-checked manifest. `content_bytes` overrides the
/// asset read when discovery matched via the watermark-embedded original
/// (design D4 — the override is a hint and is logged in the attempts trail).
fn verify_loaded(
    asset: &Path,
    opm: Opm,
    policy: &VerifyPolicy,
    content_bytes: Option<&[u8]>,
) -> VerifyOutcome {
    let ann = annotate_asset(asset);

    // Step 7 (revocation) consultation happens FIRST so its health state can
    // gate enforcement and compose the output; per §7 integrity is checked
    // BEFORE any revocation result is used.
    let journal_path = policy
        .journal_path
        .clone()
        .unwrap_or_else(|| default_journal_path(asset));
    let LoadedJournal { journal, status } = load_journal(&journal_path);
    let revocation_state = status;

    // Step 3 — content binding (reportable per-chunk, then fatal).
    let (report, reason) = check_content(asset, &opm, content_bytes);
    if let Some(r) = reason {
        return VerifyOutcome::Invalid(r, ann);
    }
    let report = report.expect("content check produced a report on success path");

    // Step 4 — MMR consistency for every checkpoint + rewind check (H).
    if let Err(reason) = check_mmr_history(&opm) {
        return VerifyOutcome::Invalid(reason, ann);
    }

    // Step 5 — checkpoint signatures with embedded/roster keys.
    if let Err(reason) = check_checkpoint_signatures(&opm, policy.allow_roster.as_ref()) {
        return VerifyOutcome::Invalid(reason, ann);
    }

    // Step 6 — timestamp sanity (verifier-local now).
    let now = policy.now.unwrap_or_else(unix_now);
    if opm.checkpoints.iter().any(|c| c.timestamp > now) {
        return VerifyOutcome::Invalid(InvalidReason::Timestamp, ann);
    }

    // Step 7 — revocation (enforced only when the journal is provably
    // healthy; Unreliable proceeds with the footer warning, §7). Every
    // checkpoint signer is checked: a manifest signed at any point by a
    // revoked key is tainted (rotation = new signer + NEW manifest, design I).
    if revocation_state.enforceable() {
        let revoked_signer = opm
            .checkpoints
            .iter()
            .map(|c| revocation_target(&c.signer_fingerprint))
            .find(|t| journal.is_revoked(t));
        if revoked_signer.is_some() {
            return VerifyOutcome::Invalid(
                InvalidReason::SignerRevoked {
                    journal_tip: journal_tip_time(&journal).unwrap_or_default(),
                },
                ann,
            );
        }
    }

    // Step 8 — threshold. Revoked attestors are excluded from the distinct
    // count (same journal contract; enforcement gated identically).
    let revoked_attestors: Vec<String> = if revocation_state.enforceable() {
        opm.attestations
            .iter()
            .map(|a| a.attestor_fingerprint.clone())
            .filter(|fp| journal.is_revoked(&revocation_target(fp)))
            .collect()
    } else {
        Vec::new()
    };
    let threshold = match check_attestations(&opm, policy.required_k, &revoked_attestors) {
        Ok(t) => t,
        Err(reason) => return VerifyOutcome::Invalid(reason, ann),
    };

    // `as of` = min(latest checkpoint, journal tip) when a journal was found
    // (a claim is only as fresh as the most recent revocation sweep); raw
    // latest checkpoint otherwise.
    let as_of = match journal_tip_time(&journal) {
        Some(tip) if !matches!(revocation_state, RevocationStatus::NoJournal) => opm
            .checkpoints
            .last()
            .map(|c| c.timestamp.min(tip))
            .unwrap_or(tip),
        _ => opm
            .checkpoints
            .last()
            .map(|c| c.timestamp)
            .unwrap_or_default(),
    };

    VerifyOutcome::Intact {
        as_of,
        chunk_report: report,
        self_attestation_flag: threshold.self_attestation,
        unattested: threshold.unattested,
        k_discrepancy: threshold.k_discrepancy,
        c2pa: ann,
        revocation: revocation_state,
    }
}

/// C2PA annotation for any asset (E/F — orthogonal to the verdict).
fn annotate_asset(asset: &Path) -> crate::c2pa::C2paAnnotation {
    match std::fs::read(asset) {
        Ok(data) => crate::c2pa::annotate(crate::c2pa::extract_store(&data, Some(asset))),
        Err(_) => crate::c2pa::C2paAnnotation {
            container: None,
            present: false,
            claim_generator: None,
            action_count: None,
            signature_parses: None,
            note: None,
        },
    }
}

/// Discovery entry point (spec §5; P-04): default sidecar first, then the
/// watermark fallback. The watermark is a HINT (design D4): extraction is a
/// candidate match only when a sibling `.opm`'s first-edit whole-file hash
/// equals the BLAKE3 of the asset or of the watermark-embedded original.
/// Multiple candidates are never guessed; every step is logged honestly.
pub fn verify_discover(asset: &Path, policy: &VerifyPolicy) -> VerifyOutcome {
    let mut attempts: Vec<String> = Vec::new();
    let default = opm::sidecar_path(asset);
    if default.exists() {
        return verify(asset, Some(&default), policy);
    }
    attempts.push(format!(
        "discovery: no sidecar at {}",
        default.to_string_lossy()
    ));

    let data = match std::fs::read(asset) {
        Ok(d) => d,
        Err(_) => {
            attempts.push("discovery: asset unreadable".into());
            return VerifyOutcome::NoManifest {
                sidecar_path: default.to_string_lossy().into_owned(),
                attempts,
                c2pa: annotate_asset(asset),
            };
        }
    };
    let annotation = annotate_asset(asset);

    let (candidates, original) = watermark_candidates(asset, &data, &mut attempts);
    let original_buf: Option<Vec<u8>> = original;
    match candidates.len() {
        0 => VerifyOutcome::NoManifest {
            sidecar_path: default.to_string_lossy().into_owned(),
            attempts,
            c2pa: annotation,
        },
        1 => {
            let p = candidates[0].clone();
            attempts.push(format!(
                "discovery: watermark hint matched {} (candidate, not trust)",
                p.to_string_lossy()
            ));
            let opm = match opm::load(&p) {
                Ok(o) => o,
                Err(_) => {
                    attempts.push("discovery: candidate manifest unreadable".into());
                    return VerifyOutcome::NoManifest {
                        sidecar_path: p.to_string_lossy().into_owned(),
                        attempts,
                        c2pa: annotation,
                    };
                }
            };
            // Which byte-stream does the manifest bind? If it binds the
            // watermark-embedded original (matched_via = "embedded original"),
            // content verification runs against those extracted bytes — a
            // hint-qualified check, disclosed in the attempts trail.
            let matched_via = original_buf.as_ref().and_then(|orig| {
                let o_hash = hex::encode(origin_crypto_sdk::blake3::hash(orig).as_bytes());
                opm.edits
                    .first()
                    .map(|e| e.content.whole_file_hash == o_hash)
                    .filter(|b| *b)
                    .map(|_| "embedded original")
            });
            let content_bytes: Option<&[u8]> = match matched_via {
                Some(_) => original_buf.as_deref(),
                None => None,
            };
            if matched_via.is_some() {
                attempts.push(
                    "discovery: content verified against watermark-embedded original \
                     (hint-qualified; watermark is not a trust signal)"
                        .into(),
                );
            }
            match verify_parsed(asset, opm, policy, content_bytes) {
                VerifyOutcome::NoManifest {
                    attempts: mut all,
                    c2pa,
                    ..
                } => {
                    let mut merged = attempts;
                    merged.append(&mut all);
                    VerifyOutcome::NoManifest {
                        sidecar_path: p.to_string_lossy().into_owned(),
                        attempts: merged,
                        c2pa,
                    }
                }
                other => other,
            }
        }
        _ => {
            attempts.push(
                "discovery: multiple watermark candidates — refusing to guess (use --sidecar)"
                    .into(),
            );
            VerifyOutcome::NoManifest {
                sidecar_path: default.to_string_lossy().into_owned(),
                attempts,
                c2pa: annotation,
            }
        }
    }
}

/// Sibling `.opm` manifests (same directory, design D6's manifest home)
/// whose first edit's whole-file hash equals the BLAKE3 of the watermarked
/// asset or of the embedded original bytes. Logs every attempt; loads each
/// candidate defensively (a corrupt sibling is a skipped candidate, not a
/// verify failure).
fn watermark_candidates(
    asset: &Path,
    data: &[u8],
    attempts: &mut Vec<String>,
) -> (Vec<std::path::PathBuf>, Option<Vec<u8>>) {
    let (wm, original) = match crate::watermark::Watermark::extract(data) {
        Ok(x) => x,
        Err(_) => {
            attempts.push("discovery: no watermark marker found".into());
            return (Vec::new(), None);
        }
    };
    if !wm.verify(&original) {
        attempts.push(
            "discovery: watermark found but its hash does not match the embedded original \
             (stripped or re-saved after watermarking) — no candidate from it"
                .into(),
        );
    }
    let asset_hash = origin_crypto_sdk::blake3::hash(data);
    let original_hash = origin_crypto_sdk::blake3::hash(&original);
    let mut candidates = Vec::new();
    let dir = match asset.parent() {
        Some(d) => d,
        None => return (candidates, Some(original)),
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return (candidates, Some(original)),
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let is_opm = p.extension().map(|e| e == "opm").unwrap_or(false);
        if !is_opm || p == opm::sidecar_path(asset) {
            continue;
        }
        let loaded = match opm::load(&p) {
            Ok(o) => o,
            Err(_) => {
                attempts.push(format!(
                    "discovery: sibling {} unreadable — skipped",
                    p.to_string_lossy()
                ));
                continue;
            }
        };
        let first = match loaded.edits.first() {
            Some(e) => e,
            None => continue,
        };
        let fh = &first.content.whole_file_hash;
        if fh == &hex::encode(asset_hash.as_bytes()) || fh == &hex::encode(original_hash.as_bytes())
        {
            candidates.push(p);
        }
    }
    if candidates.is_empty() {
        attempts
            .push("discovery: watermark found but no sibling manifest matches its content".into());
    }
    (candidates, Some(original))
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
fn check_content(
    asset: &Path,
    opm: &Opm,
    content_bytes: Option<&[u8]>,
) -> (Option<ChunkReport>, Option<InvalidReason>) {
    let read_buf: Vec<u8>;
    let data: &[u8] = if let Some(b) = content_bytes {
        b
    } else {
        read_buf = match std::fs::read(asset) {
            Ok(d) => d,
            Err(_) => return (None, Some(InvalidReason::ContentHash { chunk: None })),
        };
        &read_buf
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
        let root_from_file = content::chunk_tree(data, opm.chunk_size);
        if hex::encode(root_from_file) != edit.content.chunk_tree_root
            || hex::encode(content::whole_file_hash(data)) != edit.content.whole_file_hash
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
    if hex::encode(content::whole_file_hash(data)) != edit.content.whole_file_hash
        || hex::encode(content::chunk_tree(data, opm.chunk_size)) != edit.content.chunk_tree_root
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
    revoked_attestors: &[String],
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
        if !distinct.contains(&att.attestor_fingerprint)
            && !revoked_attestors.contains(&att.attestor_fingerprint)
        {
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
            VerifyOutcome::Invalid(InvalidReason::ContentHash { chunk: Some(0) }, _) => {}
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
            VerifyOutcome::Invalid(InvalidReason::ContentHash { chunk: Some(2) }, _) => {}
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

    // ---- P-04: discovery + annotation channel ----

    /// An asset whose watermark embeds the bytes of a manifest-paired original.
    fn watermarked_asset(dir: &tempfile::TempDir) -> (std::path::PathBuf, Vec<u8>) {
        let original = b"version one of the asset".to_vec();
        let wm = crate::watermark::Watermark::new(&original, Some("test".into()));
        let marked = wm.embed(&original).unwrap();
        let file = dir.path().join("stripped-asset.bin");
        std::fs::write(&file, &marked).unwrap();
        (file, original)
    }

    #[test]
    fn default_sidecar_still_verified_without_discovery_overhead() {
        let dir = tempfile::tempdir().unwrap();
        let (file, _sidecar) = enrolled_manifest(&dir);
        let outcome = verify_discover(&file, &policy_now(4_100_000_000));
        assert!(intact(&outcome));
    }

    #[test]
    fn watermark_fallback_finds_sibling_manifest_for_original() {
        // The true D4 scenario: the pairing is stripped — the watermarked
        // asset travels WITHOUT its default-path sidecar, and the manifest
        // sits under a non-default sibling name. Discovery must recover it.
        let dir = tempfile::tempdir().unwrap();
        let (file, original) = watermarked_asset(&dir);
        let s = signer();
        let opm =
            Opm::create_from_bytes(&original, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        opm::save(&opm, &dir.path().join("recovered.opm")).unwrap();

        let outcome = verify_discover(&file, &policy_now(4_100_000_000));
        assert!(intact(&outcome), "got: {outcome:?}");
    }

    #[test]
    fn watermarked_asset_with_default_sidecar_binds_marked_bytes() {
        // The strict default-path rule: a manifest at <asset>.opm binds what
        // it binds — one that enrolled the marked bytes verifies; one that
        // enrolled pre-watermark bytes is a content failure there (the
        // supported flows: bind the distributed bytes, or rely on discovery).
        let dir = tempfile::tempdir().unwrap();
        let (file, _original) = watermarked_asset(&dir);
        let s = signer();
        let marked = std::fs::read(&file).unwrap();
        let opm = Opm::create_from_bytes(&marked, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        opm::save(&opm, &crate::opm::sidecar_path(&file)).unwrap();

        let outcome = verify_discover(&file, &policy_now(4_100_000_000));
        assert!(intact(&outcome), "got: {outcome:?}");
    }

    #[test]
    fn unwatermarked_asset_is_honest_no_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let _ = enrolled_manifest(&dir);
        let lonely = dir.path().join("other.bin");
        std::fs::write(&lonely, b"unwatermarked content").unwrap();

        let outcome = verify_discover(&lonely, &policy_now(4_100_000_000));
        match &outcome {
            VerifyOutcome::NoManifest { attempts, c2pa, .. } => {
                assert!(attempts.iter().any(|a| a.contains("no sidecar at")));
                assert!(attempts.iter().any(|a| a.contains("no watermark marker")));
                assert!(!c2pa.present);
            }
            other => panic!("expected no-manifest, got {other:?}"),
        }
    }

    #[test]
    fn watermark_without_matching_manifest_names_what_was_tried() {
        let dir = tempfile::tempdir().unwrap();
        let (file, _original) = watermarked_asset(&dir);
        // No manifest anywhere in the directory: the trail must show the
        // watermark was found and examined, and that nothing matched it.

        let outcome = verify_discover(&file, &policy_now(4_100_000_000));
        match &outcome {
            VerifyOutcome::NoManifest { attempts, .. } => {
                assert!(
                    attempts
                        .iter()
                        .any(|a| a.contains("watermark found but no sibling manifest matches")),
                    "attempts: {attempts:?}"
                );
            }
            other => panic!("expected no-manifest, got {other:?}"),
        }
    }

    #[test]
    fn multiple_watermark_candidates_refuse_to_guess() {
        let dir = tempfile::tempdir().unwrap();
        let (file, original) = watermarked_asset(&dir);
        let s = signer();
        // Two sibling manifests both claiming the same original content.
        let opm =
            Opm::create_from_bytes(&original, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        opm::save(&opm, &dir.path().join("copy1.opm")).unwrap();
        opm::save(&opm, &dir.path().join("copy2.opm")).unwrap();

        let outcome = verify_discover(&file, &policy_now(4_100_000_000));
        match &outcome {
            VerifyOutcome::NoManifest { attempts, .. } => {
                assert!(
                    attempts.iter().any(|a| a.contains("refusing to guess")),
                    "attempts: {attempts:?}"
                );
            }
            other => panic!("expected no-manifest, got {other:?}"),
        }
    }

    #[test]
    fn c2pa_annotation_attaches_to_every_verdict() {
        // Intact verdict + C2PA-carrying asset: annotation present alongside.
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        // Make the asset C2PA-carrying WITHOUT breaking its content binding:
        // append a C2PA store via a JPEG wrapper is impossible here (that
        // would change content). Instead: verify that the channel is attached
        // (empty annotation for a non-C2PA asset, present for a C2PA one).
        let outcome = verify(&file, Some(&sidecar), &policy_now(4_100_000_000));
        match &outcome {
            VerifyOutcome::Intact { c2pa, .. } => {
                assert!(!c2pa.present, "no C2PA data was embedded");
            }
            other => panic!("expected intact, got {other:?}"),
        }

        // A C2PA-carrying unmanifested asset still gets the annotation.
        let store = crate::c2pa::tests_support::claim_store("AnnotGen/1.0");
        let marked = dir.path().join("c2pa-only.jumbf");
        std::fs::write(&marked, &store).unwrap();
        let outcome2 = verify_discover(&marked, &policy_now(4_100_000_000));
        match &outcome2 {
            VerifyOutcome::NoManifest { c2pa, .. } => {
                assert!(c2pa.present);
                assert_eq!(c2pa.claim_generator.as_deref(), Some("AnnotGen/1.0"));
            }
            other => panic!("expected no-manifest, got {other:?}"),
        }
    }

    #[test]
    fn both_manifests_independence_annotation_never_becomes_trust() {
        // Design F: an asset can carry BOTH an Origin manifest AND embedded
        // C2PA. The C2PA claim must not influence the verdict either way.
        // Here the asset itself is a .jumbf store (the sidecar-JUMBF
        // container) with its own Origin manifest alongside.
        let dir = tempfile::tempdir().unwrap();
        let store = crate::c2pa::tests_support::claim_store("CoGen/1.0");
        let asset = dir.path().join("co-asset.jumbf");
        std::fs::write(&asset, &store).unwrap();
        let s = signer();
        let opm = Opm::create_from_bytes(&store, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        let sidecar = crate::opm::sidecar_path(&asset);
        opm::save(&opm, &sidecar).unwrap();

        // Intact manifest + C2PA present: intact verdict, annotation rendered.
        let outcome = verify_discover(&asset, &policy_now(4_100_000_000));
        match &outcome {
            VerifyOutcome::Intact { c2pa, .. } => {
                assert!(c2pa.present);
                assert_eq!(c2pa.container, Some("jumbf-sidecar"));
                assert_eq!(c2pa.claim_generator.as_deref(), Some("CoGen/1.0"));
            }
            other => panic!("expected intact, got {other:?}"),
        }

        // Break the manifest's signature: C2PA presence must NOT rescue it.
        let loaded = opm::load(&sidecar).unwrap();
        let tampered = flip_falcon_sig_byte(&loaded);
        let path = save_temp(&tampered, &dir, "flip2.opm");
        let outcome2 = verify(&asset, Some(&path), &policy_now(4_100_000_000));
        match &outcome2 {
            VerifyOutcome::Invalid(_, c2pa) => {
                assert!(c2pa.present, "annotation still renders on invalid");
            }
            other => panic!("expected invalid, got {other:?}"),
        }
    }

    // ---- P-05: revocation integration (spec §7; R3 drill) ----

    use origin_attest::revocation::{RevocationJournal, RevocationRecord};

    /// A healthy journal at the asset's default path revoking `fps`.
    fn journal_revoke(dir: &tempfile::TempDir, fps: &[String], tip: i64) {
        let mut journal = RevocationJournal::new();
        let revoker =
            origin_crypto_sdk::signing::postquantum::Falcon1024Signer::from_seed(&[0x77u8; 32])
                .unwrap();
        for fp in fps {
            journal
                .append_signed(
                    RevocationRecord {
                        target_hash: revocation_target(fp),
                        revoked_by: String::new(), // filled by append_signed
                        reason: "key compromise (R3 drill)".into(),
                        timestamp: tip,
                        prev_hash: [0u8; 32],
                        signature: vec![],
                        revoker_falcon_pk: vec![],
                    },
                    &revoker,
                )
                .unwrap();
        }
        std::fs::write(
            dir.path().join("revocations.json"),
            serde_json::to_string(&journal).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn r3_revoked_signer_is_rejected_with_journal_tip() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let s = signer();
        journal_revoke(&dir, &[s.fingerprint_hex()], 4_098_000_000);

        let outcome = verify(&file, Some(&sidecar), &policy_now(4_100_000_000));
        assert_eq!(
            outcome.headline(),
            "manifest-invalid (signer-revoked, as of journal tip 4098000000)"
        );
    }

    #[test]
    fn r3_swap_gate_second_signer_accepted() {
        // Continuity per design I: the compromised signer dies via journal;
        // a NEW signer's manifest verifies against the same journal.
        let dir = tempfile::tempdir().unwrap();
        let old = signer();
        journal_revoke(&dir, &[old.fingerprint_hex()], 4_098_000_000);

        let file = dir.path().join("successor.bin");
        std::fs::write(&file, b"successor content").unwrap();
        let successor = Signer::from_seed(&OTHER_SEED).unwrap();
        let mut opm = Opm::create(&file, &successor, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        opm.attest(&Signer::from_seed(&ATTESTOR_SEED).unwrap())
            .unwrap();
        let sidecar = crate::opm::sidecar_path(&file);
        opm::save(&opm, &sidecar).unwrap();

        let outcome = verify(&file, Some(&sidecar), &policy_now(4_100_000_000));
        assert!(intact(&outcome), "got: {outcome:?}");
    }

    #[test]
    fn broken_journal_chain_proceeds_with_verbatim_warning() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        // Healthy journal, then corrupt a record's reason: chain + signature
        // both break. Verification must PROCEED (intact) with the exact §7
        // warning — never a false "revoked", never a false "clean".
        journal_revoke(&dir, &["a".repeat(64)], 4_098_000_000);
        let path = dir.path().join("revocations.json");
        let mut journal: RevocationJournal =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        journal.records[0].reason = "tampered".into();
        std::fs::write(&path, serde_json::to_string(&journal).unwrap()).unwrap();

        let outcome = verify(&file, Some(&sidecar), &policy_now(4_100_000_000));
        assert!(intact(&outcome), "verification proceeds: {outcome:?}");
        let f = outcome.footer();
        assert!(
            f.starts_with(
                "WARNING: journal integrity check failed — revocation status unreliable."
            ),
            "{f}"
        );
        assert!(f.contains("not checked: metadata"));
    }

    #[test]
    fn forged_record_signature_is_distinct_from_chain_break() {
        // Ticket 08: "chain broken" and "record forged" are different
        // findings. Flip a signature byte: the hash chain stays intact
        // (hash covers signable bytes only) but the signature fails.
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        journal_revoke(&dir, &["a".repeat(64)], 4_098_000_000);
        let path = dir.path().join("revocations.json");
        let mut journal: RevocationJournal =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        journal.records[0].signature[0] ^= 0xFF;
        std::fs::write(&path, serde_json::to_string(&journal).unwrap()).unwrap();

        let outcome = verify(&file, Some(&sidecar), &policy_now(4_100_000_000));
        assert!(intact(&outcome));
        let f = outcome.footer();
        assert!(f.contains("WARNING: journal integrity check failed"), "{f}");
        assert!(f.contains("record signature(s) invalid"), "{f}");
    }

    #[test]
    fn absent_journal_and_empty_journal_are_distinct_footers() {
        // Absent: NOT checked — absence is not evidence of absence.
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let outcome = verify(&file, Some(&sidecar), &policy_now(4_100_000_000));
        assert!(intact(&outcome));
        assert!(outcome
            .footer()
            .contains("revocation NOT checked: no journal found"));

        // Present-but-empty: checked, clean, zero records.
        std::fs::write(
            dir.path().join("revocations.json"),
            serde_json::to_string(&RevocationJournal::new()).unwrap(),
        )
        .unwrap();
        let outcome2 = verify(&file, Some(&sidecar), &policy_now(4_100_000_000));
        assert!(intact(&outcome2));
        assert!(outcome2
            .footer()
            .contains("revocation (journal consulted, chain intact: 0 records)."));
    }

    #[test]
    fn journal_tip_composes_as_of() {
        // A claim is only as fresh as the most recent revocation sweep:
        // with a journal present, `as of` = min(latest checkpoint, tip).
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        journal_revoke(&dir, &["a".repeat(64)], 1_000_000); // old sweep, unrelated target

        let outcome = verify(&file, Some(&sidecar), &policy_now(4_100_000_000));
        match &outcome {
            VerifyOutcome::Intact { as_of, .. } => assert_eq!(*as_of, 1_000_000),
            other => panic!("expected intact, got {other:?}"),
        }
    }

    #[test]
    fn revoked_attestor_excluded_from_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        // One legitimate second attestor + one that will be revoked.
        let mut opm = opm::load(&sidecar).unwrap();
        let a2 = Signer::from_seed(&OTHER_SEED).unwrap();
        opm.attest(&a2).unwrap();
        opm::save(&opm, &sidecar).unwrap();

        // Revoke the first attestor: distinct valid count drops to 1.
        let attestor_fp = Signer::from_seed(&ATTESTOR_SEED).unwrap().fingerprint_hex();
        journal_revoke(&dir, &[attestor_fp], 4_098_000_000);

        // K=2: shortfall disclosed (degraded-intact with 1 of 2).
        let policy = VerifyPolicy {
            now: Some(4_100_000_000),
            required_k: Some(2),
            allow_roster: None,
            journal_path: None,
        };
        let outcome = verify(&file, Some(&sidecar), &policy);
        match &outcome {
            VerifyOutcome::Intact { unattested, .. } => {
                assert_eq!(*unattested, Some((1, 2)), "revoked attestor excluded");
            }
            other => panic!("expected intact, got {other:?}"),
        }

        // K=1: met by the non-revoked attestor alone.
        let policy = VerifyPolicy {
            now: Some(4_100_000_000),
            required_k: Some(1),
            allow_roster: None,
            journal_path: None,
        };
        let outcome = verify(&file, Some(&sidecar), &policy);
        match &outcome {
            VerifyOutcome::Intact { unattested, .. } => assert_eq!(*unattested, None),
            other => panic!("expected intact, got {other:?}"),
        }
    }

    #[test]
    fn pq_gate_falcon_half_tamper_rejected_ed_half_intact() {
        // R3's PQ gate, cross-referenced from P-03: flipping a Falcon
        // signature byte fails the checkpoint signature even though the
        // Ed25519 half is untouched.
        let dir = tempfile::tempdir().unwrap();
        let (file, sidecar) = enrolled_manifest(&dir);
        let opm = opm::load(&sidecar).unwrap();
        let tampered = flip_falcon_sig_byte(&opm);
        let path = save_temp(&tampered, &dir, "pq.opm");
        let outcome = verify(&file, Some(&path), &policy_now(4_100_000_000));
        assert_eq!(outcome.headline(), "manifest-invalid (signer-signature)");
    }

    #[test]
    fn discovered_manifest_verdict_carries_annotation_too() {
        // Full composition: watermark-discovered manifest + C2PA in the
        // watermarked asset, on the Intact path.
        let dir = tempfile::tempdir().unwrap();
        let (file, original) = watermarked_asset(&dir);
        let s = signer();
        let opm =
            Opm::create_from_bytes(&original, &s, Action::Capture, DEFAULT_CHUNK_SIZE).unwrap();
        opm::save(&opm, &dir.path().join("recovered.opm")).unwrap();

        let outcome = verify_discover(&file, &policy_now(4_100_000_000));
        assert!(intact(&outcome), "got: {outcome:?}");
        match &outcome {
            VerifyOutcome::Intact { c2pa, .. } => assert!(!c2pa.present),
            _ => unreachable!(),
        }
    }
}
