// SPDX-License-Identifier: Apache-2.0

//! memory — the unified facade over hot index + cold store.
//!
//! This is the "one object, one closed loop" the design calls for. Callers use
//! `Memory` and never reach past it into `MemoryIndex` (hot, in-memory) or
//! `MemoryStore` (cold, SQLite + markdown). Every write:
//!
//! 1. signs the node (origin-crypto-sdk hybrid)
//! 2. persists it to disk (canonical .md + SQLite index)
//! 3. updates the hot in-memory index + orthogonal axes
//!
//! so a reload after restart restores the hot cache from the cold store with no
//! re-parsing of signatures.

use crate::axis::ZoomQuery;
use crate::index::MemoryIndex;
use crate::node::MemoryNode;
use crate::persist::MemoryStore;
use crate::sign::{derive_bundle, sign_node};
use chrono::NaiveDate;
use origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle;
use std::path::Path;
use std::sync::Arc;

/// A scored zoom result — the node id plus a relevance breakdown.
/// Every dimension is [0.0, 1.0]; the overall `score` is their weighted average
/// (unspecified query axes don't contribute — they're orthogonal, not penalized).
#[derive(Debug, Clone)]
pub struct ZoomResult {
    pub id: String,
    pub score: f64,
    pub temporal: Option<f64>,
    pub topic_overlap: Option<f64>,
    pub evidence_weight: Option<f64>,
    pub tier_weight: Option<f64>,
    /// Trust score of the node's signer in the query's trust domain
    /// (personalized PageRank). Present on every scored result — R3.
    pub signer_trust: Option<f64>,
}

/// Verification summary: every node falls into exactly one bucket.
#[derive(Debug, Default)]
pub struct VerifyReport {
    /// Nodes whose hybrid signature passes and are not revoked.
    pub valid: Vec<String>,
    /// Nodes that are cryptographically valid but retracted (revoked).
    pub revoked: Vec<String>,
    /// Nodes whose signature failed verification (tampered / corrupted).
    pub failed: Vec<String>,
}

impl VerifyReport {
    pub fn all_sound(&self) -> bool {
        self.failed.is_empty()
    }
}

pub struct Memory {
    index: MemoryIndex,
    store: MemoryStore,
    bundle: Arc<HybridSigningKeyBundle>,
    cipher: crate::crypto::BodyCipher,
    trust: crate::trust::TrustStore,
    /// Cache of computed layer roots by summary id, so repeated `verify_layer`
    /// calls skip the O(n) MMR rebuild when the summary hasn't changed.
    layer_roots: std::collections::HashMap<String, [u8; 32]>,
    /// Node ids whose stored signature failed verification on load (tampered).
    load_failures: Vec<String>,
    /// Journals (revocations / endorsements) that failed integrity verification
    /// on load. Empty means both append-only chains verified cleanly.
    journal_problems: Vec<String>,
}

impl Memory {
    /// Open (or create) a memory at `root`, bound to a signing identity.
    /// Loads any existing nodes from the cold store into the hot index, and
    /// verifies each one on load — a tampered row is recorded in `tampered()`
    /// rather than trusted silently. Both append-only journals (revocations,
    /// endorsements) are verified on load too; a broken chain is surfaced via
    /// `journal_tampered()`. The endorsement chain is replayed into the trust
    /// graph so multi-agent attribution survives restart.
    pub fn open(root: &Path, master_seed: &[u8; 32], domain: &str) -> rusqlite::Result<Self> {
        let bundle = derive_bundle(master_seed, domain);
        let self_fp = hex::encode(bundle.ed25519_pk().as_bytes());
        let store = MemoryStore::open(root)?;
        let mut index = MemoryIndex::new(master_seed, domain);
        let mut load_failures = Vec::new();
        for (node, sig) in store.load_all()? {
            if !crate::sign::verify_node(&node, &sig, &bundle) {
                load_failures.push(node.id.clone());
            }
            index.reindex_only(&node, &sig);
        }
        // Replay the persisted endorsement chain into the trust graph so
        // multi-agent attribution survives restart.
        let mut trust = crate::trust::TrustStore::new(self_fp);
        for e in store.endorsements().chain().endorsements.iter() {
            trust.add_endorsement(e.clone());
        }
        // Verify both append-only journals on load — same discipline as node
        // signature re-verification: a broken chain or a bad signature is
        // recorded and surfaced via `journal_tampered()`, never trusted
        // silently. Entries are still replayed (data is never dropped; the
        // flag is what carries the warning), mirroring `load_failures`.
        let mut journal_problems = Vec::new();
        if !store.revocations().verify(&bundle) {
            journal_problems.push("revocations: chain broken or signature mismatch".to_string());
        }
        if !store.endorsements().verify(&bundle) {
            journal_problems.push("endorsements: chain broken or signature mismatch".to_string());
        }
        Ok(Self {
            index,
            store,
            bundle,
            cipher: crate::crypto::BodyCipher::from_seed(master_seed),
            trust,
            layer_roots: std::collections::HashMap::new(),
            load_failures,
            journal_problems,
        })
    }

    /// Node ids that failed signature verification on load (tampered/invalid).
    /// Empty means every loaded node verified cleanly.
    pub fn tampered(&self) -> &[String] {
        &self.load_failures
    }

    /// Journals that failed integrity verification on load (broken hash chain
    /// or bad Falcon signature). Empty means both the revocation and the
    /// endorsement journal verified cleanly. Data from a flagged journal is
    /// still replayed — it is never silently dropped — but it must not be
    /// trusted without investigation.
    pub fn journal_tampered(&self) -> &[String] {
        &self.journal_problems
    }

    /// The SQLite schema version of the open database (post-migration, R4).
    pub fn schema_version(&self) -> rusqlite::Result<i32> {
        self.store.schema_version()
    }

    /// Add a node: sign it, persist to disk, and update the hot index.
    pub fn add(&mut self, node: MemoryNode) -> rusqlite::Result<()> {
        let sig = sign_node(&node, &self.bundle);
        self.store.save(&node, &sig)?;
        self.index.reindex_only(&node, &sig);
        Ok(())
    }

    /// Add a secret node: sign the plaintext body, then encrypt the body at
    /// rest. The signature commits to the plaintext (sign-then-encrypt); the
    /// on-disk `.md` and SQLite store only the ciphertext. The hot index keeps
    /// the plaintext for in-session queries.
    pub fn add_secret(&mut self, node: MemoryNode) -> rusqlite::Result<()> {
        let sig = sign_node(&node, &self.bundle);
        let sealed = self.cipher.encrypt(node.body.as_bytes());
        let sealed_hex = hex::encode(&sealed);
        self.store.save_encrypted(&node, &sig, &sealed_hex)?;
        self.index.reindex_only(&node, &sig);
        Ok(())
    }

    /// Decrypt a secret node's body. Returns the plaintext body, or None if the
    /// node is not encrypted or decryption fails (wrong key / tampered).
    pub fn decrypt_body(&self, id: &str) -> Option<String> {
        let sealed_hex = self.store.encrypted_body(id)?;
        let sealed = hex::decode(&sealed_hex).ok()?;
        let plaintext = self.cipher.decrypt(&sealed)?;
        String::from_utf8(plaintext).ok()
    }

    /// This agent's own fingerprint (Ed25519 public key hex).
    pub fn fingerprint(&self) -> &str {
        &self.trust.self_fp
    }

    /// Endorse another signer in a capability domain (e.g. "memory-write").
    /// Creates a Falcon-1024-signed, hash-chained endorsement record, persists
    /// it to the endorsement journal (`endorsements.json`), and adds it to the
    /// in-memory trust graph. Propagates trust through the personalized
    /// PageRank graph; survives reload via the journal replay in `open`.
    pub fn endorse(&mut self, target_fp: &str, domain: &str, confidence: f64) {
        let e =
            self.store
                .endorsements_mut()
                .endorse(target_fp, domain, confidence, "", &self.bundle);
        self.trust.add_endorsement(e);
    }

    /// Trust score for a signer in a capability domain [0.0, 1.0].
    pub fn trust_score(&self, fp: &str, domain: &str) -> f64 {
        self.trust.score(fp, domain)
    }

    /// Build a coarse summary node over `leaves` and persist it (star-chart zoom).
    /// The leaves are committed to a `LayerMmr`; its root is stored on the summary
    /// row so membership of any leaf is provable after reload. Revoked leaves
    /// (retracted via the journal) are silently excluded — a coarse layer never
    /// anchors itself on retracted evidence.
    pub fn summarize(
        &mut self,
        summary_id: &str,
        wing: &str,
        center: NaiveDate,
        leaves: &[MemoryNode],
    ) -> rusqlite::Result<()> {
        let active: Vec<MemoryNode> = leaves
            .iter()
            .filter(|n| !self.store.revocations().is_revoked(&n.content_hash_bytes()))
            .cloned()
            .collect();
        self.store
            .save_summary(summary_id, wing, center, &active, &self.bundle)
            .map(|summary_node| {
                // Keep the hot index consistent so the summary is queryable and
                // layer-verifiable within this session too.
                let sig = crate::sign::sign_node(&summary_node, &self.bundle);
                self.index.reindex_only(&summary_node, &sig);
                // Cache the layer root so repeat verify_layer calls are O(1).
                if let Some(root_hex) = self.store.layer_root(summary_id) {
                    if let Ok(bytes) = hex::decode(&root_hex) {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            self.layer_roots.insert(summary_id.to_string(), arr);
                        }
                    }
                }
            })
    }

    /// Verify a leaf's membership in a summary layer after reload, using the
    /// stored layer root. Returns false if the summary has no layer root or the
    /// proof fails (i.e. the leaf was not part of that coarse layer).
    pub fn verify_layer(&self, summary_id: &str, leaf_id: &str) -> bool {
        // Use the cached root if available (avoids hex decode on hot path);
        // fall back to the stored root from the cold store.
        let root = if let Some(cached) = self.layer_roots.get(summary_id) {
            *cached
        } else {
            let root_hex = match self.store.layer_root(summary_id) {
                Some(r) => r,
                None => return false,
            };
            match hex::decode(&root_hex) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => return false,
            }
        };
        // Rebuild a LayerMmr over the summary's linked leaves and prove membership.
        let summary = match self.node(summary_id) {
            Some(n) => n,
            None => return false,
        };
        let mut layer = crate::layer::LayerMmr::new(summary_id);
        for lid in &summary.links {
            if let Some(leaf) = self.node(lid) {
                layer.append(leaf);
            }
        }
        match layer.prove(leaf_id) {
            Some(proof) => layer.verify(&proof) && layer.root() == root,
            None => false,
        }
    }

    /// Retract a node without deleting it (preserves provenance + layer MMRs).
    /// Records an append-only, hash-chained, Falcon-signed revocation keyed by
    /// the node's content hash. The revocation survives reload and is itself
    /// verifiable via `revocations_verified`.
    pub fn revoke(&mut self, id: &str, reason: &str) -> rusqlite::Result<()> {
        let node = self
            .node(id)
            .ok_or_else(|| rusqlite::Error::QueryReturnedNoRows)?
            .clone();
        let content_hash = node.content_hash_bytes();
        let fingerprint = hex::encode(self.bundle.ed25519_pk().as_bytes());
        // The revocation store mutates its journal + persists; reach through store.
        self.store
            .revoke_node(content_hash, &fingerprint, reason, &self.bundle);
        Ok(())
    }

    /// Has this node's content hash been revoked?
    pub fn is_revoked(&self, id: &str) -> bool {
        match self.node(id) {
            Some(n) => self.store.revocations().is_revoked(&n.content_hash_bytes()),
            None => false,
        }
    }

    /// Verify the revocation journal's hash chain AND every record's Falcon sig.
    pub fn revocations_verified(&self) -> bool {
        self.store.revocations().verify(&self.bundle)
    }

    /// Verify the endorsement journal's hash chain AND the Falcon signature of
    /// every endorsement this agent issued. Foreign endorsements (whose keys
    /// are unknown locally) are skipped in signature checks but still chain-
    /// bound.
    pub fn store_endorsements_verified(&self) -> bool {
        self.store.endorsements().verify(&self.bundle)
    }

    pub fn verify(&self, id: &str) -> bool {
        self.index.verify(id)
    }

    /// Verify every node's signature and classify into valid / revoked / failed.
    /// `all_sound()` on the report means no tampering or corruption was detected.
    pub fn verify_all(&self) -> VerifyReport {
        let mut report = VerifyReport::default();
        for id in self.index.nodes().keys() {
            if self.is_revoked(id) {
                report.revoked.push(id.clone());
            } else if self.index.verify(id) {
                report.valid.push(id.clone());
            } else {
                report.failed.push(id.clone());
            }
        }
        report
    }

    pub fn zoom_time(&self, center: NaiveDate, window_days: i64) -> Vec<String> {
        self.index.zoom_time(center, window_days)
    }

    /// Documented facts only, within a temporal window — the trust-filtered zoom.
    pub fn zoom_documented(&self, center: NaiveDate, window_days: i64) -> Vec<String> {
        self.index.zoom_documented(center, window_days)
    }

    /// Zoom by storage tier (Sovereign/Standard/Nano) — the shared Origin tier axis.
    pub fn by_tier(&self, tier: origin_crypto_sdk::tier::MemoryTier) -> Vec<String> {
        self.index
            .nodes()
            .iter()
            .filter(|(id, _)| self.index.node(id).map(|n| n.tier) == Some(tier))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Multi-axis zoom projector — the "descend only where the question points"
    /// operation. A query projects onto as many orthogonal axes as it specifies
    /// and intersects them, so a question like "documented geopolitics facts
    /// around 2004, sovereign tier" resolves to exactly the nodes on all four
    /// axes at once. Unspecified axes are not constrained.
    pub fn zoom(&self, q: &ZoomQuery) -> Vec<String> {
        // Start from the temporal window if given, else the topic set, else all.
        let mut candidates: Vec<String> = match q.time {
            Some((center, window)) => self.index.zoom_time(center, window),
            None => self.index.nodes().keys().cloned().collect(),
        };

        if let Some(topics) = &q.topics {
            let mut keep = std::collections::HashSet::new();
            for t in topics {
                for id in self.index.on_topic(t) {
                    keep.insert(id);
                }
            }
            candidates.retain(|id| keep.contains(id));
        }

        if let Some(evidence) = &q.evidence {
            let set: std::collections::HashSet<String> = self
                .index
                .on_evidence(evidence.clone())
                .into_iter()
                .collect();
            candidates.retain(|id| set.contains(id));
        }

        if let Some(tier) = &q.tier {
            let set: std::collections::HashSet<String> = self.by_tier(*tier).into_iter().collect();
            candidates.retain(|id| set.contains(id));
        }

        // Retracted nodes never appear in a zoom result — they remain in the
        // store (provenance preserved) but are excluded from queries.
        candidates.retain(|id| !self.is_revoked(id));

        // Trust axis (R3): a node is only visible if its *signer* holds at
        // least `min_trust` personalized-PageRank trust in the query's trust
        // domain. Unset = unconstrained — same orthogonality as the other axes.
        if let Some(min_trust) = q.min_trust {
            let domain = q
                .trust_domain
                .clone()
                .unwrap_or_else(|| "memory-write".to_string());
            candidates.retain(|id| {
                self.index.sig(id).is_some_and(|sig| {
                    self.trust.score(&sig.signer_fingerprint, &domain) >= min_trust
                })
            });
        }

        candidates
    }

    /// Scored zoom — same intersection as `zoom`, but each surviving node gets a
    /// relevance score so results are *ranked*, not just filtered. The score is
    /// a weighted average over every axis the query specifies:
    ///
    /// - **Temporal** (if `time` set): `1 - |days_from_center| / window`
    /// - **Topic overlap** (if `topics` set): `matched / query_topics`
    /// - **Evidence weight**: Documented=1.0, Assertion=0.7, Summary=0.5, Fiction=0.3
    /// - **Tier weight**: Sovereign=1.0, Standard=0.7, Nano=0.4
    /// - **Signer trust** (R3): personalized-PageRank trust of the node's
    ///   signer in the query's `trust_domain` (default "memory-write"). For a
    ///   single-agent memory every node is self-signed (trust 1.0), so this is
    ///   a constant that doesn't change relative rank; in a multi-agent memory
    ///   it demotes nodes from untrusted signers.
    ///
    /// Unspecified axes don't contribute — they're orthogonal, not zeroed.
    pub fn zoom_scored(&self, q: &ZoomQuery) -> Vec<ZoomResult> {
        let trust_domain = q
            .trust_domain
            .clone()
            .unwrap_or_else(|| "memory-write".to_string());
        let ids = self.zoom(q);
        let mut results: Vec<ZoomResult> = ids
            .iter()
            .filter_map(|id| {
                let node = self.node(id)?;
                let mut dims = Vec::new();

                let temporal = q.time.map(|(center, window)| {
                    let days = (node.time - center).num_days().abs();
                    if window > 0 {
                        1.0 - (days as f64 / window as f64).min(1.0)
                    } else {
                        1.0
                    }
                });
                if let Some(t) = temporal {
                    dims.push(t);
                }

                let topic_overlap = q.topics.as_ref().map(|topics| {
                    if topics.is_empty() {
                        1.0
                    } else {
                        let matched = topics
                            .iter()
                            .filter(|t| node.topics.iter().any(|nt| nt == *t))
                            .count();
                        matched as f64 / topics.len() as f64
                    }
                });
                if let Some(t) = topic_overlap {
                    dims.push(t);
                }

                let evidence_weight = evidence_score(&node.evidence);
                dims.push(evidence_weight);

                let tier_weight = tier_score(node.tier);
                dims.push(tier_weight);

                // Signer trust (R3): the personalized-PageRank score of whoever
                // signed this node, in the query's trust domain. Intrinsic to
                // the node, so it always contributes — single-agent memories
                // see a constant 1.0 that leaves relative ranking untouched.
                let signer_trust = self
                    .index
                    .sig(id)
                    .map(|sig| self.trust.score(&sig.signer_fingerprint, &trust_domain));
                if let Some(t) = signer_trust {
                    dims.push(t);
                }

                let score = dims.iter().sum::<f64>() / dims.len() as f64;
                Some(ZoomResult {
                    id: id.clone(),
                    score,
                    temporal,
                    topic_overlap,
                    evidence_weight: Some(evidence_weight),
                    tier_weight: Some(tier_weight),
                    signer_trust,
                })
            })
            .collect();
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }

    /// All node ids currently in the hot index (ordered by insertion).
    pub fn node_ids(&self) -> Vec<String> {
        self.index.nodes().keys().cloned().collect()
    }

    /// The children (linked nodes) of a summary — the one-level descent.
    /// Returns `None` if the node doesn't exist; empty if it's a leaf.
    pub fn children(&self, id: &str) -> Option<Vec<String>> {
        self.node(id).map(|n| n.links.iter().cloned().collect())
    }

    /// Is this node a leaf (no children/links)?
    pub fn is_leaf(&self, id: &str) -> bool {
        self.node(id).map(|n| n.links.is_empty()).unwrap_or(true)
    }

    /// Count the depth of the hierarchy rooted at `summary_id` (1 = flat,
    /// 2 = one level of summaries-of-summaries, etc.). Returns 0 if not found.
    pub fn depth(&self, summary_id: &str) -> usize {
        let node = match self.node(summary_id) {
            Some(n) => n,
            None => return 0,
        };
        if node.links.is_empty() {
            return 1;
        }
        let child_depths: Vec<usize> = node.links.iter().map(|lid| self.depth(lid)).collect();
        1 + child_depths.into_iter().max().unwrap_or(0)
    }

    /// Walk the full subtree rooted at `summary_id` in breadth-first order.
    /// Returns the ids at each level: `result[0]` = root, `result[1]` = its
    /// children, etc. Useful for rendering the star-chart hierarchy.
    pub fn levels(&self, summary_id: &str) -> Vec<Vec<String>> {
        let mut result = Vec::new();
        let mut frontier = vec![summary_id.to_string()];
        while !frontier.is_empty() {
            result.push(frontier.clone());
            let mut next = Vec::new();
            for id in &frontier {
                if let Some(children) = self.children(id) {
                    next.extend(children);
                }
            }
            frontier = next;
        }
        result
    }

    pub fn node(&self, id: &str) -> Option<&MemoryNode> {
        self.index.node(id)
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn store(&self) -> &MemoryStore {
        &self.store
    }
}

/// Evidence trust weight — Documented is the gold standard, Fiction is the
/// weakest. Used by `zoom_scored` to rank nodes by evidentiary strength.
fn evidence_score(e: &crate::node::Evidence) -> f64 {
    use crate::node::Evidence;
    match e {
        Evidence::Documented => 1.0,
        Evidence::Assertion => 0.7,
        Evidence::Summary => 0.5,
        Evidence::Fiction => 0.3,
    }
}

/// Storage tier weight — Sovereign > Standard > Nano. Maps directly to the
/// `MemoryTier` from `origin-common` (reused, not reinvented).
fn tier_score(tier: origin_crypto_sdk::tier::MemoryTier) -> f64 {
    use origin_crypto_sdk::tier::MemoryTier;
    match tier {
        MemoryTier::Sovereign => 1.0,
        MemoryTier::Standard => 0.7,
        MemoryTier::Nano => 0.4,
    }
}
