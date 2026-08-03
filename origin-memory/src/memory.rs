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

pub struct Memory {
    index: MemoryIndex,
    store: MemoryStore,
    bundle: Arc<HybridSigningKeyBundle>,
    /// Node ids whose stored signature failed verification on load (tampered).
    load_failures: Vec<String>,
}

impl Memory {
    /// Open (or create) a memory at `root`, bound to a signing identity.
    /// Loads any existing nodes from the cold store into the hot index, and
    /// verifies each one on load — a tampered row is recorded in `tampered()`
    /// rather than trusted silently.
    pub fn open(root: &Path, master_seed: &[u8; 32], domain: &str) -> rusqlite::Result<Self> {
        let bundle = derive_bundle(master_seed, domain);
        let store = MemoryStore::open(root)?;
        let mut index = MemoryIndex::new(master_seed, domain);
        let mut load_failures = Vec::new();
        for (node, sig) in store.load_all()? {
            if !crate::sign::verify_node(&node, &sig, &bundle) {
                load_failures.push(node.id.clone());
            }
            index.reindex_only(&node, &sig);
        }
        Ok(Self {
            index,
            store,
            bundle,
            load_failures,
        })
    }

    /// Node ids that failed signature verification on load (tampered/invalid).
    /// Empty means every loaded node verified cleanly.
    pub fn tampered(&self) -> &[String] {
        &self.load_failures
    }

    /// Add a node: sign it, persist to disk, and update the hot index.
    pub fn add(&mut self, node: MemoryNode) -> rusqlite::Result<()> {
        let sig = sign_node(&node, &self.bundle);
        self.store.save(&node, &sig)?;
        self.index.reindex_only(&node, &sig);
        Ok(())
    }

    /// Build a coarse summary node over `leaves` and persist it (star-chart zoom).
    /// The leaves are committed to a `LayerMmr`; its root is stored on the summary
    /// row so membership of any leaf is provable after reload.
    pub fn summarize(
        &mut self,
        summary_id: &str,
        wing: &str,
        center: NaiveDate,
        leaves: &[MemoryNode],
    ) -> rusqlite::Result<()> {
        self.store
            .save_summary(summary_id, wing, center, leaves, &self.bundle)
            .map(|summary_node| {
                // Keep the hot index consistent so the summary is queryable and
                // layer-verifiable within this session too.
                let sig = crate::sign::sign_node(&summary_node, &self.bundle);
                self.index.reindex_only(&summary_node, &sig);
            })
    }

    /// Verify a leaf's membership in a summary layer after reload, using the
    /// stored layer root. Returns false if the summary has no layer root or the
    /// proof fails (i.e. the leaf was not part of that coarse layer).
    pub fn verify_layer(&self, summary_id: &str, leaf_id: &str) -> bool {
        let root_hex = match self.store.layer_root(summary_id) {
            Some(r) => r,
            None => return false,
        };
        let root = match hex::decode(&root_hex) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return false,
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

    pub fn verify(&self, id: &str) -> bool {
        self.index.verify(id)
    }

    pub fn verify_all(&self) -> Vec<String> {
        self.index.verify_all()
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

        candidates
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
