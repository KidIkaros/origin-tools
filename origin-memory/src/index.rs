// SPDX-License-Identifier: Apache-2.0

//! index — the memory graph container: nodes + provenance + orthogonal axes.
//!
//! This is the minimal integration that proves the thesis. A `MemoryIndex`
//! holds parsed nodes, their signatures, and the three orthogonal axes. The
//! coarse community-hierarchy layer (GraphRAG-style) and the full zoom
//! algorithm are the next frontier and are intentionally NOT implemented here.

use crate::axis::{build_axes, by_evidence, temporal_window, Axis, AxisKind};
use crate::node::{Evidence, MemoryNode};
use crate::sign::{derive_bundle, sign_node, verify_node, NodeSignature};
use chrono::NaiveDate;
use std::collections::BTreeMap;
use std::sync::Arc;

use origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle;

pub struct MemoryIndex {
    nodes: BTreeMap<String, MemoryNode>,
    sigs: BTreeMap<String, NodeSignature>,
    axes: BTreeMap<AxisKind, Axis>,
    bundle: Arc<HybridSigningKeyBundle>,
}

impl MemoryIndex {
    /// Create an index bound to a signing identity (master seed + domain).
    pub fn new(master_seed: &[u8; 32], domain: &str) -> Self {
        let bundle = derive_bundle(master_seed, domain);
        MemoryIndex {
            nodes: BTreeMap::new(),
            sigs: BTreeMap::new(),
            axes: BTreeMap::new(),
            bundle,
        }
    }

    /// Add a node, sign it, and reindex all three orthogonal axes.
    pub fn add(&mut self, node: MemoryNode) {
        let sig = sign_node(&node, &self.bundle);
        self.sigs.insert(node.id.clone(), sig);
        self.nodes.insert(node.id.clone(), node);
        self.reindex();
    }

    /// Insert an already-signed node into the hot index WITHOUT re-signing or
    /// doing a full rebuild. Used by `Memory::open` to hydrate from the cold
    /// store. `pub(crate)` only: external crates must not inject unverified
    /// nodes, or they could forge provenance.
    pub(crate) fn reindex_only(&mut self, node: &MemoryNode, sig: &NodeSignature) {
        self.sigs.insert(node.id.clone(), sig.clone());
        self.nodes.insert(node.id.clone(), node.clone());
        self.reindex();
    }

    /// Verify a single node's provenance against its stored signature.
    pub fn verify(&self, id: &str) -> bool {
        match (self.nodes.get(id), self.sigs.get(id)) {
            (Some(n), Some(s)) => verify_node(n, s, &self.bundle),
            _ => false,
        }
    }

    /// Verify every node. Returns the ids that FAIL verification (tampered).
    pub fn verify_all(&self) -> Vec<String> {
        self.nodes
            .keys()
            .filter(|id| !self.verify(id))
            .cloned()
            .collect()
    }

    /// Temporal zoom: walk the time axis around `center` within `window_days`.
    pub fn zoom_time(&self, center: NaiveDate, window_days: i64) -> Vec<String> {
        let time = self.axes.get(&AxisKind::Time).expect("time axis");
        temporal_window(time, center, window_days)
    }

    /// Evidence filter: only documented facts in the given temporal window.
    pub fn zoom_documented(&self, center: NaiveDate, window_days: i64) -> Vec<String> {
        let time = self.axes.get(&AxisKind::Time).expect("time axis");
        let ev = self.axes.get(&AxisKind::Evidence).expect("evidence axis");
        let windowed = temporal_window(time, center, window_days);
        let documented = by_evidence(ev, Evidence::Documented)
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        windowed
            .into_iter()
            .filter(|id| documented.contains(id))
            .collect()
    }

    pub fn node(&self, id: &str) -> Option<&MemoryNode> {
        self.nodes.get(id)
    }

    /// Direct access to the hot node map (used by `Memory::by_tier`).
    pub fn nodes(&self) -> &BTreeMap<String, MemoryNode> {
        &self.nodes
    }

    /// Node ids that fall on a given time axis value (a specific date).
    pub fn on_time(&self, date: &str) -> Vec<String> {
        self.axes
            .get(&AxisKind::Time)
            .and_then(|a| a.index.get(date))
            .cloned()
            .unwrap_or_default()
    }

    /// Node ids tagged with a given topic (orthogonal to time/evidence).
    pub fn on_topic(&self, topic: &str) -> Vec<String> {
        self.axes
            .get(&AxisKind::Topic)
            .and_then(|a| a.index.get(topic))
            .cloned()
            .unwrap_or_default()
    }

    /// Node ids that fall on a given evidentiary axis value.
    pub fn on_evidence(&self, kind: Evidence) -> Vec<String> {
        self.axes
            .get(&AxisKind::Evidence)
            .and_then(|a| a.index.get(kind.as_str()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    fn reindex(&mut self) {
        let nodes: Vec<MemoryNode> = self.nodes.values().cloned().collect();
        let (time, topic, evidence) = build_axes(&nodes);
        self.axes.insert(AxisKind::Time, time);
        self.axes.insert(AxisKind::Topic, topic);
        self.axes.insert(AxisKind::Evidence, evidence);
    }
}
