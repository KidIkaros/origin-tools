// SPDX-License-Identifier: Apache-2.0

//! axis — the orthogonal dimensions a memory graph is indexed by.
//!
//! The whole thesis: a flat graph collapses time, topic, and evidence onto one
//! plane (your Deep-State-map image). Instead we keep them as *separate*
//! structures and let a query project onto whichever axis answers it. An axis
//! is not a "layer above" — it is an independent index, so you can walk time
//! without topic polluting context, or filter by evidence without loading the
//! temporal backbone.

use crate::node::{Evidence, MemoryNode};
use chrono::NaiveDate;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub enum AxisKind {
    #[default]
    Time,
    Topic,
    Evidence,
}

/// A multi-axis zoom query. Each field is optional; a `Some` constrains the
/// result to nodes on that axis, and `None` leaves that axis unconstrained.
/// `Memory::zoom` intersects every specified axis so a query resolves to the
/// nodes that sit on ALL of them at once (descend only where the question points).
#[derive(Debug, Clone, Default)]
pub struct ZoomQuery {
    /// Temporal window: (center date, half-width in days).
    pub time: Option<(NaiveDate, i64)>,
    /// Topics the result must be tagged with (union within the field, intersect
    /// across fields).
    pub topics: Option<Vec<String>>,
    /// Evidentiary axis filter (e.g. only documented facts).
    pub evidence: Option<Evidence>,
    /// Storage tier axis filter (Sovereign/Standard/Nano).
    pub tier: Option<origin_crypto_sdk::tier::MemoryTier>,
    /// Minimum trust score a node's *signer* must hold (personalized PageRank
    /// in `trust_domain`) for the node to appear in results. None = no trust
    /// filter — the orthogonal trust axis is unconstrained.
    pub min_trust: Option<f64>,
    /// Capability domain to evaluate `min_trust` in. Defaults to
    /// `"memory-write"` when `min_trust` is set and this is None.
    pub trust_domain: Option<String>,
}

/// A single resolvable axis value, plus the node ids that sit on it.
#[derive(Debug, Clone, Default)]
pub struct Axis {
    pub kind: AxisKind,
    /// For Time: date -> node ids. For Topic/Evidence: label -> node ids.
    pub index: BTreeMap<String, Vec<String>>,
}

impl Axis {
    pub fn time() -> Self {
        Axis {
            kind: AxisKind::Time,
            index: BTreeMap::new(),
        }
    }

    pub fn topic() -> Self {
        Axis {
            kind: AxisKind::Topic,
            index: BTreeMap::new(),
        }
    }

    pub fn evidence() -> Self {
        Axis {
            kind: AxisKind::Evidence,
            index: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: String, node_id: String) {
        self.index.entry(key).or_default().push(node_id);
    }

    /// Count of distinct values on this axis (e.g. how many distinct dates).
    pub fn distinct(&self) -> usize {
        self.index.len()
    }
}

/// Build the three orthogonal axes from a set of nodes.
pub fn build_axes(nodes: &[MemoryNode]) -> (Axis, Axis, Axis) {
    let mut time = Axis::time();
    let mut topic = Axis::topic();
    let mut evidence = Axis::evidence();

    for n in nodes {
        time.insert(n.time.format("%Y-%m-%d").to_string(), n.id.clone());
        for t in &n.topics {
            topic.insert(t.clone(), n.id.clone());
        }
        evidence.insert(n.evidence.as_str().to_string(), n.id.clone());
    }
    (time, topic, evidence)
}

/// Temporal zoom: given a center date and a window (days), return the node ids
/// whose time falls within [center - window, center + window]. This is the
/// "walk the star chart" operation — cheap at the top, descends only where the
/// question points.
pub fn temporal_window(time: &Axis, center: NaiveDate, window_days: i64) -> Vec<String> {
    let lo = center - chrono::Duration::days(window_days);
    let hi = center + chrono::Duration::days(window_days);
    let mut out = Vec::new();
    for (k, ids) in &time.index {
        if let Ok(d) = NaiveDate::parse_from_str(k, "%Y-%m-%d") {
            if d >= lo && d <= hi {
                out.extend(ids.iter().cloned());
            }
        }
    }
    out
}

/// Evidence filter: return only node ids on a given evidentiary axis value.
/// This is the trust signal flat graphs omit — "show me only documented facts."
pub fn by_evidence(evidence: &Axis, kind: Evidence) -> Vec<String> {
    evidence
        .index
        .get(kind.as_str())
        .cloned()
        .unwrap_or_default()
}
