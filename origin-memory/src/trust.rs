// SPDX-License-Identifier: Apache-2.0

//! trust — multi-agent attribution via origin-attest's TrustGraph.
//!
//! Every MemoryNode carries `sig.signer_fingerprint` — the Ed25519 public key
//! hex of whoever signed it. This module wraps origin-attest's personalized
//! PageRank TrustGraph so you can:
//!
//! - Endorse another signer (trust delegation, anti-monopoly balanced)
//! - Query the trust score of any signer in a capability domain
//! - Filter/rank zoom results by how trusted the *signer* is
//!
//! No external identity daemon — the "federation" is just portable SDK keys +
//! signed endorsements. The TrustGraph operates on hex fingerprints as strings,
//! so it's decoupled from the key derivation layer.

use origin_attest::trust::{TrustGraph, TrustGraphConfig};
use origin_attest::types::{Endorsement, EndorsementTier};

pub struct TrustStore {
    graph: TrustGraph,
    /// The fingerprint of *this* agent (the one whose personalized PageRank
    /// we compute).
    pub self_fp: String,
}

impl TrustStore {
    pub fn new(self_fp: String) -> Self {
        let graph = TrustGraph::new(vec![self_fp.clone()]);
        Self { graph, self_fp }
    }

    /// Endorse another agent in a capability domain (e.g. "memory-write").
    /// Tier-2 endorsements propagate trust through the graph.
    pub fn endorse(&mut self, target_fp: &str, domain: &str, confidence: f64, now: i64) {
        let endorsement = Endorsement {
            tier: EndorsementTier::Tier2,
            endorser_fp: self.self_fp.clone(),
            endorsee_fp: target_fp.to_string(),
            capability_domain: domain.to_string(),
            confidence,
            context: String::new(),
            timestamp: now,
            valid_until: now + 365 * 24 * 3600, // 1 year
            prev_hash: [0u8; 32],
            nonce: 0,
            falcon_signature: Vec::new(), // signature is caller's responsibility
            revocation: false,
            supersedes: None,
        };
        self.graph.add_endorsement(endorsement);
    }

    /// Trust score for a fingerprint in a capability domain [0.0, 1.0].
    /// Seed signers (directly trusted) score 1.0; trust decays with hops.
    pub fn score(&self, fp: &str, domain: &str) -> f64 {
        self.graph.trust_score(fp, domain)
    }

    /// Directly add a raw endorsement (for loading persisted trust data).
    pub fn add_endorsement(&mut self, e: Endorsement) {
        self.graph.add_endorsement(e);
    }

    pub fn config(&self) -> &TrustGraphConfig {
        self.graph.config()
    }
}
