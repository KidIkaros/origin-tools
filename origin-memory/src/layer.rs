// SPDX-License-Identifier: Apache-2.0

//! layer — tamper-evident membership for a coarse memory layer.
//!
//! A "layer" is a set of nodes grouped by some orthogonal axis value (e.g. all
//! nodes under topic `geopolitics`, or a summary node's leaf set). Each node's
//! canonical markdown hash is appended to a Merkle mountain range. The layer
//! then carries a single `root` (32 bytes) so any reader can prove a node
//! belonged to the layer at write time — without trusting the host.
//!
//! This is what makes the coarse summary/zoom layer *provable*, not just signed:
//! a summary node links to leaves, and the layer MMR lets you prove a given
//! leaf was part of that summary's membership set.

use crate::node::MemoryNode;
use origin_crypto_sdk::blake3;
use origin_proof::mmr::{MembershipProof, MmrState};
use std::collections::BTreeMap;

pub struct LayerMmr {
    /// Stable id for the layer (e.g. "topic:geopolitics" or summary id).
    pub id: String,
    state: MmrState,
    /// Leaf index per node id, so callers can request a proof by node.
    leaf_of: BTreeMap<String, u64>,
}

impl LayerMmr {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            state: MmrState::new(),
            leaf_of: BTreeMap::new(),
        }
    }

    /// Append a node to the layer. The leaf hash is BLAKE3 of the canonical
    /// markdown (the same bytes that get signed and persisted).
    pub fn append(&mut self, node: &MemoryNode) {
        let leaf_hash = *blake3::hash(node.to_markdown().as_bytes()).as_bytes();
        self.state.append_hash(leaf_hash);
        self.leaf_of
            .insert(node.id.clone(), self.state.leaf_count - 1);
    }

    /// The layer root — a single 32-byte commitment over every appended node.
    pub fn root(&self) -> [u8; 32] {
        self.state.root()
    }

    /// Prove that `node_id` is a member of this layer.
    pub fn prove(&self, node_id: &str) -> Option<MembershipProof> {
        let idx = *self.leaf_of.get(node_id)?;
        self.state.prove(idx).ok()
    }

    /// Verify a membership proof against this layer's current root.
    pub fn verify(&self, proof: &MembershipProof) -> bool {
        self.state.verify_proof(proof, &self.root())
    }

    pub fn len(&self) -> usize {
        self.leaf_of.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_of.is_empty()
    }
}
