// SPDX-License-Identifier: Apache-2.0

//! Reconcile checkpoint MMR (P5) — a thin wrapper over `origin-proof`'s
//! `MmrState`, persisted as JSON, so every reconciliation run's
//! checkpoint is provable in a tamper-evident append-only structure.

use serde::{Deserialize, Serialize};

use origin_proof::mmr::MmrState;

/// The checkpoint log: every leaf is one reconcile run's checkpoint hash.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CheckpointMmr {
    inner: MmrState,
}

impl CheckpointMmr {
    pub fn new() -> Self {
        Self {
            inner: MmrState::new(),
        }
    }

    /// Append a checkpoint hash and return the new root.
    pub fn append_hash(&mut self, leaf_hash: [u8; 32]) -> [u8; 32] {
        self.inner.append_hash(leaf_hash);
        self.inner.root()
    }

    pub fn root(&self) -> [u8; 32] {
        self.inner.root()
    }

    pub fn leaf_count(&self) -> u64 {
        // MmrState exposes leaf_count publicly.
        self.inner.leaf_count
    }

    /// Membership proof for a checkpoint leaf, verified against the root.
    pub fn prove(&self, leaf_index: u64) -> Result<MembershipProof, String> {
        let proof = self.inner.prove(leaf_index)?;
        Ok(MembershipProof { proof })
    }

    pub fn verify_proof(&self, proof: &MembershipProof, expected_root: &[u8; 32]) -> bool {
        self.inner.verify_proof(&proof.proof, expected_root)
    }
}

/// Opaque membership proof handle (keeps `MmrState`'s proof type internal).
#[derive(Debug)]
pub struct MembershipProof {
    proof: origin_proof::mmr::MembershipProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_proof_roundtrip() {
        let mut mmr = CheckpointMmr::new();
        mmr.append_hash([1u8; 32]);
        let root = mmr.append_hash([2u8; 32]);
        let proof = mmr.prove(0).unwrap();
        assert!(mmr.verify_proof(&proof, &root));
        assert!(!mmr.verify_proof(&proof, &[9u8; 32]));
    }

    #[test]
    fn checkpoint_mmr_serde_roundtrip() {
        let mut mmr = CheckpointMmr::new();
        mmr.append_hash([7u8; 32]);
        let root = mmr.root();
        let json = serde_json::to_string(&mmr).unwrap();
        let back: CheckpointMmr = serde_json::from_str(&json).unwrap();
        assert_eq!(back.root(), root);
        assert_eq!(back.leaf_count(), 1);
    }
}
