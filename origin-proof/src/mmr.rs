// SPDX-License-Identifier: Apache-2.0

//! mmr — mountain-based Merkle mountain range (public library surface).
//!
//! This is the extraction of the MMR that previously lived privately inside
//! `commands.rs`, now a reusable `pub mod` so other crates (e.g. origin-memory)
//! can prove membership of a node/leaf in a layer without shelling out to the
//! `origin-proof` CLI. The structure is unchanged: a list of "mountains"
//! (perfect binary trees), tallest first; each append may merge equal-height
//! mountains (carry propagation), giving O(log n) proofs.

use serde::{Deserialize, Serialize};

/// A perfect binary tree (one "mountain" in the MMR).
/// Nodes stored bottom-up: leaves first, then parents, ..., then peak.
/// Mountain of height h has 2^(h+1) - 1 nodes.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Mountain {
    height: u32,
    /// Bottom-up level order: level 0 (leaves), level 1, ..., level h (peak).
    pub nodes: Vec<String>, // hex-encoded [u8; 32]
}

impl Mountain {
    pub fn leaf(hash: [u8; 32]) -> Self {
        Self {
            height: 0,
            nodes: vec![hex::encode(hash)],
        }
    }

    pub fn peak(&self) -> [u8; 32] {
        decode_hash(self.nodes.last().expect("mountain has at least one node"))
    }

    #[allow(dead_code)]
    pub fn node_count(&self) -> usize {
        (1usize << (self.height + 1)) - 1
    }

    /// Offset of level l within the nodes array.
    fn level_offset(&self, l: u32) -> usize {
        (1usize << (self.height + 1)) - (1usize << (self.height - l + 1))
    }

    /// Number of nodes at level l.
    fn level_count(&self, l: u32) -> usize {
        1usize << (self.height - l)
    }

    fn get_node(&self, level: u32, index: usize) -> [u8; 32] {
        let off = self.level_offset(level) + index;
        decode_hash(&self.nodes[off])
    }

    /// Merge two mountains of equal height into one mountain of height h+1.
    pub fn merge(left: &Mountain, right: &Mountain) -> Mountain {
        assert_eq!(
            left.height, right.height,
            "can only merge equal-height mountains"
        );
        let h = left.height + 1;
        let mut nodes = Vec::with_capacity((1 << (h + 1)) - 1);
        // Level 0: all leaves from left then right
        nodes.extend_from_slice(&left.nodes[..left.level_count(0)]);
        nodes.extend_from_slice(&right.nodes[..right.level_count(0)]);
        // Levels 1..h-1: internal nodes from left then right
        for l in 1..h {
            let lc = left.level_count(l);
            let lo = left.level_offset(l);
            let rc = right.level_count(l);
            let ro = right.level_offset(l);
            nodes.extend_from_slice(&left.nodes[lo..lo + lc]);
            nodes.extend_from_slice(&right.nodes[ro..ro + rc]);
        }
        // Level h: new peak = parent(left.peak, right.peak)
        let new_peak = parent_hash(left.peak(), right.peak());
        nodes.push(hex::encode(new_peak));
        Mountain { height: h, nodes }
    }

    /// Generate an authentication path for the leaf at `leaf_index`.
    /// Returns (leaf_hash, auth_path) where auth_path is (sibling_hash, is_left).
    /// `is_left` = true means the current node is a LEFT child.
    pub fn auth_path(&self, leaf_index: usize) -> ([u8; 32], Vec<([u8; 32], bool)>) {
        let leaf_hash = self.get_node(0, leaf_index);
        let mut path = Vec::with_capacity(self.height as usize);
        let mut idx = leaf_index;
        for _level in 0..self.height {
            let sibling_idx = idx ^ 1;
            let sibling = self.get_node(_level, sibling_idx);
            let is_left = (idx & 1) == 0;
            path.push((sibling, is_left));
            idx >>= 1;
        }
        (leaf_hash, path)
    }
}

pub fn parent_hash(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&a);
    buf.extend_from_slice(&b);
    *origin_crypto_sdk::blake3::hash(&buf).as_bytes()
}

pub fn decode_hash(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("valid hex in state");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

/// The full MMR: an ordered list of mountains (tallest first).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MmrState {
    /// Format version. v2 = mountain-based with full auth paths.
    #[serde(default = "default_version")]
    pub version: u32,
    pub mountains: Vec<Mountain>,
    pub leaf_count: u64,
}

fn default_version() -> u32 {
    2
}

impl MmrState {
    pub fn new() -> Self {
        Self {
            version: 2,
            mountains: vec![],
            leaf_count: 0,
        }
    }

    pub fn append_hash(&mut self, leaf_hash: [u8; 32]) {
        let mut m = Mountain::leaf(leaf_hash);
        // Merge with existing mountains of the same height (carry propagation).
        while let Some(last) = self.mountains.last() {
            if last.height == m.height {
                let left = self.mountains.pop().unwrap();
                m = Mountain::merge(&left, &m);
            } else {
                break;
            }
        }
        self.mountains.push(m);
        self.leaf_count += 1;
    }

    pub fn peaks(&self) -> Vec<[u8; 32]> {
        self.mountains.iter().map(|m| m.peak()).collect()
    }

    pub fn root(&self) -> [u8; 32] {
        let peaks = self.peaks();
        if peaks.is_empty() {
            return [0u8; 32];
        }
        peaks
            .iter()
            .skip(1)
            .fold(peaks[0], |acc, &p| parent_hash(acc, p))
    }

    /// Find which mountain contains `leaf_index` and the index within it.
    pub fn locate_leaf(&self, leaf_index: u64) -> Result<(usize, usize), String> {
        if leaf_index >= self.leaf_count {
            return Err(format!(
                "index {leaf_index} out of range ({} leaves)",
                self.leaf_count
            ));
        }
        let mut remaining = leaf_index as usize;
        for (mi, m) in self.mountains.iter().enumerate() {
            let leaves_in_mountain = 1usize << m.height;
            if remaining < leaves_in_mountain {
                return Ok((mi, remaining));
            }
            remaining -= leaves_in_mountain;
        }
        Err("internal error: leaf not found in any mountain".to_string())
    }
}

/// One step of an authentication path: sibling hash + whether current node is left.
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthStep {
    pub hash: String,
    pub is_left: bool,
}

/// A membership proof for a single leaf against the MMR root.
#[derive(Serialize, Deserialize, Debug)]
pub struct MembershipProof {
    pub leaf_index: u64,
    pub leaf_count: u64,
    /// BLAKE3 hash of the original data.
    pub leaf_hash: String,
    /// Authentication path from leaf to peak.
    pub auth_path: Vec<AuthStep>,
    /// Index of the peak this leaf belongs to.
    pub peak_index: usize,
    /// All peak hashes (for root reconstruction).
    pub peaks: Vec<String>,
}

impl MmrState {
    /// Produce a membership proof for `leaf_index`.
    pub fn prove(&self, leaf_index: u64) -> Result<MembershipProof, String> {
        let (mountain_idx, leaf_in_mountain) = self.locate_leaf(leaf_index)?;
        let mountain = &self.mountains[mountain_idx];
        let (leaf_hash, path) = mountain.auth_path(leaf_in_mountain);

        Ok(MembershipProof {
            leaf_index,
            leaf_count: self.leaf_count,
            leaf_hash: hex::encode(leaf_hash),
            auth_path: path
                .iter()
                .map(|(h, is_left)| AuthStep {
                    hash: hex::encode(h),
                    is_left: *is_left,
                })
                .collect(),
            peak_index: mountain_idx,
            peaks: self.peaks().iter().map(hex::encode).collect(),
        })
    }

    /// Verify a membership proof against an expected root.
    pub fn verify_proof(&self, proof: &MembershipProof, expected_root: &[u8; 32]) -> bool {
        // Step 1: walk the auth path leaf -> peak.
        let mut current = decode_hash(&proof.leaf_hash);
        for step in &proof.auth_path {
            let sibling = decode_hash(&step.hash);
            current = if step.is_left {
                parent_hash(current, sibling)
            } else {
                parent_hash(sibling, current)
            };
        }

        // Step 2: reconstruct root from peaks, substituting the computed peak.
        if proof.peak_index >= proof.peaks.len() {
            return false;
        }
        let mut peaks: Vec<[u8; 32]> = proof.peaks.iter().map(|p| decode_hash(p)).collect();
        peaks[proof.peak_index] = current;

        let computed = if peaks.is_empty() {
            [0u8; 32]
        } else {
            peaks
                .iter()
                .skip(1)
                .fold(peaks[0], |acc, &p| parent_hash(acc, p))
        };

        computed == *expected_root
    }
}

impl Default for MmrState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(data: &[u8]) -> [u8; 32] {
        *origin_crypto_sdk::blake3::hash(data).as_bytes()
    }

    fn build_mmr(n: u64) -> MmrState {
        let mut state = MmrState::new();
        for i in 0..n {
            state.append_hash(h(&i.to_le_bytes()));
        }
        state
    }

    #[test]
    fn root_changes_on_append() {
        let mut s = MmrState::new();
        let r0 = s.root();
        s.append_hash(h(b"a"));
        let r1 = s.root();
        assert_ne!(r0, r1);
    }

    #[test]
    fn every_leaf_verifies() {
        let s = build_mmr(100);
        let root = s.root();
        for i in 0..100 {
            let proof = s.prove(i).unwrap();
            assert!(s.verify_proof(&proof, &root), "leaf {i} in 100-leaf MMR");
        }
    }

    #[test]
    fn tampered_leaf_fails() {
        let s = build_mmr(10);
        let mut proof = s.prove(3).unwrap();
        // Flip a byte in the leaf hash.
        let mut bytes = hex::decode(&proof.leaf_hash).unwrap();
        bytes[0] ^= 0xff;
        proof.leaf_hash = hex::encode(bytes);
        let root = s.root();
        assert!(!s.verify_proof(&proof, &root));
    }
}
