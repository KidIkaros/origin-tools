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
    ///
    /// Convenience wrapper for v2 (legacy-hash) mountains; new code should
    /// call [`Mountain::merge_with`] with the owning state's version.
    pub fn merge(left: &Mountain, right: &Mountain) -> Mountain {
        Self::merge_with(left, right, 2)
    }

    /// Merge two equal-height mountains, hashing the new peak with the
    /// internal-node hash for `version` (v2 legacy or v3 domain-separated).
    pub fn merge_with(left: &Mountain, right: &Mountain, version: u32) -> Mountain {
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
        let new_peak = node_hash_for(version, left.peak(), right.peak());
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

/// Domain-separation tag for internal MMR node hashing (format v3+).
///
/// Internal nodes hash `NODE_DOMAIN ‖ left ‖ right`; leaves hash bare data.
/// The distinct domains mean a leaf can never collide with an internal node:
/// without this tag, a 64-byte leaf whose data equals two child hashes
/// concatenated would hash to exactly the internal node value, enabling
/// second-preimage forgery of membership proofs (the CVE-2012-2459 bug
/// class, fixed in Bitcoin by prefixing depth and index).
pub const NODE_DOMAIN: &[u8] = b"ORGN-MMR-NODE";

/// v2 internal-node hash: `blake3(a ‖ b)`.
///
/// Retained so existing v2 state files and proofs keep verifying. Not
/// domain-separated — see [`NODE_DOMAIN`]. Do not use for new data.
pub fn parent_hash(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&a);
    buf.extend_from_slice(&b);
    *origin_crypto_sdk::blake3::hash(&buf).as_bytes()
}

/// v3 internal-node hash: `blake3(NODE_DOMAIN ‖ a ‖ b)`.
///
/// Domain-separated from leaf hashing (`blake3(data)`), closing the
/// leaf/internal-node collision that v2's untagged concatenation allows.
pub fn parent_hash_v3(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(NODE_DOMAIN.len() + 64);
    buf.extend_from_slice(NODE_DOMAIN);
    buf.extend_from_slice(&a);
    buf.extend_from_slice(&b);
    *origin_crypto_sdk::blake3::hash(&buf).as_bytes()
}

/// Internal-node hash for a state/proof of the given format version.
///
/// v3+ states and proofs use the domain-separated hash; v2 uses the legacy
/// untagged one. New states are created as v3 by [`MmrState::new`].
pub fn node_hash_for(version: u32, a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    if version >= 3 {
        parent_hash_v3(a, b)
    } else {
        parent_hash(a, b)
    }
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
    /// Format version. v2 = mountain-based, legacy untagged node hashes;
    /// v3 = same structure with domain-separated internal-node hashes
    /// (see [`NODE_DOMAIN`]). New states are v3; v2 states load and verify
    /// unchanged, and new appends to a v2 state upgrade it to v3.
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
            version: 3,
            mountains: vec![],
            leaf_count: 0,
        }
    }

    pub fn append_hash(&mut self, leaf_hash: [u8; 32]) {
        // Hashes with the state's own version throughout: a loaded v2 state
        // stays internally v2 (mixing hash schemes in one tree would make
        // its peaks incomparable), so appends to it continue with the legacy
        // hash. New states created by `new()` are v3 and hash
        // domain-separated from their first append.
        let version = self.version;
        let mut m = Mountain::leaf(leaf_hash);
        // Merge with existing mountains of the same height (carry propagation).
        while let Some(last) = self.mountains.last() {
            if last.height == m.height {
                let left = self.mountains.pop().unwrap();
                m = Mountain::merge_with(&left, &m, version);
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
            .fold(peaks[0], |acc, &p| node_hash_for(self.version, acc, p))
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
    /// Format version of the state that produced this proof. Missing on
    /// v2-era proof files (serde default) — those verify with the legacy
    /// untagged node hash, exactly as they did when created.
    #[serde(default = "default_version")]
    pub version: u32,
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
            version: self.version,
        })
    }

    /// Verify a membership proof against an expected root.
    ///
    /// The proof's own `version` selects the internal-node hash, so proofs
    /// from v2-era state files verify unchanged under this code.
    pub fn verify_proof(&self, proof: &MembershipProof, expected_root: &[u8; 32]) -> bool {
        let nh = |a: [u8; 32], b: [u8; 32]| node_hash_for(proof.version, a, b);
        // Step 1: walk the auth path leaf -> peak.
        let mut current = decode_hash(&proof.leaf_hash);
        for step in &proof.auth_path {
            let sibling = decode_hash(&step.hash);
            current = if step.is_left {
                nh(current, sibling)
            } else {
                nh(sibling, current)
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
            peaks.iter().skip(1).fold(peaks[0], |acc, &p| nh(acc, p))
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

    // -----------------------------------------------------------------------
    // Domain separation (v3): leaf hashes and internal-node hashes must live
    // in disjoint input domains. Under the legacy v2 scheme a 64-byte leaf
    // whose data equals two 32-byte child hashes concatenated hashes to
    // exactly the parent node's value — second-preimage forgery of membership
    // (the CVE-2012-2459 bug class). These tests pin the fix.
    // -----------------------------------------------------------------------

    /// The forged leaf's data is `left_hash ‖ right_hash` — the same 64 bytes
    /// a parent node hashes. Under v2 the leaf hash EQUALS the parent hash
    /// (the collision); under v3 it must not.
    fn collision_pair() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let left = h(b"left-leaf-data");
        let right = h(b"right-leaf-data");
        let parent = parent_hash(left, right); // v2 node hash
        let forged_leaf = h(&[left, right].concat()); // 64-byte leaf = a‖b
        (left, right, parent, forged_leaf)
    }

    #[test]
    fn v2_leaf_collides_with_internal_node_documents_the_bug() {
        // Pins the vulnerability the fix addresses: under the legacy scheme
        // the collision exists. If this ever stops holding, v2 is no longer
        // the scheme we think it is and the migration story must be revisited.
        let (_l, _r, parent, forged_leaf) = collision_pair();
        assert_eq!(
            forged_leaf, parent,
            "v2 leaf/internal collision vanished — revisit the v2 compat claim"
        );
    }

    #[test]
    fn v3_domain_separation_breaks_the_collision() {
        let (left, right, _v2_parent, forged_leaf) = collision_pair();
        let v3_parent = parent_hash_v3(left, right);
        assert_ne!(
            forged_leaf, v3_parent,
            "v3: a leaf hashing a‖b must not equal the internal node hash"
        );
        assert_ne!(v3_parent, parent_hash(left, right));
    }

    #[test]
    fn v3_forged_membership_proof_fails() {
        // End-to-end: a leaf whose data is the concatenation of the two real
        // child hashes cannot pass a v3 membership proof it isn't part of.
        let mut s = MmrState::new(); // v3
        let a = h(b"real-leaf-A");
        let b = h(b"real-leaf-B");
        s.append_hash(a);
        s.append_hash(b);
        let root = s.root();

        // The attacker's leaf: data = a_hash ‖ b_hash (64 bytes).
        let forged = h(&[a, b].concat());
        let mut forged_state = MmrState::new();
        forged_state.append_hash(forged);
        let proof = forged_state.prove(0).unwrap();

        assert!(
            !s.verify_proof(&proof, &root),
            "forged 64-byte leaf must not verify against the real root"
        );
    }

    #[test]
    fn v3_round_trip_still_verifies() {
        let s = build_mmr(100);
        assert_eq!(s.version, 3, "new states are v3");
        let root = s.root();
        for i in 0..100 {
            let proof = s.prove(i).unwrap();
            assert!(s.verify_proof(&proof, &root), "leaf {i} in 100-leaf v3 MMR");
        }
    }

    #[test]
    fn v2_state_verifies_with_legacy_hash() {
        // A state explicitly built as v2 (simulating a loaded legacy file)
        // must keep verifying under the legacy hash.
        let mut s = MmrState {
            version: 2,
            ..MmrState::new()
        };
        for i in 0..10u64 {
            s.append_hash(h(&i.to_le_bytes()));
        }
        let root = s.root();
        let proof = s.prove(5).unwrap();
        assert_eq!(proof.version, 2, "proof inherits the state's version");
        assert!(s.verify_proof(&proof, &root));
    }

    #[test]
    fn v2_proof_json_without_version_verifies_as_v2() {
        // Simulates an on-disk v2-era proof file: JSON predating the
        // `version` field. serde default (2) must route it to legacy hashing.
        let mut s = MmrState {
            version: 2,
            ..MmrState::new()
        };
        s.append_hash(h(b"x"));
        s.append_hash(h(b"y"));
        let root = s.root();
        let proof = s.prove(0).unwrap();
        let mut json: serde_json::Value = serde_json::to_value(&proof).unwrap();
        json.as_object_mut().unwrap().remove("version");
        let legacy: MembershipProof = serde_json::from_value(json).unwrap();
        assert_eq!(legacy.version, 2, "missing version defaults to 2");
        assert!(s.verify_proof(&legacy, &root));
    }
}
