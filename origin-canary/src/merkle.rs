// SPDX-License-Identifier: OPL-1.4
//
// Copyright (c) 2026 Origin Contributors

//! BLAKE3 Merkle tree for canary commitments.

use origin_crypto_sdk::blake3;
use serde::{Deserialize, Serialize};

/// A BLAKE3 Merkle tree built over a set of hex-encoded leaf hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// All leaf hashes (hex-encoded BLAKE3).
    pub leaves: Vec<String>,
    /// The Merkle root (hex-encoded BLAKE3).
    pub root: String,
    /// All tree levels, from leaves (index 0) to root (last index).
    pub levels: Vec<Vec<String>>,
}

/// Build a Merkle tree from a list of hex-encoded leaf hashes.
///
/// Leaves are BLAKE3 hashes represented as lowercase hex strings. The tree
/// is built bottom-up: adjacent pairs are concatenated (raw bytes, not hex)
/// and hashed with BLAKE3. An odd node at any level is duplicated to form a
/// pair.
///
/// # Panics
///
/// Panics if `leaf_hashes` is empty.
pub fn build_merkle_tree(leaf_hashes: Vec<String>) -> MerkleTree {
    assert!(
        !leaf_hashes.is_empty(),
        "Merkle tree requires at least one leaf"
    );

    let leaf_hashes_clone = leaf_hashes.clone();
    let mut levels = vec![leaf_hashes_clone.clone()];

    let mut current_level = leaf_hashes;
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                let combined = blake3_hash_format(&current_level[i], &current_level[i + 1]);
                next_level.push(combined);
                i += 2;
            } else {
                // Odd node — duplicate to form a pair.
                let combined = blake3_hash_format(&current_level[i], &current_level[i]);
                next_level.push(combined);
                i += 1;
            }
        }
        levels.push(next_level.clone());
        current_level = next_level;
    }

    MerkleTree {
        leaves: leaf_hashes_clone,
        root: current_level[0].clone(),
        levels,
    }
}

/// Compute a BLAKE3 hash of two concatenated hex strings.
///
/// The input is treated as raw bytes (decoded from hex), concatenated, and
/// hashed with BLAKE3. The output is a lowercase hex string.
fn blake3_hash_format(left: &str, right: &str) -> String {
    let left_bytes = hex::decode(left).expect("valid hex leaf hash");
    let right_bytes = hex::decode(right).expect("valid hex leaf hash");
    let mut combined = Vec::with_capacity(left_bytes.len() + right_bytes.len());
    combined.extend_from_slice(&left_bytes);
    combined.extend_from_slice(&right_bytes);
    let hash = blake3::hash(&combined);
    hex::encode(hash.as_bytes())
}

/// Generate a Merkle proof for a leaf at the given index.
///
/// The proof is a list of sibling hashes (in order from leaf to root) that,
/// combined with the leaf hash, reconstruct the root.
pub fn get_merkle_proof(tree: &MerkleTree, leaf_index: usize) -> Vec<String> {
    let mut proof = Vec::new();
    let mut index = leaf_index;
    // Walk levels 0..levels.len()-1 (skip the root level).
    for level_idx in 0..tree.levels.len().saturating_sub(1) {
        let level = &tree.levels[level_idx];
        let sibling_idx = if index.is_multiple_of(2) {
            index + 1
        } else {
            index - 1
        };
        if sibling_idx < level.len() {
            proof.push(level[sibling_idx].clone());
        } else if index < level.len() {
            // Odd node at the end of the level: the tree builder paired it
            // with a duplicate of itself, so the sibling IS the node itself.
            proof.push(level[index].clone());
        }
        index /= 2;
    }
    proof
}

/// Walk a proof from a leaf back to the claimed root.
///
/// `leaf_index` is the leaf's position in the tree (needed to know whether
/// each sibling hashes on the left or the right). Returns true only if the
/// walk reconstructs `root` exactly.
pub fn verify_proof(leaf: &str, proof: &[String], leaf_index: usize, root: &str) -> bool {
    let mut current = leaf.to_string();
    let mut idx = leaf_index;
    for sibling in proof {
        let (left, right) = if idx.is_multiple_of(2) {
            (current.clone(), sibling.clone())
        } else {
            (sibling.clone(), current.clone())
        };
        let combined = [left, right]
            .iter()
            .filter_map(|h| hex::decode(h).ok())
            .collect::<Vec<_>>()
            .concat();
        current = hex::encode(blake3::hash(&combined).as_bytes());
        idx /= 2;
    }
    current == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use origin_crypto_sdk::blake3;

    #[test]
    fn single_leaf_tree() {
        let leaf = hex::encode(blake3::hash(b"leaf-0").as_bytes());
        let tree = build_merkle_tree(vec![leaf.clone()]);
        assert_eq!(tree.root, leaf);
        assert_eq!(tree.leaves, vec![leaf]);
        assert_eq!(tree.levels.len(), 1);
    }

    #[test]
    fn two_leaf_tree() {
        let leaf_a = hex::encode(blake3::hash(b"leaf-a").as_bytes());
        let leaf_b = hex::encode(blake3::hash(b"leaf-b").as_bytes());
        let tree = build_merkle_tree(vec![leaf_a.clone(), leaf_b.clone()]);
        // Root = BLAKE3( raw(leaf_a) || raw(leaf_b) )
        let combined = [hex::decode(&leaf_a).unwrap(), hex::decode(&leaf_b).unwrap()].concat();
        let expected_root = hex::encode(blake3::hash(&combined).as_bytes());
        assert_eq!(tree.root, expected_root);
        assert_eq!(tree.leaves, vec![leaf_a, leaf_b]);
        assert_eq!(tree.levels.len(), 2);
    }

    #[test]
    fn merkle_proof_roundtrip() {
        let leaves: Vec<String> = (0..4)
            .map(|i| {
                let hash = blake3::hash(format!("leaf-{i}").as_bytes());
                hex::encode(hash.as_bytes())
            })
            .collect();
        let tree = build_merkle_tree(leaves.clone());
        // Verify every leaf's proof reconstructs the root.
        for (i, leaf) in tree.leaves.iter().enumerate() {
            let proof = get_merkle_proof(&tree, i);
            let mut current = leaf.clone();
            let mut idx = i;
            for sibling in proof {
                let left = if idx % 2 == 0 {
                    current.clone()
                } else {
                    sibling.clone()
                };
                let right = if idx % 2 == 0 {
                    sibling.clone()
                } else {
                    current.clone()
                };
                let combined = [hex::decode(&left).unwrap(), hex::decode(&right).unwrap()].concat();
                current = hex::encode(blake3::hash(&combined).as_bytes());
                idx /= 2;
            }
            assert_eq!(current, tree.root);
        }
    }
}
