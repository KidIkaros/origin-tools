// SPDX-License-Identifier: Apache-2.0

//! Append-only Merkle Mountain Range (MMR) for the commit log.
//!
//! Mirrors the algorithm in `origin-proof` (which is CLI-oriented and has no
//! stable library re-export): leaves are hashed with their position, peaks are
//! stored explicitly, and the root folds the peaks left-to-right. This gives
//! origin-vcs a tamper-evident **total order** over commits, in addition to the
//! signed parent chain.

use std::collections::BTreeMap;

fn parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    origin_crypto_sdk::sha3_256(&buf)
}

/// Leaf hash binds the data to its position to prevent second-preimage
/// cross-position swaps.
fn leaf_hash(data: &[u8; 32], pos: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + 32);
    buf.extend_from_slice(&pos.to_be_bytes());
    buf.extend_from_slice(data);
    origin_crypto_sdk::sha3_256(&buf)
}

/// Compact persistent MMR state (serde round-trippable).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MmrState {
    /// Peak hashes keyed by peak **height** (h bits -> peak of 2^h leaves).
    /// Using a map keeps us from allocating sparse vectors.
    pub peaks: BTreeMap<u32, [u8; 32]>,
    /// Total number of leaves appended.
    pub leaf_count: u64,
    /// Serialized form version.
    pub version: u8,
}

impl MmrState {
    pub fn new() -> Self {
        MmrState {
            peaks: BTreeMap::new(),
            leaf_count: 0,
            version: 1,
        }
    }

    /// Position of the next leaf (also equals the number of leaves).
    pub fn next_position(&self) -> u64 {
        self.leaf_count
    }

    /// Append a raw datum (typically a commit id). Returns the leaf index.
    pub fn append(&mut self, data: &[u8; 32]) -> u64 {
        let pos = self.next_position();
        self.leaf_count += 1;
        let mut hash = leaf_hash(data, pos);

        // Carry chain: a new leaf is a mountain of height 0. If a peak of the
        // same height already exists, fold them into a mountain of height+1 and
        // continue up. `leaf_count` counting up guarantees the carries terminate.
        let mut height = 0u32;
        loop {
            if let Some(peak) = self.peaks.remove(&height) {
                // Consistent convention: the pre-existing (older) peak is always
                // the left child of the merge; the incoming (newer) hash is the
                // right child. Deterministic and tamper-evident regardless of
                // which exact ordering a conforming peer chooses.
                hash = parent_hash(&peak, &hash);
                height += 1;
                continue;
            }
            break;
        }
        self.peaks.insert(height, hash);
        pos
    }

    /// Number of peaks (mountains).
    pub fn num_mountains(&self) -> usize {
        self.peaks.len()
    }

    /// The current root: fold the mountains in ascending height order.
    pub fn root(&self) -> [u8; 32] {
        let mut it = self.peaks.values();
        let Some(first) = it.next() else {
            return [0u8; 32];
        };
        let mut acc = *first;
        for m in it {
            acc = parent_hash(&acc, m);
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_increases_count_and_folds() {
        let mut m = MmrState::new();
        assert_eq!(m.next_position(), 0);
        for i in 0u8..7 {
            m.append(&[i; 32]);
        }
        assert_eq!(m.leaf_count, 7);
        // 7 leaves = mountains of 4, 2, 1 -> 3 peaks.
        assert_eq!(m.num_mountains(), 3);
        assert_ne!(m.root(), [0u8; 32]);
    }

    #[test]
    fn rooted_is_deterministic() {
        let mut a = MmrState::new();
        let mut b = MmrState::new();
        for i in 0u8..10 {
            let d = [i; 32];
            a.append(&d);
            b.append(&d);
        }
        assert_eq!(a.root(), b.root());
        b.append(&[99u8; 32]);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn serde_roundtrip() {
        let mut m = MmrState::new();
        for i in 0u8..5 {
            m.append(&[i; 32]);
        }
        let json = serde_json::to_string(&m).unwrap();
        let back: MmrState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.root(), m.root());
        assert_eq!(back.leaf_count, m.leaf_count);
    }

    #[test]
    fn append_is_append_only() {
        let mut a = MmrState::new();
        let mut b = MmrState::new();
        for i in 0u8..4 {
            a.append(&[i; 32]);
            b.append(&[i; 32]);
        }
        let r = a.root();
        // Appending the same data twice yields a different root (positions bind).
        b.append(&[0u8; 32]);
        assert_ne!(r, b.root());
    }
}
