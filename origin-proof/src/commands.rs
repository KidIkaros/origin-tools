// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::cli::{AppendArgs, Commands, ProveArgs, RootArgs, VerifyArgs};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Mountain-based MMR with full authentication paths
// ---------------------------------------------------------------------------

/// A perfect binary tree (one "mountain" in the MMR).
/// Nodes stored bottom-up: leaves first, then parents, ..., then peak.
/// Mountain of height h has 2^(h+1) - 1 nodes.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Mountain {
    height: u32,
    /// Bottom-up level order: level 0 (leaves), level 1, ..., level h (peak).
    nodes: Vec<String>, // hex-encoded [u8; 32]
}

impl Mountain {
    fn leaf(hash: [u8; 32]) -> Self {
        Self {
            height: 0,
            nodes: vec![hex::encode(hash)],
        }
    }

    fn peak(&self) -> [u8; 32] {
        decode_hash(self.nodes.last().expect("mountain has at least one node"))
    }

    #[allow(dead_code)]
    fn node_count(&self) -> usize {
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
    fn merge(left: &Mountain, right: &Mountain) -> Mountain {
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

    /// Generate an authentication path for the leaf at `leaf_index` within this mountain.
    /// Returns (leaf_hash, auth_path) where auth_path is a list of (sibling_hash, is_left).
    /// `is_left` means the current node is a LEFT child (so sibling is on the right).
    fn auth_path(&self, leaf_index: usize) -> ([u8; 32], Vec<([u8; 32], bool)>) {
        let leaf_hash = self.get_node(0, leaf_index);
        let mut path = Vec::with_capacity(self.height as usize);
        let mut idx = leaf_index;
        for level in 0..self.height {
            let sibling_idx = idx ^ 1;
            let sibling = self.get_node(level, sibling_idx);
            let is_left = (idx & 1) == 0; // our node is a left child
            path.push((sibling, is_left));
            idx >>= 1;
        }
        (leaf_hash, path)
    }
}

fn parent_hash(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&a);
    buf.extend_from_slice(&b);
    *origin_crypto_sdk::blake3::hash(&buf).as_bytes()
}

fn decode_hash(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("valid hex in state");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

/// The full MMR: an ordered list of mountains (tallest first).
#[derive(Serialize, Deserialize, Clone, Debug)]
struct MmrState {
    /// Format version. v2 = mountain-based with full auth paths.
    #[serde(default = "default_version")]
    version: u32,
    mountains: Vec<Mountain>,
    leaf_count: u64,
}

fn default_version() -> u32 {
    2
}

impl MmrState {
    fn new() -> Self {
        Self {
            version: 2,
            mountains: vec![],
            leaf_count: 0,
        }
    }

    fn append_hash(&mut self, leaf_hash: [u8; 32]) {
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

    fn peaks(&self) -> Vec<[u8; 32]> {
        self.mountains.iter().map(|m| m.peak()).collect()
    }

    fn root(&self) -> [u8; 32] {
        let peaks = self.peaks();
        if peaks.is_empty() {
            return [0u8; 32];
        }
        peaks
            .iter()
            .skip(1)
            .fold(peaks[0], |acc, &p| parent_hash(acc, p))
    }

    /// Find which mountain contains `leaf_index` and the index within that mountain.
    fn locate_leaf(&self, leaf_index: u64) -> Result<(usize, usize), String> {
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

// ---------------------------------------------------------------------------
// Proof format
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
struct MembershipProof {
    leaf_index: u64,
    leaf_count: u64,
    /// BLAKE3 hash of the original data.
    leaf_hash: String,
    /// Authentication path from leaf to peak. Each entry: (sibling_hash, is_left).
    /// is_left = true means the current node is a left child.
    auth_path: Vec<AuthStep>,
    /// Index of the peak this leaf belongs to (0 = tallest/leftmost mountain).
    peak_index: usize,
    /// All peak hashes (for root reconstruction).
    peaks: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthStep {
    hash: String,
    is_left: bool,
}

// ---------------------------------------------------------------------------
// State I/O
// ---------------------------------------------------------------------------

fn load_state(path: &str) -> Result<MmrState, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
    let state: MmrState =
        serde_json::from_str(&content).map_err(|e| format!("cannot parse state: {e}"))?;
    if state.version != 2 {
        return Err(format!(
            "unsupported state version {} (expected 2)",
            state.version
        ));
    }
    Ok(state)
}

fn save_state(state: &MmrState, path: Option<&str>) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(state).map_err(|e| format!("cannot serialize state: {e}"))?;
    match path {
        Some(p) => std::fs::write(p, &json).map_err(|e| format!("cannot write '{p}': {e}")),
        None => {
            println!("{json}");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Append(args) => cmd_append(args),
        Commands::Root(args) => cmd_root(args),
        Commands::Prove(args) => cmd_prove(args),
        Commands::Verify(args) => cmd_verify(args),
    }
}

fn cmd_append(args: AppendArgs) -> Result<(), String> {
    let mut state = match &args.state {
        Some(p) if Path::new(p).exists() => load_state(p)?,
        _ => MmrState::new(),
    };

    let data = hex::decode(args.data.trim()).map_err(|e| format!("invalid data hex: {e}"))?;
    if data.is_empty() {
        return Err("data must not be empty".to_string());
    }
    let leaf_hash = *origin_crypto_sdk::blake3::hash(&data).as_bytes();
    state.append_hash(leaf_hash);

    save_state(&state, args.output.as_deref())?;
    eprintln!(
        "appended leaf #{} (root: {})",
        state.leaf_count - 1,
        hex::encode(state.root())
    );
    Ok(())
}

fn cmd_root(args: RootArgs) -> Result<(), String> {
    let state = load_state(&args.state)?;
    println!("{}", hex::encode(state.root()));
    eprintln!(
        "{} leaves, {} mountains",
        state.leaf_count,
        state.mountains.len()
    );
    Ok(())
}

fn cmd_prove(args: ProveArgs) -> Result<(), String> {
    let state = load_state(&args.state)?;
    let (mountain_idx, leaf_in_mountain) = state.locate_leaf(args.index)?;
    let mountain = &state.mountains[mountain_idx];
    let (leaf_hash, path) = mountain.auth_path(leaf_in_mountain);

    let proof = MembershipProof {
        leaf_index: args.index,
        leaf_count: state.leaf_count,
        leaf_hash: hex::encode(leaf_hash),
        auth_path: path
            .iter()
            .map(|(h, is_left)| AuthStep {
                hash: hex::encode(h),
                is_left: *is_left,
            })
            .collect(),
        peak_index: mountain_idx,
        peaks: state.peaks().iter().map(hex::encode).collect(),
    };

    let json = serde_json::to_string_pretty(&proof).map_err(|e| format!("serialize proof: {e}"))?;
    println!("{json}");
    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<(), String> {
    let content = std::fs::read_to_string(&args.proof)
        .map_err(|e| format!("cannot read '{}': {e}", args.proof))?;
    let proof: MembershipProof =
        serde_json::from_str(&content).map_err(|e| format!("cannot parse proof: {e}"))?;

    let expected_root =
        hex::decode(args.root.trim()).map_err(|e| format!("invalid root hex: {e}"))?;
    if expected_root.len() != 32 {
        return Err(format!(
            "root must be 32 bytes, got {}",
            expected_root.len()
        ));
    }

    // Step 1: Walk the auth path from leaf to peak.
    let mut current = decode_hash(&proof.leaf_hash);
    for step in &proof.auth_path {
        let sibling = decode_hash(&step.hash);
        current = if step.is_left {
            parent_hash(current, sibling)
        } else {
            parent_hash(sibling, current)
        };
    }

    // Step 2: Reconstruct root from peaks, substituting the computed peak.
    if proof.peak_index >= proof.peaks.len() {
        println!("INVALID");
        eprintln!(
            "peak_index {} out of range ({} peaks)",
            proof.peak_index,
            proof.peaks.len()
        );
        std::process::exit(1);
    }
    let mut peaks: Vec<[u8; 32]> = proof.peaks.iter().map(|p| decode_hash(p)).collect();
    peaks[proof.peak_index] = current;

    let computed_root = if peaks.is_empty() {
        [0u8; 32]
    } else {
        peaks
            .iter()
            .skip(1)
            .fold(peaks[0], |acc, &p| parent_hash(acc, p))
    };

    // Step 3: Compare.
    if computed_root == expected_root[..] {
        println!("OK");
        eprintln!(
            "leaf {} verified against root ({} peaks, auth path length {})",
            proof.leaf_index,
            peaks.len(),
            proof.auth_path.len()
        );
        Ok(())
    } else {
        println!("INVALID");
        eprintln!(
            "computed root {} != expected {}",
            hex::encode(computed_root),
            hex::encode(&expected_root)
        );
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

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

    /// Verify a proof internally (same logic as cmd_verify but without exit()).
    fn verify_proof(state: &MmrState, leaf_index: u64) -> bool {
        let (mi, li) = state.locate_leaf(leaf_index).unwrap();
        let mountain = &state.mountains[mi];
        let (leaf_hash, path) = mountain.auth_path(li);

        // Walk auth path
        let mut current = leaf_hash;
        for (sibling, is_left) in &path {
            current = if *is_left {
                parent_hash(current, *sibling)
            } else {
                parent_hash(*sibling, current)
            };
        }

        // Reconstruct root
        let mut peaks = state.peaks();
        peaks[mi] = current;
        let computed = if peaks.is_empty() {
            [0u8; 32]
        } else {
            peaks
                .iter()
                .skip(1)
                .fold(peaks[0], |acc, &p| parent_hash(acc, p))
        };
        computed == state.root()
    }

    #[test]
    fn single_leaf_mmr() {
        let state = build_mmr(1);
        assert_eq!(state.leaf_count, 1);
        assert_eq!(state.mountains.len(), 1);
        assert_eq!(state.mountains[0].height, 0);
        assert_eq!(state.root(), h(&0u64.to_le_bytes()));
        assert!(verify_proof(&state, 0));
    }

    #[test]
    fn two_leaves_single_mountain() {
        let state = build_mmr(2);
        assert_eq!(state.mountains.len(), 1);
        assert_eq!(state.mountains[0].height, 1);
        assert!(verify_proof(&state, 0));
        assert!(verify_proof(&state, 1));
    }

    #[test]
    fn three_leaves_two_mountains() {
        let state = build_mmr(3);
        assert_eq!(state.mountains.len(), 2);
        assert_eq!(state.mountains[0].height, 1); // 2 leaves
        assert_eq!(state.mountains[1].height, 0); // 1 leaf
        for i in 0..3 {
            assert!(verify_proof(&state, i), "leaf {i} must verify");
        }
    }

    #[test]
    fn power_of_two_single_mountain() {
        for &n in &[4u64, 8, 16, 32] {
            let state = build_mmr(n);
            assert_eq!(state.mountains.len(), 1, "n={n} should be one mountain");
            assert_eq!(state.mountains[0].height, n.trailing_zeros());
            for i in 0..n {
                assert!(verify_proof(&state, i), "n={n} leaf {i}");
            }
        }
    }

    #[test]
    fn non_power_of_two_multiple_mountains() {
        // 5 = 4 + 1 → mountains [h=2, h=0]
        let state = build_mmr(5);
        assert_eq!(state.mountains.len(), 2);
        assert_eq!(state.mountains[0].height, 2);
        assert_eq!(state.mountains[1].height, 0);
        for i in 0..5 {
            assert!(verify_proof(&state, i), "leaf {i}");
        }

        // 7 = 4 + 2 + 1 → mountains [h=2, h=1, h=0]
        let state = build_mmr(7);
        assert_eq!(state.mountains.len(), 3);
        for i in 0..7 {
            assert!(verify_proof(&state, i), "leaf {i}");
        }

        // 13 = 8 + 4 + 1 → mountains [h=3, h=2, h=0]
        let state = build_mmr(13);
        assert_eq!(state.mountains.len(), 3);
        for i in 0..13 {
            assert!(verify_proof(&state, i), "leaf {i}");
        }
    }

    #[test]
    fn out_of_range_index_errors() {
        let state = build_mmr(3);
        assert!(state.locate_leaf(3).is_err());
        assert!(state.locate_leaf(100).is_err());
    }

    #[test]
    fn empty_mmr_root_is_zero() {
        let state = MmrState::new();
        assert_eq!(state.root(), [0u8; 32]);
        assert_eq!(state.peaks().len(), 0);
    }

    #[test]
    fn tampered_leaf_fails_verification() {
        let state = build_mmr(4);
        let (mi, li) = state.locate_leaf(1).unwrap();
        let mountain = &state.mountains[mi];
        let (_, path) = mountain.auth_path(li);

        // Use a wrong leaf hash
        let wrong_leaf = h(b"tampered");
        let mut current = wrong_leaf;
        for (sibling, is_left) in &path {
            current = if *is_left {
                parent_hash(current, *sibling)
            } else {
                parent_hash(*sibling, current)
            };
        }
        let mut peaks = state.peaks();
        peaks[mi] = current;
        let computed = peaks
            .iter()
            .skip(1)
            .fold(peaks[0], |acc, &p| parent_hash(acc, p));
        assert_ne!(computed, state.root(), "tampered leaf must not verify");
    }

    #[test]
    fn tampered_sibling_fails_verification() {
        let state = build_mmr(4);
        let (mi, li) = state.locate_leaf(2).unwrap();
        let mountain = &state.mountains[mi];
        let (leaf_hash, mut path) = mountain.auth_path(li);

        // Corrupt the first sibling
        path[0].0 = h(b"evil sibling");
        let mut current = leaf_hash;
        for (sibling, is_left) in &path {
            current = if *is_left {
                parent_hash(current, *sibling)
            } else {
                parent_hash(*sibling, current)
            };
        }
        let mut peaks = state.peaks();
        peaks[mi] = current;
        let computed = peaks
            .iter()
            .skip(1)
            .fold(peaks[0], |acc, &p| parent_hash(acc, p));
        assert_ne!(computed, state.root(), "tampered sibling must not verify");
    }

    #[test]
    fn root_changes_on_append() {
        let s1 = build_mmr(1);
        let s2 = build_mmr(2);
        let s3 = build_mmr(3);
        assert_ne!(s1.root(), s2.root());
        assert_ne!(s2.root(), s3.root());
        assert_ne!(s1.root(), s3.root());
    }

    #[test]
    fn deterministic_roots() {
        let a = build_mmr(10);
        let b = build_mmr(10);
        assert_eq!(a.root(), b.root());
        assert_eq!(a.peaks(), b.peaks());
    }

    #[test]
    fn auth_path_length_equals_mountain_height() {
        let state = build_mmr(8);
        let (mi, li) = state.locate_leaf(5).unwrap();
        let mountain = &state.mountains[mi];
        let (_, path) = mountain.auth_path(li);
        assert_eq!(path.len(), mountain.height as usize);
    }

    #[test]
    fn large_mmr_100_leaves() {
        let state = build_mmr(100);
        // 100 = 64 + 32 + 4 → 3 mountains
        assert_eq!(state.mountains.len(), 3);
        assert_eq!(state.mountains[0].height, 6); // 64
        assert_eq!(state.mountains[1].height, 5); // 32
        assert_eq!(state.mountains[2].height, 2); // 4
                                                  // Spot-check several leaves across mountains
        for i in [0, 1, 63, 64, 65, 95, 96, 99] {
            assert!(verify_proof(&state, i), "leaf {i} in 100-leaf MMR");
        }
    }

    #[test]
    fn mountain_merge_preserves_leaves() {
        let left = Mountain::leaf(h(b"a"));
        let right = Mountain::leaf(h(b"b"));
        let merged = Mountain::merge(&left, &right);
        assert_eq!(merged.height, 1);
        assert_eq!(merged.node_count(), 3);
        // Leaves preserved
        assert_eq!(merged.get_node(0, 0), h(b"a"));
        assert_eq!(merged.get_node(0, 1), h(b"b"));
        // Peak = parent(a, b)
        assert_eq!(merged.peak(), parent_hash(h(b"a"), h(b"b")));
    }

    #[test]
    fn serialization_roundtrip() {
        let state = build_mmr(5);
        let json = serde_json::to_string(&state).unwrap();
        let restored: MmrState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.root(), state.root());
        assert_eq!(restored.leaf_count, state.leaf_count);
        assert_eq!(restored.mountains.len(), state.mountains.len());
    }
}
