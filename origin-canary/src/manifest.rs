// SPDX-License-Identifier: Apache-2.0
//
// Copyright (c) 2026 Origin Contributors

//! Canary manifest — the creator's ground-truth record of embedded canaries.

use serde::{Deserialize, Serialize};

/// A single embedded canary token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryToken {
    /// Index of this token within the distribution.
    pub token_id: usize,
    /// The canary secret embedded in source (e.g. `canary_a1b2c3d4e5f6`).
    pub secret: String,
    /// Which embedding strategy hid this token.
    pub embedding_type: String,
    /// Relative path to the file containing this token (for creator reference).
    pub target_file: String,
    /// Line number where the token was embedded (1-indexed, approximate).
    pub line_number: usize,
    /// BLAKE3 hash of `(secret || project_id || distribution_id || token_id)`.
    pub merkle_leaf: Option<String>,
    /// Merkle proof (sibling hashes from leaf to root), if built.
    pub merkle_proof: Vec<String>,
}

/// The full manifest for a distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryManifest {
    /// Arbitrary project identifier chosen by the creator.
    pub project_id: u64,
    /// Distribution identifier (e.g. release tag, version string).
    pub distribution_id: String,
    /// Per-distribution salt used for token generation. Keep offline.
    pub salt: String,
    /// BLAKE3 hash of the source tree at embedding time.
    pub source_tree_hash: String,
    /// Token count embedded in this distribution.
    pub token_count: usize,
    /// The canary tokens embedded (includes secrets — keep offline / encrypted).
    pub canary_tokens: Vec<CanaryToken>,
    /// BLAKE3 Merkle root of the canary leaf set.
    pub merkle_root: Option<String>,
}

impl CanaryManifest {
    /// Number of canary tokens in this manifest.
    pub fn len(&self) -> usize {
        self.canary_tokens.len()
    }

    /// Whether the manifest contains any tokens.
    pub fn is_empty(&self) -> bool {
        self.canary_tokens.is_empty()
    }
}
