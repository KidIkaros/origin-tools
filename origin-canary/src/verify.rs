// SPDX-License-Identifier: OPL-1.4
//
// Copyright (c) 2026 Origin Contributors

//! Canary verification — scan suspect code for embedded canary tokens.

use crate::embed::hash_source_tree;
use crate::manifest::{CanaryManifest, CanaryToken};
use std::fs;
use std::path::Path;

/// Result of an integrity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityStatus {
    /// The current tree hash matches the manifest's recorded hash.
    Intact,
    /// The tree hash differs — at least one file was added, removed, renamed,
    /// or had its contents altered since embedding.
    Tampered,
}

/// Verify the integrity of a source tree against the manifest's recorded
/// `source_tree_hash`.
///
/// This detects *tampering or any change* to the embedded tree (unlike
/// `verify_source`, which only scans for token *presence* / theft). It is a
/// coarse signal: any modification to any file — including a legitimate edit
/// by the Maintainer — will report `Tampered`. Use it to confirm a distribution
/// has not been altered since the canary was embedded.
pub fn verify_integrity(
    source_dir: &Path,
    manifest: &CanaryManifest,
) -> Result<IntegrityStatus, String> {
    let current = hash_source_tree(source_dir)?;
    if current == manifest.source_tree_hash {
        Ok(IntegrityStatus::Intact)
    } else {
        Ok(IntegrityStatus::Tampered)
    }
}

/// A match for a canary token found in suspect code.
#[derive(Debug, Clone)]
pub struct CanaryMatch {
    /// The token ID from the manifest.
    pub token_id: usize,
    /// The canary secret that was found.
    pub secret: String,
    /// Relative path to the file containing the match.
    pub file_path: String,
    /// Line number where the match was found (1-indexed, approximate).
    pub line_number: usize,
    /// The line content (truncated for display).
    pub line_content: String,
}

/// Scan a source tree for canary tokens from a manifest.
///
/// Returns a list of matches, each with the file path, line number, and
/// line content where a canary secret was found.
pub fn verify_source(source_dir: &Path, manifest: &CanaryManifest) -> Vec<CanaryMatch> {
    let mut matches = Vec::new();

    for token in &manifest.canary_tokens {
        let matches_for_token = scan_for_token(source_dir, source_dir, token);
        matches.extend(matches_for_token);
    }

    matches
}

fn scan_for_token(root: &Path, dir: &Path, token: &CanaryToken) -> Vec<CanaryMatch> {
    let mut matches = Vec::new();
    let secret = &token.secret;

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let exclusions = [
                    "test",
                    "tests",
                    "__pycache__",
                    "node_modules",
                    ".git",
                    "venv",
                    ".venv",
                    "build",
                    "dist",
                    "target",
                    ".tox",
                    ".nox",
                    ".eggs",
                ];
                if !exclusions.contains(&name.as_str()) {
                    matches.extend(scan_for_token(root, &path, token));
                }
            } else if path.is_file() {
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_string();
                    if [
                        "py", "js", "jsx", "ts", "tsx", "rs", "sol", "c", "cpp", "h", "hpp", "go",
                        "java", "kt",
                    ]
                    .contains(&ext_str.as_str())
                    {
                        if let Ok(content) = fs::read_to_string(&path) {
                            for (line_idx, line) in content.lines().enumerate() {
                                if line.contains(secret) {
                                    // Paths are always reported relative to the
                                    // scan root, never to the immediate parent.
                                    let relative =
                                        path.strip_prefix(root).map_err(|_| ()).unwrap_or(&path);
                                    matches.push(CanaryMatch {
                                        token_id: token.token_id,
                                        secret: secret.clone(),
                                        file_path: relative.to_string_lossy().to_string(),
                                        line_number: line_idx + 1,
                                        line_content: truncate_line(line, 120),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    matches
}

/// Truncate a line for display purposes.
///
/// Char-boundary safe: never slices through a multi-byte UTF-8 character
/// (suspect code can contain any text).
fn truncate_line(line: &str, max_len: usize) -> String {
    if line.len() <= max_len {
        line.to_string()
    } else {
        let limit = max_len - 3;
        let mut end = limit.min(line.len());
        while end > 0 && !line.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &line[..end])
    }
}

/// Print verification results in a human-readable format.
pub fn print_verification_results(matches: &[CanaryMatch], manifest: &CanaryManifest) {
    if matches.is_empty() {
        println!("No canary tokens found in the scanned source.");
        return;
    }

    println!(
        "Found {} canary token match(es) in the scanned source:",
        matches.len()
    );
    for m in matches {
        println!(
            "  [{}] {} (line {}): {}",
            m.token_id, m.secret, m.line_number, m.line_content
        );
    }

    println!();
    println!("Distribution: {}", manifest.distribution_id);
    println!("Project ID:   {}", manifest.project_id);
    println!(
        "Merkle root:  {}",
        manifest.merkle_root.as_deref().unwrap_or("not built")
    );
    println!();
    println!("This confirms the code was derived from the OPL distribution.");
    println!("To assemble a litigation evidence package, run the 'evidence' subcommand.");
}
