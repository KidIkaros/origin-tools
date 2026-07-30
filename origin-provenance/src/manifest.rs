// SPDX-License-Identifier: Apache-2.0

//! Directory manifests — recursive provenance records for file trees.
//!
//! A manifest is a JSON document listing every file in a directory tree
//! with its provenance stamp. It serves as a baseline for integrity
//! verification: scan a directory, compare against a manifest, and
//! report any additions, deletions, or modifications.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{ProvenanceError, Result};
use crate::stamp::Stamp;

/// Manifest format version.
pub const MANIFEST_VERSION: u8 = 1;

/// Verification result for a single file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStatus {
    /// File exists and hash matches.
    Ok,
    /// File exists but hash differs.
    Modified,
    /// File is in the manifest but missing on disk.
    Missing,
    /// File is on disk but not in the manifest.
    Added,
}

/// A provenance manifest for a directory tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Format version.
    pub version: u8,
    /// Root directory that was scanned (relative paths used in entries).
    pub root: String,
    /// Unix timestamp when the manifest was created.
    pub created: u64,
    /// File entries: relative path → stamp.
    pub entries: BTreeMap<String, Stamp>,
}

impl Manifest {
    /// Create an empty manifest.
    pub fn new(root: &str) -> Self {
        Manifest {
            version: MANIFEST_VERSION,
            root: root.to_string(),
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            entries: BTreeMap::new(),
        }
    }

    /// Scan a directory tree and build a manifest.
    /// Skips hidden files/dirs (starting with '.') and the manifest file itself.
    pub fn scan(dir: &Path) -> Result<Self> {
        let root_str = dir.to_string_lossy().to_string();
        let mut manifest = Manifest::new(&root_str);
        Self::scan_recursive(dir, dir, &mut manifest)?;
        Ok(manifest)
    }

    fn scan_recursive(base: &Path, current: &Path, manifest: &mut Manifest) -> Result<()> {
        let entries = std::fs::read_dir(current)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip hidden files and directories
            if name_str.starts_with('.') {
                continue;
            }

            if path.is_dir() {
                Self::scan_recursive(base, &path, manifest)?;
            } else if path.is_file() {
                let rel = path
                    .strip_prefix(base)
                    .map_err(|e| ProvenanceError::Other(format!("path strip: {e}")))?;
                let rel_str = rel.to_string_lossy().to_string();
                let stamp = Stamp::from_file(&path)?;
                manifest.entries.insert(rel_str, stamp);
            }
        }
        Ok(())
    }

    /// Verify a directory against this manifest.
    /// Returns a map of relative path → status.
    pub fn verify(&self, dir: &Path) -> Result<BTreeMap<String, FileStatus>> {
        let mut results = BTreeMap::new();

        // Check every manifest entry
        for (rel_path, stamp) in &self.entries {
            let full_path = dir.join(rel_path);
            if !full_path.exists() {
                results.insert(rel_path.clone(), FileStatus::Missing);
                continue;
            }
            let content = std::fs::read(&full_path)?;
            if stamp.verify_content(&content) {
                results.insert(rel_path.clone(), FileStatus::Ok);
            } else {
                results.insert(rel_path.clone(), FileStatus::Modified);
            }
        }

        // Scan disk for files not in the manifest
        self.scan_for_added(dir, dir, &mut results)?;

        Ok(results)
    }

    fn scan_for_added(
        &self,
        base: &Path,
        current: &Path,
        results: &mut BTreeMap<String, FileStatus>,
    ) -> Result<()> {
        let entries = std::fs::read_dir(current)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.starts_with('.') {
                continue;
            }

            if path.is_dir() {
                self.scan_for_added(base, &path, results)?;
            } else if path.is_file() {
                let rel = path
                    .strip_prefix(base)
                    .map_err(|e| ProvenanceError::Other(format!("path strip: {e}")))?;
                let rel_str = rel.to_string_lossy().to_string();
                if !self.entries.contains_key(&rel_str) && !results.contains_key(&rel_str) {
                    results.insert(rel_str, FileStatus::Added);
                }
            }
        }
        Ok(())
    }

    /// Count entries by status.
    pub fn summarize(results: &BTreeMap<String, FileStatus>) -> (usize, usize, usize, usize) {
        let mut ok = 0;
        let mut modified = 0;
        let mut missing = 0;
        let mut added = 0;
        for status in results.values() {
            match status {
                FileStatus::Ok => ok += 1,
                FileStatus::Modified => modified += 1,
                FileStatus::Missing => missing += 1,
                FileStatus::Added => added += 1,
            }
        }
        (ok, modified, missing, added)
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| ProvenanceError::InvalidManifest(e.to_string()))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| ProvenanceError::InvalidManifest(e.to_string()))
    }

    /// Save to a file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load from a file.
    pub fn load(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        Self::from_json(&json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_and_verify_clean() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"beta").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/c.txt"), b"gamma").unwrap();

        let manifest = Manifest::scan(dir.path()).unwrap();
        assert_eq!(manifest.entries.len(), 3);
        assert!(manifest.entries.contains_key("a.txt"));
        assert!(manifest.entries.contains_key("b.txt"));
        assert!(manifest.entries.contains_key("sub/c.txt"));

        let results = manifest.verify(dir.path()).unwrap();
        let (ok, modified, missing, added) = Manifest::summarize(&results);
        assert_eq!(ok, 3);
        assert_eq!(modified, 0);
        assert_eq!(missing, 0);
        assert_eq!(added, 0);
    }

    #[test]
    fn detect_modification() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"original").unwrap();

        let manifest = Manifest::scan(dir.path()).unwrap();
        std::fs::write(dir.path().join("file.txt"), b"tampered!").unwrap();

        let results = manifest.verify(dir.path()).unwrap();
        assert_eq!(results["file.txt"], FileStatus::Modified);
    }

    #[test]
    fn detect_missing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("gone.txt"), b"will be deleted").unwrap();

        let manifest = Manifest::scan(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join("gone.txt")).unwrap();

        let results = manifest.verify(dir.path()).unwrap();
        assert_eq!(results["gone.txt"], FileStatus::Missing);
    }

    #[test]
    fn detect_added() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("existing.txt"), b"here").unwrap();

        let manifest = Manifest::scan(dir.path()).unwrap();
        std::fs::write(dir.path().join("new.txt"), b"surprise").unwrap();

        let results = manifest.verify(dir.path()).unwrap();
        assert_eq!(results["new.txt"], FileStatus::Added);
    }

    #[test]
    fn manifest_json_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("x.txt"), b"data").unwrap();

        let manifest = Manifest::scan(dir.path()).unwrap();
        let json = manifest.to_json().unwrap();
        let loaded = Manifest::from_json(&json).unwrap();
        assert_eq!(loaded.entries.len(), manifest.entries.len());
        assert_eq!(loaded.root, manifest.root);
    }

    #[test]
    fn skips_hidden_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("visible.txt"), b"see me").unwrap();
        std::fs::write(dir.path().join(".hidden"), b"ignore me").unwrap();

        let manifest = Manifest::scan(dir.path()).unwrap();
        assert_eq!(manifest.entries.len(), 1);
        assert!(manifest.entries.contains_key("visible.txt"));
    }

    #[test]
    fn summarize_all_statuses() {
        let mut results = BTreeMap::new();
        results.insert("ok.txt".to_string(), FileStatus::Ok);
        results.insert("mod.txt".to_string(), FileStatus::Modified);
        results.insert("miss.txt".to_string(), FileStatus::Missing);
        results.insert("add.txt".to_string(), FileStatus::Added);

        let (ok, modified, missing, added) = Manifest::summarize(&results);
        assert_eq!(ok, 1);
        assert_eq!(modified, 1);
        assert_eq!(missing, 1);
        assert_eq!(added, 1);
    }
}
