// SPDX-License-Identifier: Apache-2.0

//! The wallet's contacts table (INTEGRATION.md §5): a `label → MeshId`
//! phone book populated from discovery results and DHT lookups.
//!
//! Contacts are **not secret** (they are public node identities), so they
//! live in a plain JSON file next to the wallet file — no passphrase
//! needed to read them, no coupling to the wallet's encrypted payload.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, WalletError};

/// The contacts table: a deterministic (sorted) label → MeshId map.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Contacts {
    /// Label → 64-hex-char MeshId.
    pub entries: BTreeMap<String, String>,
    /// Where this table lives (derived from the wallet file path).
    #[serde(skip)]
    path: PathBuf,
}

/// The sidecar file for a wallet file: `wallet.dat` → `wallet.dat.contacts.json`.
pub fn contacts_path(wallet_path: &Path) -> PathBuf {
    let mut os = wallet_path.as_os_str().to_os_string();
    os.push(".contacts.json");
    PathBuf::from(os)
}

impl Contacts {
    /// Load the table next to `wallet_path`; a missing file is an empty
    /// table, never an error.
    pub fn load(wallet_path: &Path) -> Result<Self> {
        let path = contacts_path(wallet_path);
        if !path.exists() {
            return Ok(Self {
                entries: BTreeMap::new(),
                path,
            });
        }
        let raw = std::fs::read_to_string(&path)?;
        let mut table: Self = serde_json::from_str(&raw)
            .map_err(|e| WalletError::Serialization(e.to_string()))?;
        table.path = path;
        Ok(table)
    }

    /// Add or replace a contact and persist. The mesh id must parse as 64
    /// hex chars (a `stoa::MeshId`).
    pub fn add(&mut self, label: &str, mesh: &str) -> Result<()> {
        let _: stoa::MeshId = mesh
            .parse()
            .map_err(|e| WalletError::InvalidAddress(format!("{mesh}: {e}")))?;
        self.entries.insert(label.to_string(), mesh.to_string());
        self.save()
    }

    /// Where this table lives on disk (the sidecar path derived from the
    /// wallet file).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persist the table.
    pub fn save(&self) -> Result<()> {
        if self.path.as_os_str().is_empty() {
            return Err(WalletError::Serialization(
                "contacts table has no backing path".into(),
            ));
        }
        let json = serde_json::to_string_pretty(&self)
            .map_err(|e| WalletError::Serialization(e.to_string()))?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    /// Look up a label; `None` when unknown.
    pub fn get(&self, label: &str) -> Option<&str> {
        self.entries.get(label).map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contacts_roundtrip_and_validation() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = dir.path().join("wallet.dat");
        let mut table = Contacts::load(&wallet).unwrap();
        assert!(table.entries.is_empty(), "missing file = empty table");

        table.add("alice", &hex::encode([0xAB; 32])).unwrap();
        table.add("bob", &hex::encode([0xCD; 32])).unwrap();
        assert_eq!(table.get("alice"), Some(hex::encode([0xAB; 32]).as_str()));

        // A bad mesh id is refused.
        assert!(table.add("bad", "not-a-mesh-id").is_err());

        // Reload from disk — persisted.
        let reloaded = Contacts::load(&wallet).unwrap();
        assert_eq!(reloaded.entries.len(), 2);
        assert_eq!(reloaded.get("bob"), Some(hex::encode([0xCD; 32]).as_str()));
    }
}
