//! List keys command (P2.2) — show the key labels that have been sharded into
//! this vault. The vault holds a single master seed, so "keys" are the human
//! labels recorded at shard time (each `Shard` audit entry's `key_id`), plus
//! any explicit entries in the vault's `keys` map.

use crate::audit::Operation;
use crate::cli::ListKeysArgs;
use crate::error::Error;
use crate::vault_handle::VaultHandle;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Serialize)]
struct ListKeysResponse {
    ok: bool,
    command: &'static str,
    vault: String,
    count: usize,
    keys: Vec<String>,
}

/// List the distinct key labels present in the vault's audit history.
pub fn cmd_list_keys(
    _args: ListKeysArgs,
    vault_path: &Path,
    passphrase: &str,
    json: bool,
) -> Result<Vec<String>, Error> {
    let handle = VaultHandle::open(vault_path, passphrase)?;
    let vault_data = handle.data();

    // Collect labels from (a) the keys map and (b) every Shard audit entry's
    // key_id. Deduplicate, preserve insertion order via a BTreeSet.
    let mut labels: BTreeSet<String> = BTreeSet::new();
    for k in vault_data.keys.keys() {
        labels.insert(k.clone());
    }
    for entry in &vault_data.audit_log {
        if matches!(entry.operation, Operation::Shard { .. }) {
            labels.insert(entry.key_id.clone());
        }
    }

    let keys: Vec<String> = labels.into_iter().collect();

    if json {
        let response = ListKeysResponse {
            ok: true,
            command: "list-keys",
            vault: vault_path.display().to_string(),
            count: keys.len(),
            keys: keys.clone(),
        };
        crate::commands::output::print_json(&response, "list-keys")?;
    } else {
        if keys.is_empty() {
            println!("No sharded keys recorded in this vault yet.");
        } else {
            println!("Keys in vault {}:", vault_path.display());
            for k in &keys {
                println!("  - {}", k);
            }
        }
    }

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{InitArgs, ShardArgs};
    use crate::commands::init::cmd_init;
    use crate::commands::shard::cmd_shard;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn init_vault(dir: &std::path::Path, pw: &str) -> PathBuf {
        let vault_path = dir.join("secrets.vault");
        let pw_file = dir.join("pw.txt");
        std::fs::write(&pw_file, format!("{}\n", pw)).unwrap();
        cmd_init(
            InitArgs {
                tier: "standard".to_string(),
            },
            &vault_path,
            Some(pw_file.as_path()),
            false,
            false,
        )
        .unwrap();
        vault_path
    }

    #[test]
    fn test_list_keys_empty_before_shard() {
        let dir = tempdir().unwrap();
        let vault_path = init_vault(dir.path(), "list-passphrase-12");
        let keys =
            cmd_list_keys(ListKeysArgs {}, &vault_path, "list-passphrase-12", false).unwrap();
        assert!(keys.is_empty(), "fresh vault should list no keys");
    }

    #[test]
    fn test_list_keys_reports_sharded_labels() {
        let dir = tempdir().unwrap();
        let vault_path = init_vault(dir.path(), "list-passphrase-12");
        let sargs = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
            force: false,
            expires: None,
        };
        cmd_shard(sargs, &vault_path, "list-passphrase-12", false).unwrap();

        let keys =
            cmd_list_keys(ListKeysArgs {}, &vault_path, "list-passphrase-12", false).unwrap();
        assert!(keys.contains(&"master".to_string()));
    }

    #[test]
    fn test_list_keys_dedupes_repeated_shards() {
        let dir = tempdir().unwrap();
        let vault_path = init_vault(dir.path(), "list-passphrase-12");
        for _ in 0..2 {
            let sargs = ShardArgs {
                key: "master".to_string(),
                threshold: 2,
                shares: 3,
                force: true,
                expires: None,
            };
            cmd_shard(sargs, &vault_path, "list-passphrase-12", false).unwrap();
        }
        let keys =
            cmd_list_keys(ListKeysArgs {}, &vault_path, "list-passphrase-12", false).unwrap();
        // Only one "master" even though we sharded twice.
        assert_eq!(keys.iter().filter(|k| *k == "master").count(), 1);
    }
}
