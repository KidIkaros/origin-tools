//! List shares command (P2.3) — scan the `<vault_dir>/shares/` directory beside
//! the vault and report each share's number, threshold, total, label, and
//! recipient (if the share was exported to a specific recipient).

use crate::cli::ListSharesArgs;
use crate::error::Error;
use crate::share::Share;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// One row of `list-shares` output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShareInfo {
    pub file: String,
    pub share_number: u8,
    pub threshold: u8,
    pub total_shares: u8,
    pub label: String,
    pub recipient: Option<String>,
}

/// List the share files present beside the vault.
pub fn cmd_list_shares(
    _args: ListSharesArgs,
    vault_path: &Path,
    _passphrase: &str,
    json: bool,
) -> Result<Vec<ShareInfo>, Error> {
    let shares_dir = vault_path
        .parent()
        .map(|p| p.join("shares"))
        .unwrap_or_else(|| PathBuf::from("shares"));

    let mut infos: Vec<ShareInfo> = Vec::new();

    if shares_dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(&shares_dir)
            .map_err(|e| Error::IoError(format!("read shares dir: {e}")))?
            .filter_map(|e| e.ok())
            .collect();
        // Stable order by file name.
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = match std::fs::read_to_string(&path) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let share: Share = match serde_json::from_str(&raw) {
                Ok(s) => s,
                Err(_) => continue,
            };
            infos.push(ShareInfo {
                file: path.display().to_string(),
                share_number: share.share_number,
                threshold: share.threshold,
                total_shares: share.total_shares,
                label: share.key_id,
                recipient: share.recipient,
            });
        }
    }

    // Order by share number for readability.
    infos.sort_by_key(|i| i.share_number);

    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "list-shares",
                "vault": vault_path.display().to_string(),
                "shares_dir": shares_dir.display().to_string(),
                "count": infos.len(),
                "shares": infos,
            })
        );
    } else {
        if infos.is_empty() {
            println!("No share files found in {}", shares_dir.display());
        } else {
            println!(
                "Shares in {} (threshold {}/{}):",
                shares_dir.display(),
                infos.first().map(|i| i.threshold).unwrap_or(0),
                infos.first().map(|i| i.total_shares).unwrap_or(0)
            );
            for info in &infos {
                let recipient = info
                    .recipient
                    .as_ref()
                    .map(|r| format!(" -> {r}"))
                    .unwrap_or_default();
                println!(
                    "  #{}  label={}  (share_{:03}.json{})",
                    info.share_number, info.label, info.share_number, recipient
                );
            }
        }
    }

    Ok(infos)
}

/// Best-effort mtime of a path (used by tests/debug; not part of the API).
#[allow(dead_code)]
fn modified_at(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{ExportArgs, InitArgs, ShardArgs};
    use crate::commands::export::cmd_export_share;
    use crate::commands::init::cmd_init;
    use crate::commands::shard::cmd_shard;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn setup(dir: &std::path::Path, pw: &str) -> PathBuf {
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
        )
        .unwrap();
        vault_path
    }

    #[test]
    fn test_list_shares_reports_sharded_files() {
        let dir = tempdir().unwrap();
        let vault_path = setup(dir.path(), "list-shares-pw-12");
        let sargs = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
            force: false,
        };
        cmd_shard(sargs, &vault_path, "list-shares-pw-12", false).unwrap();

        let infos =
            cmd_list_shares(ListSharesArgs {}, &vault_path, "list-shares-pw-12", false).unwrap();
        assert_eq!(infos.len(), 3);
        for (i, info) in infos.iter().enumerate() {
            assert_eq!(info.share_number, (i + 1) as u8);
            assert_eq!(info.threshold, 2);
            assert_eq!(info.total_shares, 3);
            assert_eq!(info.label, "master");
            assert!(info.recipient.is_none());
        }
    }

    #[test]
    fn test_list_shares_empty_without_shares_dir() {
        let dir = tempdir().unwrap();
        let vault_path = setup(dir.path(), "list-shares-pw-12");
        let infos =
            cmd_list_shares(ListSharesArgs {}, &vault_path, "list-shares-pw-12", false).unwrap();
        assert!(infos.is_empty());
    }

    #[test]
    fn test_list_shares_shows_recipient_for_exported() {
        let dir = tempdir().unwrap();
        let vault_path = setup(dir.path(), "list-shares-pw-12");
        let sargs = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
            force: false,
        };
        cmd_shard(sargs, &vault_path, "list-shares-pw-12", false).unwrap();

        // Export share 1 to recipient "alice".
        let out = dir.path().join("exported_share_1.json");
        let eargs = ExportArgs {
            share: 1,
            out: out.clone(),
            recipient: Some("alice".to_string()),
            force: false,
        };
        cmd_export_share(eargs, &vault_path, "list-shares-pw-12", false).unwrap();

        // The exported file is NOT in shares_dir, so list-shares should still
        // report the 3 sharded files (recipient None in those). The exported
        // file is a separate artifact.
        let infos =
            cmd_list_shares(ListSharesArgs {}, &vault_path, "list-shares-pw-12", false).unwrap();
        assert_eq!(infos.len(), 3);
        assert!(infos.iter().all(|i| i.recipient.is_none()));
    }
}
