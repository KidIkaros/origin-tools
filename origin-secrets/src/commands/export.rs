//! Export-share command — package a share for handoff to a recipient.

use crate::cli::ExportArgs;
use crate::error::Error;
use crate::share::Share;
use std::path::{Path, PathBuf};

/// Export a previously created share for delivery to its recipient.
///
/// Loads `<vault_dir>/shares/share_<n>.json`, optionally stamps the `recipient`
/// field, and writes the annotated share to the output path. The share's
/// cryptographic binding (its hybrid signature over `share_data`) is preserved
/// unchanged — only the recipient annotation is added.
pub fn cmd_export_share(args: ExportArgs, vault_path: &Path) -> Result<Share, Error> {
    let shares_dir = vault_path
        .parent()
        .map(|p| p.join("shares"))
        .unwrap_or_else(|| PathBuf::from("shares"));
    let share_path = shares_dir.join(format!("share_{:03}.json", args.share));

    let raw = std::fs::read_to_string(&share_path)
        .map_err(|_| Error::ShareNotFound { share_number: args.share })?;
    let mut share: Share =
        serde_json::from_str(&raw).map_err(|_| Error::ShareCorrupted { share_number: args.share })?;

    if let Some(recipient) = args.recipient {
        share.recipient = Some(recipient);
    }

    let serialized =
        serde_json::to_string_pretty(&share).map_err(|e| Error::IoError(e.to_string()))?;
    std::fs::write(&args.out, serialized).map_err(|e| Error::IoError(e.to_string()))?;

    println!(
        "Exported share {} to {} (recipient: {}).",
        args.share,
        args.out.display(),
        share.recipient.as_deref().unwrap_or("<none>")
    );
    Ok(share)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ShardArgs;
    use crate::commands::shard::cmd_shard;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_vault(dir: &std::path::Path) -> (PathBuf, String) {
        use crate::crypto::encrypt_vault_data;
        use crate::vault::{MemoryTier, Vault};

        let passphrase = "export-passphrase";
        let salt = [9u8; 16];
        let nonce = [10u8; 24];
        let tier = MemoryTier::Standard;
        let key = crate::crypto::derive_vault_key(passphrase.as_bytes(), &salt, tier).unwrap();
        let mut vd = crate::crypto::VaultData::new();
        vd.master_seed = [7u8; 32];
        let enc = encrypt_vault_data(&vd, &key, salt, nonce, tier).unwrap();
        let vault = Vault {
            version: enc.version,
            created_at: enc.created_at.clone(),
            tier: enc.tier,
            fingerprint: enc.fingerprint.clone(),
            salt: enc.salt,
            nonce: enc.nonce,
            ciphertext: enc.ciphertext,
        };
        let path = dir.join("secrets.vault");
        std::fs::write(&path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();
        (path, passphrase.to_string())
    }

    #[test]
    fn test_export_share_success() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase) = make_vault(dir.path());
        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
        };
        cmd_shard(args, &vault_path, &passphrase).unwrap();

        let out = dir.path().join("exported_001.json");
        let export_args = ExportArgs {
            share: 1,
            out: out.clone(),
            recipient: Some("alice".to_string()),
        };
        let share = cmd_export_share(export_args, &vault_path).unwrap();
        assert_eq!(share.share_number, 1);
        assert_eq!(share.recipient.as_deref(), Some("alice"));

        // The written file should parse back identically (minus recipient change).
        let written: Share =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(written.recipient.as_deref(), Some("alice"));
        assert_eq!(written.share_data, share.share_data);
    }

    #[test]
    fn test_export_share_no_recipient() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase) = make_vault(dir.path());
        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
        };
        cmd_shard(args, &vault_path, &passphrase).unwrap();

        let out = dir.path().join("exported_002.json");
        let export_args = ExportArgs {
            share: 2,
            out,
            recipient: None,
        };
        let share = cmd_export_share(export_args, &vault_path).unwrap();
        assert_eq!(share.recipient, None);
    }

    #[test]
    fn test_export_missing_share() {
        let dir = tempdir().unwrap();
        let (vault_path, _) = make_vault(dir.path());
        let out = dir.path().join("x.json");
        let export_args = ExportArgs {
            share: 9, // not created
            out,
            recipient: None,
        };
        let result = cmd_export_share(export_args, &vault_path);
        assert!(matches!(
            result,
            Err(Error::ShareNotFound { share_number: 9 })
        ));
    }
}
