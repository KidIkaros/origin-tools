//! Verify command — integrity checks for vaults and shares.

use crate::cli::VerifyArgs;
use crate::crypto::{decrypt_vault_data, derive_vault_key, EncryptedVault};
use crate::error::Error;
use crate::share::Share;
use crate::vault::Vault;
use std::path::Path;

/// Verify a vault or share.
///
/// - `--vault-path`: decrypts the vault using the supplied passphrase,
///   re-derives its fingerprint, and confirms the audit log is present.
///   Returns `Ok(())` when integrity holds, otherwise an error.
/// - `--share`: performs structural validation of a share file (parse,
///   non-empty data, well-formed hybrid signature, embedded threshold/total).
///   Full cryptographic verification of a standalone share requires the master
///   seed, which is only available after `recover`; report structural status.
pub fn cmd_verify(args: VerifyArgs, vault_path: &Path, passphrase: &str) -> Result<(), Error> {
    if let Some(path) = &args.share {
        return verify_share(path);
    }

    if let Some(path) = &args.vault_path {
        return verify_vault(path, passphrase);
    }

    // Default: verify the resolved default vault if it exists.
    if vault_path.exists() {
        return verify_vault(vault_path, passphrase);
    }

    Err(Error::VaultNotFound(vault_path.to_path_buf()))
}

/// Decrypt and integrity-check a vault file.
fn verify_vault(path: &Path, passphrase: &str) -> Result<(), Error> {
    let raw = std::fs::read_to_string(path).map_err(|_| Error::VaultNotFound(path.to_path_buf()))?;
    let vault: Vault =
        serde_json::from_str(&raw).map_err(|e| Error::VaultCorrupted(e.to_string()))?;

    let key = derive_vault_key(passphrase.as_bytes(), &vault.salt, vault.tier)?;
    let encrypted = EncryptedVault {
        version: vault.version,
        created_at: vault.created_at.clone(),
        tier: vault.tier,
        fingerprint: vault.fingerprint.clone(),
        salt: vault.salt,
        nonce: vault.nonce,
        ciphertext: vault.ciphertext.clone(),
    };
    let vault_data = decrypt_vault_data(&encrypted, &key)?;

    if vault_data.audit_log.is_empty() {
        return Err(Error::AuditLogNotFound);
    }

    println!(
        "Vault OK: {} audit entries, seed length {} bytes.",
        vault_data.audit_log.len(),
        vault_data.master_seed.len()
    );
    Ok(())
}

/// Structural validation of a share file.
fn verify_share(path: &Path) -> Result<(), Error> {
    let raw = std::fs::read_to_string(path).map_err(|_| Error::ShareNotFound { share_number: 0 })?;
    let share: Share =
        serde_json::from_str(&raw).map_err(|_| Error::ShareCorrupted { share_number: 0 })?;

    if share.share_data.is_empty() {
        return Err(Error::ShareCorrupted {
            share_number: share.share_number,
        });
    }
    if share.signature.ed25519.is_empty() || share.signature.falcon1024.is_empty() {
        return Err(Error::ShareCorrupted {
            share_number: share.share_number,
        });
    }
    if share.threshold == 0 || share.threshold > share.total_shares {
        return Err(Error::InvalidThreshold {
            threshold: share.threshold,
            total_shares: share.total_shares,
        });
    }

    println!(
        "Share {} structurally valid: threshold {}, total {}, {} bytes, fingerprint {}.",
        share.share_number,
        share.threshold,
        share.total_shares,
        share.share_data.len(),
        share.fingerprint
    );
    println!("Cryptographic verification requires `recover` with K shares.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ShardArgs;
    use crate::commands::shard::cmd_shard;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn build_vault(dir: &std::path::Path) -> (PathBuf, String) {
        use crate::crypto::encrypt_vault_data;
        use crate::vault::{MemoryTier, Vault};

        let passphrase = "verify-passphrase-test";
        let salt = [5u8; 16];
        let nonce = [6u8; 24];
        let tier = MemoryTier::Standard;
        let key = derive_vault_key(passphrase.as_bytes(), &salt, tier).unwrap();
        let mut vd = crate::crypto::VaultData::new();
        vd.master_seed = [123u8; 32];
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
    fn test_verify_vault_ok() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase) = build_vault(dir.path());
        // Shard to populate the audit log.
        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
        };
        cmd_shard(args, &vault_path, &passphrase).unwrap();

        let verify_args = VerifyArgs {
            vault_path: None,
            share: None,
            recovery_log: None,
        };
        let result = cmd_verify(verify_args, &vault_path, &passphrase);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_vault_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let (vault_path, _) = build_vault(dir.path());
        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
        };
        cmd_shard(args, &vault_path, "verify-passphrase-test").unwrap();

        let verify_args = VerifyArgs {
            vault_path: None,
            share: None,
            recovery_log: None,
        };
        let result = cmd_verify(verify_args, &vault_path, "wrong-pass");
        assert!(matches!(result, Err(Error::VaultDecryptionFailed(_))));
    }

    #[test]
    fn test_verify_vault_missing_file() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.vault");
        let verify_args = VerifyArgs {
            vault_path: None,
            share: None,
            recovery_log: None,
        };
        let result = cmd_verify(verify_args, &missing, "x");
        assert!(matches!(result, Err(Error::VaultNotFound(_))));
    }

    #[test]
    fn test_verify_share_structural_ok() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase) = build_vault(dir.path());
        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
        };
        cmd_shard(args, &vault_path, &passphrase).unwrap();

        let share_path = dir.path().join("shares").join("share_001.json");
        let verify_args = VerifyArgs {
            vault_path: None,
            share: Some(share_path),
            recovery_log: None,
        };
        let result = cmd_verify(verify_args, &vault_path, &passphrase);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_share_missing_file() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("share_x.json");
        let verify_args = VerifyArgs {
            vault_path: None,
            share: Some(missing),
            recovery_log: None,
        };
        let result = cmd_verify(verify_args, &dir.path().join("vault"), "x");
        assert!(matches!(result, Err(Error::ShareNotFound { .. })));
    }

    #[test]
    fn test_verify_requires_target() {
        let dir = tempdir().unwrap();
        let verify_args = VerifyArgs {
            vault_path: None,
            share: None,
            recovery_log: None,
        };
        // No --vault-path/--share given; default vault path doesn't exist -> VaultNotFound.
        let result = cmd_verify(verify_args, &dir.path().join("absent.vault"), "x");
        assert!(matches!(result, Err(Error::VaultNotFound(_))));
    }
}
