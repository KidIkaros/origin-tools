//! Verify command — integrity checks for vaults and shares.

use crate::cli::VerifyArgs;
use crate::crypto::{decrypt_vault_data, derive_vault_key, EncryptedVault};
use crate::error::Error;
use crate::share::Share;
use crate::vault::Vault;
use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle};
use std::path::Path;

/// Domain used when deriving the share-signing bundle from the master seed.
/// Must match the domain used in `shard`/`recover`/`export`.
const SHARE_SIGNING_DOMAIN: &str = "origin-secrets/share/v1";

/// Verify a vault or share.
///
/// - `--vault-path`: decrypts the vault using the supplied passphrase,
///   re-derives its fingerprint, and confirms the audit log is present.
///   Returns `Ok(())` when integrity holds, otherwise an error.
/// - `--share`: performs full hybrid-signature verification of a share when a
///   vault is available (the master seed lets us derive the signing bundle and
///   check the Ed25519 + Falcon-1024 signature over the share data). Falls back
///   to structural validation when no vault is supplied.
pub fn cmd_verify(
    args: VerifyArgs,
    vault_path: &Path,
    passphrase: &str,
    json: bool,
) -> Result<(), Error> {
    if let Some(path) = &args.share {
        // Resolve a vault for full cryptographic verification, preferring the
        // share's OWN source vault (the vault living beside the share file:
        // shares are written to `<vault_dir>/shares/share_<n>.json`, so the
        // vault is the grandparent of the share file). Verifying a share against
        // its source vault is always correct — the share was signed by that
        // vault's master seed. Only when no adjacent source vault exists (an
        // exported/moved share) do we fall back to an explicitly supplied vault
        // (`--vault-path` or the global `-V`), which lets an operator name the
        // originating vault. Falls back to structural-only — with a clear
        // warning — when neither is available.
        let source_vault = path
            .parent()
            .and_then(|shares_dir| shares_dir.parent())
            .map(|vault_dir| vault_dir.join("secrets.vault"));

        if let Some(src) = &source_vault {
            if src.exists() {
                return verify_share(path, Some(src), passphrase, json);
            }
        }

        // No adjacent source vault: try an explicitly supplied vault.
        if let Some(explicit) = &args.vault_path {
            if explicit.exists() {
                return verify_share(path, Some(explicit), passphrase, json);
            }
        }
        if vault_path.exists() {
            return verify_share(path, Some(vault_path), passphrase, json);
        }

        // No candidate vault found: structural-only validation with a clear,
        // actionable message (never imply the user did something wrong when a
        // vault simply wasn't supplied).
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "command": "verify",
                    "target": "share",
                    "share": 0,
                    "verified": false,
                    "method": "structural",
                    "warning": "no vault available for cryptographic verification; supply -V <vault> (or --vault-path) or place the share beside its source vault, or use `recover` for a full check",
                })
            );
        } else {
            println!(
                "Cryptographic verification skipped: no vault available. Supply -V <vault> (or --vault-path), keep the share beside its source vault, or use `recover` for a full check."
            );
        }
        return verify_share(path, None, passphrase, json);
    }

    if let Some(path) = &args.vault_path {
        return verify_vault(path, passphrase, json, args.recovery_log.is_some());
    }

    // Default: verify the resolved default vault if it exists.
    if vault_path.exists() {
        return verify_vault(vault_path, passphrase, json, args.recovery_log.is_some());
    }

    Err(Error::VaultNotFound(vault_path.to_path_buf()))
}

/// Decrypt and integrity-check a vault file.
fn verify_vault(
    path: &Path,
    passphrase: &str,
    json: bool,
    recovery_log: bool,
) -> Result<(), Error> {
    let raw =
        std::fs::read_to_string(path).map_err(|_| Error::VaultNotFound(path.to_path_buf()))?;
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

    // --recovery-log: confirm the vault carries at least one Recover audit
    // entry (i.e. it was rebuilt from shares at some point). This makes the
    // previously-dead flag meaningful.
    if recovery_log {
        let has_recover = vault_data
            .audit_log
            .iter()
            .any(|e| matches!(e.operation, crate::audit::Operation::Recover { .. }));
        if !has_recover {
            return Err(Error::AuditLogNotFound);
        }
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "command": "verify",
                    "target": "recovery-log",
                    "vault": path.display().to_string(),
                    "recovery_entries_present": true,
                })
            );
        } else {
            println!("Recovery log present in vault {}.", path.display());
        }
        return Ok(());
    }

    // A fresh vault (init'd, never sharded/exported) has an empty audit log.
    // That is a valid state, not corruption — only report it, don't fail.
    let audit_entries = vault_data.audit_log.len();
    if audit_entries == 0 && !vault_data.master_seed.is_empty() {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "command": "verify",
                    "target": "vault",
                    "vault": path.display().to_string(),
                    "audit_entries": 0,
                    "seed_length": vault_data.master_seed.len(),
                    "note": "fresh vault, no audit entries yet",
                })
            );
        } else {
            println!(
                "Vault OK (fresh): seed length {} bytes, no audit entries yet.",
                vault_data.master_seed.len()
            );
        }
        return Ok(());
    }

    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "verify",
                "target": "vault",
                "vault": path.display().to_string(),
                "audit_entries": audit_entries,
                "seed_length": vault_data.master_seed.len(),
            })
        );
    } else {
        println!(
            "Vault OK: {} audit entries, seed length {} bytes.",
            audit_entries,
            vault_data.master_seed.len()
        );
    }
    Ok(())
}

/// Structural + (when a vault is available) cryptographic validation of a share.
///
/// When `vault` is `Some`, the master seed is recovered from the vault and used
/// to derive the share-signing bundle; the Ed25519 + Falcon-1024 hybrid
/// signature over the share data is then verified. When `vault` is `None`, only
/// structural validation is performed (a standalone share cannot be
/// cryptographically verified without the master seed).
fn verify_share(
    path: &Path,
    vault: Option<&Path>,
    passphrase: &str,
    json: bool,
) -> Result<(), Error> {
    let raw = std::fs::read_to_string(path).map_err(|_| Error::ShareNotFound {
        share_number: 0,
        path: path.to_path_buf(),
    })?;
    let share: Share = serde_json::from_str(&raw).map_err(|_| Error::ShareCorrupted {
        share_number: 0,
        path: path.to_path_buf(),
    })?;

    if share.share_data.is_empty() {
        return Err(Error::ShareCorrupted {
            share_number: share.share_number,
            path: path.to_path_buf(),
        });
    }
    if share.signature.ed25519.is_empty() || share.signature.falcon1024.is_empty() {
        return Err(Error::ShareCorrupted {
            share_number: share.share_number,
            path: path.to_path_buf(),
        });
    }
    if share.threshold == 0 || share.total_shares == 0 || share.threshold > share.total_shares {
        // shares must support recovery: 1 <= threshold <= total
        return Err(Error::InvalidThreshold {
            threshold: share.threshold,
            total_shares: share.total_shares,
        });
    }

    // Full cryptographic verification when a vault is available.
    if let Some(vault_path) = vault {
        let bundle = derive_share_signer(vault_path, passphrase, share.share_number)?;
        // Exported shares sign share_data + recipient; original shares sign
        // share_data only. Match the signing behaviour of `export`/`shard`.
        let mut msg = share.share_data.clone();
        if let Some(recipient) = &share.recipient {
            msg.extend_from_slice(recipient.as_bytes());
        }
        Ed25519Falcon1024::verify(
            bundle.ed25519_pk(),
            bundle.falcon1024_pk(),
            &msg,
            &share
                .signature
                .to_sdk()
                .map_err(|e| Error::SignatureVerificationFailed(format!("{e:?}")))?,
        )
        .map_err(|_| Error::ShareVerificationFailed {
            share_number: share.share_number,
            details: "hybrid signature invalid".to_string(),
        })?;
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "command": "verify",
                    "target": "share",
                    "share": share.share_number,
                    "verified": true,
                    "method": "hybrid",
                })
            );
        } else {
            println!(
                "Share {} cryptographically verified (Ed25519 + Falcon-1024).",
                share.share_number
            );
        }
        return Ok(());
    }

    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "verify",
                "target": "share",
                "share": share.share_number,
                "verified": false,
                "method": "structural",
                "threshold": share.threshold,
                "total_shares": share.total_shares,
                "data_bytes": share.share_data.len(),
                "fingerprint": share.fingerprint,
            })
        );
    } else {
        println!(
            "Share {} structurally valid: threshold {}, total {}, {} bytes, fingerprint {}.",
            share.share_number,
            share.threshold,
            share.total_shares,
            share.share_data.len(),
            share.fingerprint
        );
        println!(
            "Cryptographic verification skipped (no vault available); supply -V <vault> or use `recover` for full check."
        );
    }
    Ok(())
}

/// Derive the share-signing bundle from a vault's master seed for verification.
fn derive_share_signer(
    vault_path: &Path,
    passphrase: &str,
    share_number: u8,
) -> Result<std::sync::Arc<HybridSigningKeyBundle>, Error> {
    let raw = std::fs::read_to_string(vault_path)
        .map_err(|_| Error::VaultNotFound(vault_path.to_path_buf()))?;
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
    let seed: &[u8; 32] = vault_data
        .master_seed
        .as_slice()
        .try_into()
        .map_err(|_| Error::CryptoError("vault master seed wrong length".to_string()))?;
    HybridSigningKeyBundle::from_seed_cached(seed, SHARE_SIGNING_DOMAIN)
        .map_err(|e| Error::SignatureVerificationFailed(format!("{e:?} (share {share_number})")))
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
            force: false,
        };
        cmd_shard(args, &vault_path, &passphrase, false).unwrap();

        let verify_args = VerifyArgs {
            vault_path: None,
            share: None,
            recovery_log: None,
        };
        let result = cmd_verify(verify_args, &vault_path, &passphrase, false);
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
            force: false,
        };
        cmd_shard(args, &vault_path, "verify-passphrase-test", false).unwrap();

        let verify_args = VerifyArgs {
            vault_path: None,
            share: None,
            recovery_log: None,
        };
        let result = cmd_verify(verify_args, &vault_path, "wrong-pass", false);
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
        let result = cmd_verify(verify_args, &missing, "x", false);
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
            force: false,
        };
        cmd_shard(args, &vault_path, &passphrase, false).unwrap();

        let share_path = dir.path().join("shares").join("share_001.json");
        let verify_args = VerifyArgs {
            vault_path: None,
            share: Some(share_path),
            recovery_log: None,
        };
        let result = cmd_verify(verify_args, &vault_path, &passphrase, false);
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
        let result = cmd_verify(verify_args, &dir.path().join("vault"), "x", false);
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
        let result = cmd_verify(verify_args, &dir.path().join("absent.vault"), "x", false);
        assert!(matches!(result, Err(Error::VaultNotFound(_))));
    }
}
