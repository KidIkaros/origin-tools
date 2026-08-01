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
pub fn cmd_verify(args: VerifyArgs, vault_path: &Path, passphrase: &str) -> Result<(), Error> {
    if let Some(path) = &args.share {
        // Prefer full verification against the resolved default vault if present.
        if vault_path.exists() {
            return verify_share(path, Some(vault_path), passphrase);
        }
        return verify_share(path, None, passphrase);
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

/// Structural + (when a vault is available) cryptographic validation of a share.
///
/// When `vault` is `Some`, the master seed is recovered from the vault and used
/// to derive the share-signing bundle; the Ed25519 + Falcon-1024 hybrid
/// signature over the share data is then verified. When `vault` is `None`, only
/// structural validation is performed (a standalone share cannot be
/// cryptographically verified without the master seed).
fn verify_share(path: &Path, vault: Option<&Path>, passphrase: &str) -> Result<(), Error> {
    let raw = std::fs::read_to_string(path).map_err(|_| Error::ShareNotFound { share_number: 0 })?;
    let share: Share =
        serde_json::from_str(&raw).map_err(|e| Error::ShareCorrupted { share_number: 0 })?;

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

    // Full cryptographic verification when a vault is available.
    if let Some(vault_path) = vault {
        let bundle = derive_share_signer(vault_path, passphrase, share.share_number)?;
        Ed25519Falcon1024::verify(
            bundle.ed25519_pk(),
            bundle.falcon1024_pk(),
            &share.share_data,
            &share.signature.to_sdk().map_err(|e| {
                Error::SignatureVerificationFailed(format!("{e:?}"))
            })?,
        )
        .map_err(|_| Error::ShareVerificationFailed {
            share_number: share.share_number,
            details: "hybrid signature invalid".to_string(),
        })?;
        println!(
            "Share {} cryptographically verified (Ed25519 + Falcon-1024).",
            share.share_number
        );
        return Ok(());
    }

    println!(
        "Share {} structurally valid: threshold {}, total {}, {} bytes, fingerprint {}.",
        share.share_number,
        share.threshold,
        share.total_shares,
        share.share_data.len(),
        share.fingerprint
    );
    println!("Cryptographic verification skipped (no vault supplied); use `recover` for full check.");
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
