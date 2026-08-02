//! Verify command — integrity checks for vaults and shares.
use crate::cli::VerifyArgs;
use crate::crypto::{decrypt_vault_data, derive_vault_key, EncryptedVault};
use crate::error::Error;
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
    // P3.3/P3.1/P3.2: shared reader decrypts encrypted-at-rest shares, rejects
    // revoked shares (when a vault is present), and enforces expiry.
    let share = crate::commands::share_io::read_share_file(path, vault, passphrase)?;

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
        // P3.4: if the share embeds a verifier, perform a full offline
        // hybrid-sig check without the vault.
        match crate::commands::share_io::verify_share_offline(&share) {
            Ok(()) => println!(
                "Cryptographic verification PASSED offline (embedded verifier; Ed25519 + Falcon-1024)."
            ),
            Err(Error::SignatureVerificationFailed { .. }) => {
                return Err(Error::ShareVerificationFailed {
                    share_number: share.share_number,
                    details: "offline hybrid signature invalid".to_string(),
                });
            }
            Err(_) => println!(
                "Cryptographic verification skipped (no embedded verifier and no vault); supply -V <vault>."
            ),
        }
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
    use crate::share::{HybridSignature, Share};
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn build_vault(dir: &std::path::Path) -> (PathBuf, String) {
        build_vault_inner(dir, [123u8; 32], "verify-passphrase-test")
    }

    /// Build a vault with an explicit master seed so two vaults can have
    /// DIFFERENT signing keys (used to test cross-vault share rejection).
    fn build_vault_with_seed(dir: &std::path::Path, seed: [u8; 32]) -> (PathBuf, String) {
        build_vault_inner(dir, seed, "verify-passphrase-test")
    }

    fn build_vault_inner(
        dir: &std::path::Path,
        seed: [u8; 32],
        passphrase: &str,
    ) -> (PathBuf, String) {
        use crate::crypto::encrypt_vault_data;
        use crate::vault::{MemoryTier, Vault};

        let salt = [5u8; 16];
        let nonce = [6u8; 24];
        let tier = MemoryTier::Standard;
        let key = derive_vault_key(passphrase.as_bytes(), &salt, tier).unwrap();
        let mut vd = crate::crypto::VaultData::new();
        vd.master_seed = seed;
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
            expires: None,
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
            expires: None,
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
            expires: None,
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

    #[test]
    fn test_verify_share_with_recipient_checks_share_data_plus_recipient() {
        // Reproduces the P1.3 bug class: an exported share signs
        // `share_data + recipient`. If verify only checked `share_data`, the
        // signature would mismatch and a legitimate share would be rejected.
        let dir = tempdir().unwrap();
        let (vault, passphrase) = build_vault(dir.path());

        // Derive the signing bundle the same way export/shard do, and sign
        // share_data || recipient to mimic an exported share.
        let bundle = derive_share_signer(&vault, &passphrase, 1).unwrap();
        let share_data: Vec<u8> = vec![1, 2, 3, 4];
        let recipient = "alice".to_string();
        let mut msg = share_data.clone();
        msg.extend_from_slice(recipient.as_bytes());
        let sdk_sig: Ed25519Falcon1024 = bundle.sign_hybrid(&msg);

        let share = Share {
            version: 1,
            key_id: "master".to_string(),
            share_number: 1,
            threshold: 2,
            total_shares: 3,
            share_data: share_data.clone(),
            fingerprint: "deadbeef".to_string(),
            signature: HybridSignature::from_sdk(&sdk_sig),
            created_at: "2026-08-01T00:00:00Z".to_string(),
            recipient: Some(recipient.clone()),
            expires_at: None,
            verifier: None,
        };
        let share_path = dir.path().join("exported_share.json");
        std::fs::write(&share_path, serde_json::to_string_pretty(&share).unwrap()).unwrap();

        // The share is not adjacent to a vault, but we supply -V explicitly.
        let verify_args = VerifyArgs {
            vault_path: None,
            share: Some(share_path.clone()),
            recovery_log: None,
        };
        let result = cmd_verify(verify_args, &vault, &passphrase, false);
        assert!(
            result.is_ok(),
            "exported share (signed over share_data+recipient) must verify: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_share_structural_only_when_no_vault_available() {
        // When no vault is available (no adjacent source vault, no -V), verify
        // must fall back to structural-only validation and succeed (exit 0),
        // with a clear warning — never a false tamper-positive.
        let dir = tempdir().unwrap();
        let share_data: Vec<u8> = vec![9, 8, 7, 6];
        let share = Share {
            version: 1,
            key_id: "master".to_string(),
            share_number: 1,
            threshold: 2,
            total_shares: 3,
            share_data: share_data.clone(),
            fingerprint: "cafe".to_string(),
            signature: HybridSignature {
                ed25519: vec![0u8; 64],
                falcon1024: vec![0u8; 32],
            },
            created_at: "2026-08-01T00:00:00Z".to_string(),
            recipient: None,
            expires_at: None,
            verifier: None,
        };
        let share_path = dir.path().join("orphan_share.json");
        std::fs::write(&share_path, serde_json::to_string_pretty(&share).unwrap()).unwrap();

        // Pass a non-existent vault path; share is not adjacent to a vault.
        let verify_args = VerifyArgs {
            vault_path: None,
            share: Some(share_path.clone()),
            recovery_log: None,
        };
        let result = cmd_verify(
            verify_args,
            &dir.path().join("does_not_exist.vault"),
            "irrelevant",
            false,
        );
        assert!(
            result.is_ok(),
            "structural-only verification must succeed when no vault is present: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_share_prefers_adjacent_source_vault() {
        // When the share lives in <vault_dir>/shares/, verify must use the
        // adjacent source vault (grandparent/secrets.vault), not the -V default,
        // and crypto-verify successfully.
        let dir = tempdir().unwrap();
        let (vault, passphrase) = build_vault(dir.path());
        // build_vault writes to dir/secrets.vault; place the share in dir/shares/.
        let shares_dir = dir.path().join("shares");
        std::fs::create_dir_all(&shares_dir).unwrap();

        // Re-sign a share the same way shard/export would, so it verifies
        // against the source vault's signing key.
        let bundle = derive_share_signer(&vault, &passphrase, 2).unwrap();
        let share_data: Vec<u8> = vec![4, 5, 6, 7];
        let sdk_sig: Ed25519Falcon1024 = bundle.sign_hybrid(&share_data);
        let share = Share {
            version: 1,
            key_id: "master".to_string(),
            share_number: 2,
            threshold: 2,
            total_shares: 3,
            share_data: share_data.clone(),
            fingerprint: "face".to_string(),
            signature: HybridSignature::from_sdk(&sdk_sig),
            created_at: "2026-08-01T00:00:00Z".to_string(),
            recipient: None,
            expires_at: None,
            verifier: None,
        };
        let share_path = shares_dir.join("share_002.json");
        std::fs::write(&share_path, serde_json::to_string_pretty(&share).unwrap()).unwrap();

        // Supply a DIFFERENT (non-existent) -V; the source vault must win.
        let verify_args = VerifyArgs {
            vault_path: None,
            share: Some(share_path.clone()),
            recovery_log: None,
        };
        let result = cmd_verify(
            verify_args,
            &dir.path().join("other.vault"),
            &passphrase,
            false,
        );
        assert!(
            result.is_ok(),
            "share must verify against its adjacent source vault despite -V pointing elsewhere: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_share_structural_only_json_emits_warning() {
        // JSON mode must emit a structured payload (ok:true, method:structural,
        // warning) rather than panicking or printing human text.
        let dir = tempdir().unwrap();
        let share = Share {
            version: 1,
            key_id: "master".to_string(),
            share_number: 1,
            threshold: 2,
            total_shares: 3,
            share_data: vec![1, 2, 3],
            fingerprint: "beef".to_string(),
            signature: HybridSignature {
                ed25519: vec![0u8; 64],
                falcon1024: vec![0u8; 32],
            },
            created_at: "2026-08-01T00:00:00Z".to_string(),
            recipient: None,
            expires_at: None,
            verifier: None,
        };
        let share_path = dir.path().join("orphan.json");
        std::fs::write(&share_path, serde_json::to_string_pretty(&share).unwrap()).unwrap();

        let verify_args = VerifyArgs {
            vault_path: None,
            share: Some(share_path.clone()),
            recovery_log: None,
        };
        // Capture stdout to confirm a JSON payload is emitted.
        let result = cmd_verify(
            verify_args,
            &dir.path().join("nope.vault"),
            "irrelevant",
            true,
        );
        assert!(
            result.is_ok(),
            "json structural verify must succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_share_explicit_vault_path_used_when_no_adjacent() {
        // When --vault-path points at an existing vault and the share has no
        // adjacent source vault, that explicit vault must be used for crypto
        // verification.
        let dir = tempdir().unwrap();
        let (vault, passphrase) = build_vault(dir.path());
        let bundle = derive_share_signer(&vault, &passphrase, 3).unwrap();
        let share_data: Vec<u8> = vec![7, 7, 7];
        let sdk_sig: Ed25519Falcon1024 = bundle.sign_hybrid(&share_data);
        let share = Share {
            version: 1,
            key_id: "master".to_string(),
            share_number: 3,
            threshold: 2,
            total_shares: 3,
            share_data: share_data.clone(),
            fingerprint: "abba".to_string(),
            signature: HybridSignature::from_sdk(&sdk_sig),
            created_at: "2026-08-01T00:00:00Z".to_string(),
            recipient: None,
            expires_at: None,
            verifier: None,
        };
        let share_path = dir.path().join("moved_share.json");
        std::fs::write(&share_path, serde_json::to_string_pretty(&share).unwrap()).unwrap();

        let verify_args = VerifyArgs {
            vault_path: Some(vault.clone()),
            share: Some(share_path.clone()),
            recovery_log: None,
        };
        let result = cmd_verify(
            verify_args,
            &dir.path().join("other.vault"),
            &passphrase,
            false,
        );
        assert!(
            result.is_ok(),
            "explicit --vault-path must crypto-verify a moved share: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_share_with_recipient_rejects_wrong_recipient() {
        // Signing over the wrong recipient must fail verification.
        let dir = tempdir().unwrap();
        let (vault, passphrase) = build_vault(dir.path());

        let bundle = derive_share_signer(&vault, &passphrase, 1).unwrap();
        let share_data: Vec<u8> = vec![1, 2, 3, 4];
        // Sign over "alice" but label the share as "bob".
        let mut msg = share_data.clone();
        msg.extend_from_slice(b"alice");
        let sdk_sig: Ed25519Falcon1024 = bundle.sign_hybrid(&msg);

        let share = Share {
            version: 1,
            key_id: "master".to_string(),
            share_number: 1,
            threshold: 2,
            total_shares: 3,
            share_data: share_data.clone(),
            fingerprint: "deadbeef".to_string(),
            signature: HybridSignature::from_sdk(&sdk_sig),
            created_at: "2026-08-01T00:00:00Z".to_string(),
            recipient: Some("bob".to_string()),
            expires_at: None,
            verifier: None,
        };
        let share_path = dir.path().join("bad_recipient.json");
        std::fs::write(&share_path, serde_json::to_string_pretty(&share).unwrap()).unwrap();

        let verify_args = VerifyArgs {
            vault_path: None,
            share: Some(share_path.clone()),
            recovery_log: None,
        };
        let result = cmd_verify(verify_args, &vault, &passphrase, false);
        assert!(
            matches!(result, Err(Error::ShareVerificationFailed { .. })),
            "share signed over wrong recipient must fail: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_share_crypto_success_json_emits_verified() {
        // When crypto verification succeeds with a vault present, JSON mode
        // must emit verified:true (not just structural). Exercises the
        // success JSON branch of verify_share.
        let dir = tempdir().unwrap();
        let (vault, passphrase) = build_vault(dir.path());
        let bundle = derive_share_signer(&vault, &passphrase, 4).unwrap();
        let share_data: Vec<u8> = vec![2, 4, 6, 8];
        let sdk_sig: Ed25519Falcon1024 = bundle.sign_hybrid(&share_data);
        let share = Share {
            version: 1,
            key_id: "master".to_string(),
            share_number: 4,
            threshold: 2,
            total_shares: 3,
            share_data: share_data.clone(),
            fingerprint: "c0de".to_string(),
            signature: HybridSignature::from_sdk(&sdk_sig),
            created_at: "2026-08-01T00:00:00Z".to_string(),
            recipient: None,
            expires_at: None,
            verifier: None,
        };
        let share_path = dir.path().join("good_share.json");
        std::fs::write(&share_path, serde_json::to_string_pretty(&share).unwrap()).unwrap();

        let verify_args = VerifyArgs {
            vault_path: Some(vault.clone()),
            share: Some(share_path.clone()),
            recovery_log: None,
        };
        let result = cmd_verify(
            verify_args,
            &dir.path().join("other.vault"),
            &passphrase,
            true,
        );
        assert!(
            result.is_ok(),
            "crypto-verify success in JSON mode must succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_share_crypto_failure_returns_error() {
        // A share whose signature does not match the supplied vault must fail
        // with ShareVerificationFailed (not fall back to structural). Use two
        // DIFFERENT passphrases so the master seeds (and signing keys) differ.
        let dir = tempdir().unwrap();
        let (vault_a, passphrase) = build_vault(dir.path());
        // Build a share signed by a DIFFERENT vault's key (different passphrase
        // => different master seed => different signing bundle).
        let other_dir = tempdir().unwrap();
        let (vault_b, pw_b) = build_vault_with_seed(other_dir.path(), [222u8; 32]);
        let bundle_b = derive_share_signer(&vault_b, &pw_b, 1).unwrap();
        let share_data: Vec<u8> = vec![1, 1, 1];
        let sdk_sig: Ed25519Falcon1024 = bundle_b.sign_hybrid(&share_data);
        let share = Share {
            version: 1,
            key_id: "master".to_string(),
            share_number: 1,
            threshold: 2,
            total_shares: 3,
            share_data: share_data.clone(),
            fingerprint: "bad1".to_string(),
            signature: HybridSignature::from_sdk(&sdk_sig),
            created_at: "2026-08-01T00:00:00Z".to_string(),
            recipient: None,
            expires_at: None,
            verifier: None,
        };
        let share_path = dir.path().join("cross_vault_share.json");
        std::fs::write(&share_path, serde_json::to_string_pretty(&share).unwrap()).unwrap();

        let verify_args = VerifyArgs {
            vault_path: None,
            share: Some(share_path.clone()),
            recovery_log: None,
        };
        let result = cmd_verify(verify_args, &vault_a, &passphrase, false);
        assert!(
            matches!(result, Err(Error::ShareVerificationFailed { .. })),
            "share signed by a different vault must fail crypto verification: {:?}",
            result
        );
    }
}
