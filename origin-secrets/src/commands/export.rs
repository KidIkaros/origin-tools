//! Export-share command — package a share for handoff to a recipient.

use crate::cli::ExportArgs;
use crate::crypto::{decrypt_vault_data, derive_vault_key, EncryptedVault};
use crate::error::Error;
use crate::share::{HybridSignature, Share};
use crate::vault::Vault;
use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle};
use std::path::{Path, PathBuf};

/// Domain separation label — must match `shard` / `recover`.
const SHARE_SIGNING_DOMAIN: &str = "origin-secrets/share/v1";

/// Export a previously created share for delivery to its recipient.
///
/// Loads `<vault_dir>/shares/share_<n>.json`. When a `recipient` is supplied,
/// the share is cryptographically re-bound to that recipient: the vault is
/// decrypted, the master seed's signing bundle re-signs `share_data || recipient`
/// (hybrid Ed25519 + Falcon-1024), the recipient is stamped, and an `ExportShare`
/// audit entry is appended to the vault (re-encrypted). This gives the export a
/// non-repudiable, recipient-specific signature rather than bare metadata.
///
/// Without a recipient, the share is copied verbatim (annotation only).
pub fn cmd_export_share(
    args: ExportArgs,
    vault_path: &Path,
    passphrase: &str,
    json: bool,
) -> Result<Share, Error> {
    // Validate the share number is in range (1-based; 0 is never valid).
    if args.share == 0 {
        return Err(Error::ShareCorrupted {
            share_number: 0,
            path: args.out.clone(),
        });
    }
    let shares_dir = vault_path
        .parent()
        .map(|p| p.join("shares"))
        .unwrap_or_else(|| PathBuf::from("shares"));
    let share_path = shares_dir.join(format!("share_{:03}.json", args.share));

    let raw = std::fs::read_to_string(&share_path).map_err(|_| Error::ShareNotFound {
        share_number: args.share,
        path: share_path.clone(),
    })?;
    let mut share: Share = serde_json::from_str(&raw).map_err(|_| Error::ShareCorrupted {
        share_number: args.share,
        path: share_path.clone(),
    })?;

    if let Some(recipient) = &args.recipient {
        // Re-sign the share binding it to the recipient, and log the export.
        re_sign_for_recipient(vault_path, passphrase, &mut share, recipient)?;
        if !json {
            println!(
                "Re-signed share {} for recipient '{}' and logged the export.",
                args.share, recipient
            );
        }
    } else if !json {
        println!("Exported share {} (no recipient binding).", args.share);
    }

    let serialized =
        serde_json::to_string_pretty(&share).map_err(|e| Error::IoError(e.to_string()))?;
    // Refuse to clobber an existing output file unless --force is given.
    if !args.force && args.out.exists() {
        return Err(Error::FileAlreadyExists(args.out.clone()));
    }
    std::fs::write(&args.out, serialized).map_err(|e| Error::IoError(e.to_string()))?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "export-share",
                "share": args.share,
                "out": args.out.display().to_string(),
                "recipient": share.recipient,
            })
        );
    } else {
        println!(
            "Exported share {} to {} (recipient: {}).",
            args.share,
            args.out.display(),
            share.recipient.as_deref().unwrap_or("<none>")
        );
    }
    Ok(share)
}

/// Decrypt the vault, derive the seed's signing bundle, re-sign `share_data ||
/// recipient`, stamp the recipient, and append an `ExportShare` audit entry.
fn re_sign_for_recipient(
    vault_path: &Path,
    passphrase: &str,
    share: &mut Share,
    recipient: &str,
) -> Result<(), Error> {
    // Load + decrypt the vault to recover the master seed.
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
    let mut vault_data = decrypt_vault_data(&encrypted, &key)?;

    // Derive the same signing bundle used at shard time.
    let seed: &[u8; 32] = vault_data
        .master_seed
        .as_slice()
        .try_into()
        .map_err(|_| Error::CryptoError("vault master seed wrong length".to_string()))?;
    let bundle = HybridSigningKeyBundle::from_seed_cached(seed, SHARE_SIGNING_DOMAIN)
        .map_err(|e| Error::SignatureGenerationFailed(format!("{e:?}")))?;

    // Bind share_data + recipient into the signature.
    let mut msg = share.share_data.clone();
    msg.extend_from_slice(recipient.as_bytes());
    let sdk_sig: Ed25519Falcon1024 = bundle.sign_hybrid(&msg);
    share.signature = HybridSignature::from_sdk(&sdk_sig);
    share.recipient = Some(recipient.to_string());

    // Append the export audit entry and re-encrypt the vault.
    let entry = crate::audit::AuditEntry {
        entry_id: format!("export-{}", uuidish(&share.share_data)),
        operation: crate::audit::Operation::ExportShare {
            share_number: share.share_number,
            recipient: recipient.to_string(),
        },
        key_id: share.key_id.clone(),
        timestamp: now_iso(),
        operator: OPERATOR.to_string(),
        details: crate::audit::OperationDetails::Success {
            message: format!("Exported share {} to {}", share.share_number, recipient),
        },
        signature: HybridSignature::from_sdk(&sdk_sig),
    };
    vault_data.audit_log.push(entry);

    // Re-encrypt and write the vault back. Use a FRESH nonce: the key is
    // unchanged (same passphrase + salt), but XChaCha20-Poly1305 must never
    // reuse a (key, nonce) pair — reusing vault.nonce would leak the delta.
    let reencrypt_nonce: [u8; 24] = crate::crypto::random_array()?;
    let re_enc = crate::crypto::encrypt_vault_data(
        &vault_data,
        &key,
        vault.salt,
        reencrypt_nonce,
        vault.tier,
    )?;
    let updated = Vault {
        version: re_enc.version,
        created_at: re_enc.created_at.clone(),
        tier: re_enc.tier,
        fingerprint: re_enc.fingerprint.clone(),
        salt: re_enc.salt,
        nonce: re_enc.nonce,
        ciphertext: re_enc.ciphertext,
    };
    std::fs::write(
        vault_path,
        serde_json::to_string_pretty(&updated).map_err(|e| Error::IoError(e.to_string()))?,
    )
    .map_err(|e| Error::IoError(e.to_string()))?;
    Ok(())
}

/// Best-effort ISO-8601 UTC timestamp using only std.
fn now_iso() -> String {
    crate::observability::epoch_to_ymd_hms_now()
}

/// Operator recorded in audit entries for this command.
const OPERATOR: &str = "origin-secrets-cli";

/// Small deterministic-ish id from share bytes (avoids a uuid dependency).
fn uuidish(bytes: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    format!("{:016x}", h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ShardArgs;
    use crate::commands::shard::cmd_shard;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_vault(dir: &std::path::Path) -> (PathBuf, String) {
        use crate::crypto::{encrypt_vault_data, VaultData};
        use crate::vault::{MemoryTier, Vault};

        let passphrase = "export-passphrase";
        let salt = [9u8; 16];
        let nonce = [10u8; 24];
        let tier = MemoryTier::Standard;
        let key = derive_vault_key(passphrase.as_bytes(), &salt, tier).unwrap();
        let mut vd = VaultData::new();
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
            force: false,
        };
        cmd_shard(args, &vault_path, &passphrase, false).unwrap();

        let out = dir.path().join("exported_001.json");
        let export_args = ExportArgs {
            share: 1,
            out: out.clone(),
            recipient: Some("alice".to_string()),
            force: false,
        };
        let share = cmd_export_share(export_args, &vault_path, &passphrase, false).unwrap();
        assert_eq!(share.share_number, 1);
        assert_eq!(share.recipient.as_deref(), Some("alice"));

        // The written file should parse back with recipient + a signature.
        let written: Share = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(written.recipient.as_deref(), Some("alice"));
        assert_eq!(written.share_data, share.share_data);
        assert!(!written.signature.ed25519.is_empty());
        assert!(!written.signature.falcon1024.is_empty());

        // The vault must now carry an ExportShare audit entry.
        let raw = std::fs::read_to_string(&vault_path).unwrap();
        let vault: Vault = serde_json::from_str(&raw).unwrap();
        let enc = EncryptedVault {
            version: vault.version,
            created_at: vault.created_at.clone(),
            tier: vault.tier,
            fingerprint: vault.fingerprint.clone(),
            salt: vault.salt,
            nonce: vault.nonce,
            ciphertext: vault.ciphertext,
        };
        let vd = decrypt_vault_data(
            &enc,
            &derive_vault_key(passphrase.as_bytes(), &vault.salt, vault.tier).unwrap(),
        )
        .unwrap();
        assert!(vd
            .audit_log
            .iter()
            .any(|e| matches!(e.operation, crate::audit::Operation::ExportShare { .. })));
    }

    #[test]
    fn test_export_share_no_recipient() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase) = make_vault(dir.path());
        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
            force: false,
        };
        cmd_shard(args, &vault_path, &passphrase, false).unwrap();

        let out = dir.path().join("exported_002.json");
        let export_args = ExportArgs {
            share: 2,
            out,
            recipient: None,
            force: false,
        };
        let share = cmd_export_share(export_args, &vault_path, &passphrase, false).unwrap();
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
            force: false,
        };
        let result = cmd_export_share(export_args, &vault_path, "x", false);
        assert!(matches!(
            result,
            Err(Error::ShareNotFound {
                share_number: 9,
                ..
            })
        ));
    }

    #[test]
    fn test_export_resign_rejects_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase) = make_vault(dir.path());
        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
            force: false,
        };
        cmd_shard(args, &vault_path, &passphrase, false).unwrap();

        // Recipient export requires the vault passphrase; a wrong one fails.
        let out = dir.path().join("exported_003.json");
        let export_args = ExportArgs {
            share: 1,
            out,
            recipient: Some("bob".to_string()),
            force: false,
        };
        let result = cmd_export_share(export_args, &vault_path, "wrong-pass", false);
        assert!(matches!(result, Err(Error::VaultDecryptionFailed(_))));
    }
}
