//! Shard command — split a vault's master seed into K-of-N threshold shares.

use crate::audit::{AuditEntry, Operation, OperationDetails};
use crate::cli::ShardArgs;
use crate::crypto::{decrypt_vault_data, derive_vault_key, encrypt_vault_data, EncryptedVault};
use crate::error::Error;
use crate::share::{HybridSignature, Share};
use crate::vault::Vault;
use origin_crypto_sdk::error_correction::ReedSolomonCodec;
use origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle;
use std::path::{Path, PathBuf};

/// Domain separation label for share signatures.
const SHARE_SIGNING_DOMAIN: &str = "origin-secrets/share/v1";

/// Execute the `shard` command.
///
/// Decrypts the vault at `vault_path` using `passphrase`, splits the
/// master seed into `args.shares` Reed-Solomon shards with a recovery
/// threshold of `args.threshold`, signs each share with the hybrid
/// (Ed25519 + Falcon-1024) key bundle derived from the master seed, and
/// writes each share to `<vault_dir>/shares/share_<n>.json`. The vault's
/// audit log is appended with a `Shard` entry and re-encrypted.
pub fn cmd_shard(
    args: ShardArgs,
    vault_path: &Path,
    passphrase: &str,
    json: bool,
) -> Result<Vec<Share>, Error> {
    let threshold = args.threshold;
    let total = args.shares;

    // Validate label is non-empty.
    if args.key.trim().is_empty() {
        return Err(Error::CryptoError(
            "share label must not be empty (use --label <NAME>)".to_string(),
        ));
    }

    // Validate threshold semantics: 1 <= threshold <= total.
    if threshold == 0 || threshold > total {
        return Err(Error::InvalidThreshold {
            threshold,
            total_shares: total,
        });
    }

    // Load and decrypt the vault.
    let vault_json = std::fs::read_to_string(vault_path)
        .map_err(|_| Error::VaultNotFound(vault_path.to_path_buf()))?;
    let vault: Vault =
        serde_json::from_str(&vault_json).map_err(|e| Error::VaultCorrupted(e.to_string()))?;

    let key = derive_vault_key(passphrase.as_bytes(), &vault.salt, vault.tier)?;
    let encrypted_vault = EncryptedVault {
        version: vault.version,
        created_at: vault.created_at.clone(),
        tier: vault.tier,
        fingerprint: vault.fingerprint.clone(),
        salt: vault.salt,
        nonce: vault.nonce,
        ciphertext: vault.ciphertext.clone(),
    };
    let mut vault_data = decrypt_vault_data(&encrypted_vault, &key)?;

    // Split the 32-byte master seed with K-of-N erasure coding.
    // data_shards = threshold (K), parity_shards = total - threshold (N-K).
    let data_shards = threshold as usize;
    let parity_shards = (total - threshold) as usize;
    let codec = ReedSolomonCodec::new(data_shards, parity_shards);
    let shards = codec
        .encode_shards(&vault_data.master_seed)
        .map_err(|e| Error::CryptoError(format!("Reed-Solomon encode failed: {e}")))?;

    // Derive the hybrid signing bundle from the master seed (deterministic).
    let signer =
        HybridSigningKeyBundle::from_seed_cached(&vault_data.master_seed, SHARE_SIGNING_DOMAIN)
            .map_err(|e| Error::SignatureGenerationFailed(format!("{e:?}")))?;

    // Write each share file.
    let vault_dir = vault_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let shares_dir = vault_dir.join("shares");
    std::fs::create_dir_all(&shares_dir).map_err(|e| Error::IoError(e.to_string()))?;

    // C4: refuse to leave stale shares from a prior sharding behind. If the
    // shares dir already contains share files that are NOT part of this
    // generation's output set, fail closed so a later `recover` can't silently
    // pick up a share belonging to a different master seed.
    let expected: std::collections::HashSet<String> = (1..=total)
        .map(|n| format!("share_{:03}.json", n))
        .collect();
    for entry in std::fs::read_dir(&shares_dir).map_err(|e| Error::IoError(e.to_string()))? {
        let entry = entry.map_err(|e| Error::IoError(e.to_string()))?;
        let fname = entry.file_name().to_string_lossy().to_string();
        if fname.starts_with("share_") && fname.ends_with(".json") && !expected.contains(&fname) {
            if args.force {
                // Operator explicitly opted in: remove the stale share so the new
                // generation is the only source of truth.
                let _ = std::fs::remove_file(entry.path());
                continue;
            }
            return Err(Error::IoError(format!(
                "stale share file {}/{} from a previous sharding remains; remove it or use --force",
                shares_dir.display(),
                fname
            )));
        }
    }

    let timestamp = crate::observability::epoch_to_ymd_hms_now();

    let mut written = Vec::with_capacity(shards.len());
    for (i, shard_data) in shards.iter().enumerate() {
        let share_number = (i + 1) as u8;
        let fingerprint = blake3::hash(shard_data);
        let signature = HybridSignature::from_sdk(&signer.sign_hybrid(shard_data));

        let share = Share {
            version: 1,
            key_id: args.key.clone(),
            share_number,
            threshold,
            total_shares: total,
            share_data: shard_data.clone(),
            fingerprint: hex::encode(&fingerprint.as_bytes()[..4]),
            signature,
            created_at: timestamp.clone(),
            recipient: None,
        };

        let out_path = shares_dir.join(format!("share_{:03}.json", share_number));
        let serialized = serde_json::to_string_pretty(&share)
            .map_err(|e| Error::IoError(format!("serialize share: {e}")))?;
        std::fs::write(&out_path, serialized).map_err(|e| Error::IoError(e.to_string()))?;

        written.push(share);
    }

    // Append a Shard audit entry and re-encrypt the vault.
    let audit_entry = AuditEntry {
        entry_id: format!("shard-{}", timestamp),
        operation: Operation::Shard {
            threshold,
            total_shares: total,
        },
        key_id: args.key.clone(),
        timestamp: timestamp.clone(),
        operator: "origin-secrets-cli".to_string(),
        details: OperationDetails::Success {
            message: format!("Sharded master key into {total} shares (threshold {threshold})"),
        },
        signature: HybridSignature::from_sdk(&signer.sign_hybrid(b"audit:shard")),
    };
    vault_data.audit_log.push(audit_entry);

    // Re-encrypt the vault with a FRESH nonce. The key is unchanged (same
    // passphrase + salt), but XChaCha20-Poly1305 is a stream cipher and the
    // same (key, nonce) pair must never be reused — reusing vault.nonce would
    // be deterministic nonce reuse and leak the plaintext delta.
    let reencrypt_nonce: [u8; 24] = crate::crypto::random_array()?;
    let reencrypted =
        encrypt_vault_data(&vault_data, &key, vault.salt, reencrypt_nonce, vault.tier)?;
    let updated_vault = Vault {
        version: reencrypted.version,
        created_at: reencrypted.created_at,
        tier: reencrypted.tier,
        fingerprint: reencrypted.fingerprint.clone(),
        salt: reencrypted.salt,
        nonce: reencrypted.nonce,
        ciphertext: reencrypted.ciphertext,
    };
    let updated_json = serde_json::to_string_pretty(&updated_vault)
        .map_err(|e| Error::IoError(format!("serialize vault: {e}")))?;
    std::fs::write(vault_path, updated_json).map_err(|e| Error::IoError(e.to_string()))?;

    if json {
        let share_files: Vec<String> = written
            .iter()
            .map(|s| {
                shares_dir
                    .join(format!("share_{:03}.json", s.share_number))
                    .display()
                    .to_string()
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "shard",
                "key": args.key,
                "threshold": threshold,
                "total_shares": total,
                "share_files": share_files,
            })
        );
    } else {
        println!(
            "Sharded master key '{}' into {} shares (threshold {}).",
            args.key, total, threshold
        );
        println!("Share files written to: {}", shares_dir.display());
    }

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::VaultData;
    use crate::vault::MemoryTier;
    use tempfile::tempdir;

    /// Create a vault file in `dir` and return its path + the passphrase used.
    fn make_vault_in_dir(dir: &Path) -> (PathBuf, String, [u8; 16], [u8; 24], MemoryTier) {
        let passphrase = "demo-passphrase-for-testing-only";
        let tier = MemoryTier::Standard;
        let salt: [u8; 16] = [3u8; 16];
        let nonce: [u8; 24] = [4u8; 24];
        let key = derive_vault_key(passphrase.as_bytes(), &salt, tier).unwrap();

        let mut vault_data = VaultData::new();
        vault_data.master_seed = [42u8; 32];
        let encrypted = encrypt_vault_data(&vault_data, &key, salt, nonce, tier).unwrap();
        let vault = Vault {
            version: encrypted.version,
            created_at: encrypted.created_at,
            tier: encrypted.tier,
            fingerprint: encrypted.fingerprint.clone(),
            salt: encrypted.salt,
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
        };
        let vault_path = dir.join("secrets.vault");
        std::fs::write(&vault_path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();
        (vault_path, passphrase.to_string(), salt, nonce, tier)
    }

    /// Regression: re-encrypting the vault (e.g. on `shard`) must NOT reuse the
    /// original (key, nonce) pair. XChaCha20-Poly1305 is a stream cipher; reuse
    /// leaks the plaintext delta between the two ciphertexts. We assert the
    /// vault's nonce changes after a re-encrypt, and both versions still decrypt.
    #[test]
    fn test_shard_does_not_reuse_nonce() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase, _, _, _) = make_vault_in_dir(dir.path());

        // Capture the nonce right after init (make_vault_in_dir wrote it).
        let before: Vault = {
            let raw = std::fs::read_to_string(&vault_path).unwrap();
            serde_json::from_str(&raw).unwrap()
        };
        let nonce_before = before.nonce;

        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 4,
            force: false,
        };
        cmd_shard(args, &vault_path, &passphrase, false).unwrap();

        let after: Vault = {
            let raw = std::fs::read_to_string(&vault_path).unwrap();
            serde_json::from_str(&raw).unwrap()
        };
        let nonce_after = after.nonce;

        // Nonce must have changed (fresh random nonce on re-encrypt).
        assert_ne!(
            nonce_before, nonce_after,
            "vault nonce was reused on re-encrypt — nonce-reuse vulnerability"
        );

        // Both ciphertexts must be independently decryptable under the same key.
        let key = derive_vault_key(passphrase.as_bytes(), &before.salt, before.tier).unwrap();
        let dec_before = decrypt_vault_data(
            &EncryptedVault {
                version: before.version,
                created_at: before.created_at.clone(),
                tier: before.tier,
                fingerprint: before.fingerprint.clone(),
                salt: before.salt,
                nonce: before.nonce,
                ciphertext: before.ciphertext.clone(),
            },
            &key,
        );
        let dec_after = decrypt_vault_data(
            &EncryptedVault {
                version: after.version,
                created_at: after.created_at.clone(),
                tier: after.tier,
                fingerprint: after.fingerprint.clone(),
                salt: after.salt,
                nonce: after.nonce,
                ciphertext: after.ciphertext.clone(),
            },
            &key,
        );
        assert!(dec_before.is_ok(), "original ciphertext no longer decrypts");
        assert!(
            dec_after.is_ok(),
            "re-encrypted ciphertext does not decrypt"
        );
        // The re-encrypted vault should carry the new Shard audit entry.
        assert_eq!(dec_after.unwrap().audit_log.len(), 1);
    }

    #[test]
    fn test_shard_valid_3_of_5() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase, _, _, _) = make_vault_in_dir(dir.path());

        let args = ShardArgs {
            key: "master-key".to_string(),
            threshold: 3,
            shares: 5,
            force: false,
        };

        let shares = cmd_shard(args, &vault_path, &passphrase, false).unwrap();
        assert_eq!(shares.len(), 5);
        for (i, s) in shares.iter().enumerate() {
            assert_eq!(s.share_number, (i + 1) as u8);
            assert_eq!(s.threshold, 3);
            assert_eq!(s.total_shares, 5);
            assert_eq!(s.key_id, "master-key");
            assert!(!s.share_data.is_empty());
            assert!(!s.signature.ed25519.is_empty());
            assert!(!s.signature.falcon1024.is_empty());
        }

        for n in 1..=5 {
            let p = dir
                .path()
                .join("shares")
                .join(format!("share_{:03}.json", n));
            assert!(p.exists(), "missing share file {n}");
        }

        // Audit log now has a Shard entry.
        let vault_json = std::fs::read_to_string(&vault_path).unwrap();
        let vault: Vault = serde_json::from_str(&vault_json).unwrap();
        let key = derive_vault_key(passphrase.as_bytes(), &vault.salt, vault.tier).unwrap();
        let vd = decrypt_vault_data(
            &EncryptedVault {
                version: vault.version,
                created_at: vault.created_at.clone(),
                tier: vault.tier,
                fingerprint: vault.fingerprint.clone(),
                salt: vault.salt,
                nonce: vault.nonce,
                ciphertext: vault.ciphertext.clone(),
            },
            &key,
        )
        .unwrap();
        assert_eq!(vd.audit_log.len(), 1);
        assert!(matches!(
            vd.audit_log[0].operation,
            Operation::Shard {
                threshold: 3,
                total_shares: 5
            }
        ));
    }

    #[test]
    fn test_shard_empty_label_rejected() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase, _, _, _) = make_vault_in_dir(dir.path());
        let args = ShardArgs {
            key: "".to_string(),
            threshold: 2,
            shares: 3,
            force: false,
        };
        let result = cmd_shard(args, &vault_path, &passphrase, false);
        assert!(result.is_err(), "empty --label must be rejected");
        assert!(result.unwrap_err().to_string().contains("label"));
    }

    #[test]
    fn test_shard_threshold_zero_rejected() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase, _, _, _) = make_vault_in_dir(dir.path());
        let args = ShardArgs {
            key: "k".to_string(),
            threshold: 0,
            shares: 3,
            force: false,
        };
        let result = cmd_shard(args, &vault_path, &passphrase, false);
        assert!(matches!(
            result,
            Err(Error::InvalidThreshold { threshold: 0, .. })
        ));
    }

    #[test]
    fn test_shard_threshold_greater_than_total_rejected() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase, _, _, _) = make_vault_in_dir(dir.path());
        let args = ShardArgs {
            key: "k".to_string(),
            threshold: 5,
            shares: 3,
            force: false,
        };
        let result = cmd_shard(args, &vault_path, &passphrase, false);
        assert!(matches!(
            result,
            Err(Error::InvalidThreshold {
                threshold: 5,
                total_shares: 3
            })
        ));
    }

    #[test]
    fn test_shard_wrong_passphrase_fails() {
        let dir = tempdir().unwrap();
        let (vault_path, _, _, _, _) = make_vault_in_dir(dir.path());
        let args = ShardArgs {
            key: "k".to_string(),
            threshold: 2,
            shares: 3,
            force: false,
        };
        let result = cmd_shard(args, &vault_path, "wrong-passphrase", false);
        assert!(matches!(result, Err(Error::VaultDecryptionFailed(_))));
    }

    #[test]
    fn test_shard_missing_vault_fails() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.vault");
        let args = ShardArgs {
            key: "k".to_string(),
            threshold: 2,
            shares: 3,
            force: false,
        };
        let result = cmd_shard(args, &missing, "x", false);
        assert!(matches!(result, Err(Error::VaultNotFound(_))));
    }

    #[test]
    fn test_shard_recovers_seed_from_threshold() {
        use origin_crypto_sdk::error_correction::ReedSolomonCodec;

        let dir = tempdir().unwrap();
        let (vault_path, passphrase, _, _, _) = make_vault_in_dir(dir.path());
        let args = ShardArgs {
            key: "k".to_string(),
            threshold: 2,
            shares: 4,
            force: false,
        };
        let shares = cmd_shard(args, &vault_path, &passphrase, false).unwrap();
        assert_eq!(shares.len(), 4);

        // Any K=2 shards must reconstruct the original 32-byte master seed.
        // decode_shards expects the full N-length Option vec (data+parity),
        // with missing shards as None.
        let codec = ReedSolomonCodec::new(2, 2);
        let mut opts: Vec<Option<Vec<u8>>> =
            shares.iter().map(|s| Some(s.share_data.clone())).collect();
        // Drop the last two so only K=2 shards remain present.
        opts[2] = None;
        opts[3] = None;
        let recovered = codec.decode_shards(&opts, 32).unwrap();
        assert_eq!(recovered, vec![42u8; 32]);
    }
}
