//! Revoke a share (P3.1) — mark a share number as revoked in the vault's
//! `revoked_shares` set. Once revoked, `recover` and `verify --share` reject
//! that share number without requiring a full re-shard. Audit history is
//! preserved and a `Revoke` entry is appended.

use crate::audit::{AuditEntry, Operation, OperationDetails};
use crate::cli::RevokeShareArgs;
use crate::crypto::{decrypt_vault_data, derive_vault_key, encrypt_vault_data, EncryptedVault};
use crate::error::Error;
use crate::share::HybridSignature;
use crate::vault::Vault;
use std::path::Path;

const OPERATOR: &str = "origin-secrets-cli";

/// Revoke a share number. Re-encrypts the vault at the same tier/salt/nonce
/// (the passphrase is unchanged) with the share number added to the revocation
/// set, and appends a `Revoke` audit entry.
pub fn cmd_revoke_share(
    args: RevokeShareArgs,
    vault_path: &Path,
    passphrase: &str,
    json: bool,
) -> Result<(), Error> {
    if args.share_number == 0 {
        return Err(Error::CryptoError(
            "share number must be in 1..=255".to_string(),
        ));
    }

    let raw = std::fs::read_to_string(vault_path)
        .map_err(|_| Error::VaultNotFound(vault_path.to_path_buf()))?;
    let vault: Vault =
        serde_json::from_str(&raw).map_err(|e| Error::VaultCorrupted(e.to_string()))?;
    let tier = vault.tier;
    let key = derive_vault_key(passphrase.as_bytes(), &vault.salt, tier)?;
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

    if vault_data.revoked_shares.contains(&args.share_number) {
        return Err(Error::CryptoError(format!(
            "share #{} is already revoked",
            args.share_number
        )));
    }
    vault_data.revoked_shares.insert(args.share_number);

    // Append the revocation record before re-encrypting.
    let timestamp = crate::observability::epoch_to_ymd_hms_now();
    let signer = origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle::from_seed_cached(
        &vault_data.master_seed,
        "origin-secrets/audit/v1",
    )
    .map_err(|e| Error::SignatureGenerationFailed(format!("{e:?}")))?;
    let audit_sig: origin_crypto_sdk::signing::hybrid::Ed25519Falcon1024 =
        signer.sign_hybrid(b"audit:revoke");
    let revoke_entry = AuditEntry {
        entry_id: format!("revoke-{}", timestamp),
        operation: Operation::Revoke {
            share_number: args.share_number,
        },
        key_id: "*".to_string(),
        timestamp: timestamp.clone(),
        operator: OPERATOR.to_string(),
        details: OperationDetails::Success {
            message: format!("Revoked share #{}", args.share_number),
        },
        signature: HybridSignature::from_sdk(&audit_sig),
    };
    vault_data.audit_log.push(revoke_entry);

    // Re-encrypt at the SAME salt/nonce/tier (passphrase unchanged).
    let reencrypted = encrypt_vault_data(&vault_data, &key, vault.salt, vault.nonce, tier)?;
    let updated_vault = Vault {
        version: reencrypted.version,
        created_at: reencrypted.created_at,
        tier: reencrypted.tier,
        fingerprint: reencrypted.fingerprint.clone(),
        salt: reencrypted.salt,
        nonce: reencrypted.nonce,
        ciphertext: reencrypted.ciphertext,
    };
    std::fs::write(
        vault_path,
        serde_json::to_string_pretty(&updated_vault).map_err(|e| Error::IoError(e.to_string()))?,
    )
    .map_err(|e| Error::IoError(e.to_string()))?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "revoke-share",
                "vault": vault_path.display().to_string(),
                "revoked_share": args.share_number,
                "revoked_total": vault_data.revoked_shares.len(),
                "audit_entries": vault_data.audit_log.len(),
            })
        );
    } else {
        println!(
            "Revoked share #{} in vault: {}",
            args.share_number,
            vault_path.display()
        );
        println!(
            "Total revoked shares: {}. Audit history preserved ({} entries).",
            vault_data.revoked_shares.len(),
            vault_data.audit_log.len()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::RevokeShareArgs;
    use crate::crypto::decrypt_vault_data;
    use crate::crypto::derive_vault_key;
    use crate::crypto::encrypt_vault_data;
    use crate::crypto::EncryptedVault;
    use crate::crypto::VaultData;
    use crate::vault::Vault;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn build_vault(dir: &std::path::Path, pw: &str, seed: [u8; 32]) -> PathBuf {
        let path = dir.join("secrets.vault");
        let salt: [u8; 16] = [9u8; 16];
        let nonce: [u8; 24] = [10u8; 24];
        let tier = crate::vault::MemoryTier::Standard;
        let key = derive_vault_key(pw.as_bytes(), &salt, tier).unwrap();
        let mut vd = VaultData::new();
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
        std::fs::write(&path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();
        path
    }

    #[test]
    fn test_revoke_adds_to_revoked_set() {
        let dir = tempdir().unwrap();
        let pw = "revoke-pass-12";
        let vault_path = build_vault(dir.path(), pw, [7u8; 32]);

        cmd_revoke_share(RevokeShareArgs { share_number: 2 }, &vault_path, pw, false).unwrap();

        // Re-read and confirm the revocation is persisted (inside the encrypted vault).
        let raw = std::fs::read_to_string(&vault_path).unwrap();
        let v: Vault = serde_json::from_str(&raw).unwrap();
        let key = derive_vault_key(pw.as_bytes(), &v.salt, v.tier).unwrap();
        let enc = EncryptedVault {
            version: v.version,
            created_at: v.created_at.clone(),
            tier: v.tier,
            fingerprint: v.fingerprint.clone(),
            salt: v.salt,
            nonce: v.nonce,
            ciphertext: v.ciphertext,
        };
        let vd = decrypt_vault_data(&enc, &key).unwrap();
        assert!(vd.revoked_shares.contains(&2));
    }

    #[test]
    fn test_revoke_rejects_zero() {
        let dir = tempdir().unwrap();
        let vault_path = build_vault(dir.path(), "revoke-pass-12", [7u8; 32]);
        let r = cmd_revoke_share(
            RevokeShareArgs { share_number: 0 },
            &vault_path,
            "revoke-pass-12",
            false,
        );
        assert!(r.is_err());
    }

    #[test]
    fn test_revoke_already_revoked_errors() {
        let dir = tempdir().unwrap();
        let pw = "revoke-pass-12";
        let vault_path = build_vault(dir.path(), pw, [7u8; 32]);
        cmd_revoke_share(RevokeShareArgs { share_number: 3 }, &vault_path, pw, false).unwrap();
        let r = cmd_revoke_share(RevokeShareArgs { share_number: 3 }, &vault_path, pw, false);
        assert!(r.is_err());
    }
}
