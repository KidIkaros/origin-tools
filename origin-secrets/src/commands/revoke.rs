//! Revoke a share (P3.1) — mark a share number as revoked in the vault's
//! `revoked_shares` set. Once revoked, `recover` and `verify --share` reject
//! that share number without requiring a full re-shard. Audit history is
//! preserved and a `Revoke` entry is appended.

use crate::audit::{AuditEntry, Operation, OperationDetails};
use crate::cli::RevokeShareArgs;
use crate::constant_time::{u8_eq, u8_in_hashset};
use crate::error::Error;
use crate::share::HybridSignature;
use crate::vault_handle::VaultHandle;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct RevokeResponse {
    ok: bool,
    command: &'static str,
    vault: String,
    revoked_share: u8,
    revoked_total: usize,
    audit_entries: usize,
}

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
    // Constant-time check for share_number == 0 to prevent timing side-channels
    if u8_eq(args.share_number, 0) {
        return Err(Error::CryptoError(
            "share number must be in 1..=255".to_string(),
        ));
    }

    let mut handle = VaultHandle::open(vault_path, passphrase)?;

    // Constant-time check for revoked share to prevent timing side-channels
    if u8_in_hashset(args.share_number, &handle.data().revoked_shares) {
        return Err(Error::CryptoError(format!(
            "share #{} is already revoked",
            args.share_number
        )));
    }
    handle.data_mut().revoked_shares.insert(args.share_number);

    // Append the revocation record before re-encrypting.
    let timestamp = crate::observability::epoch_to_ymd_hms_now();
    let seed = handle.data().master_seed;
    let signer = origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle::from_seed_cached(
        &seed,
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
    handle.data_mut().audit_log.push(revoke_entry);
    // VaultHandle.save() preserves the key/salt and generates a fresh nonce.
    handle.save()?;
    let revoked_total = handle.data().revoked_shares.len();
    let audit_entries = handle.data().audit_log.len();

    if json {
        let response = RevokeResponse {
            ok: true,
            command: "revoke-share",
            vault: vault_path.display().to_string(),
            revoked_share: args.share_number,
            revoked_total,
            audit_entries,
        };
        crate::commands::output::print_json(&response, "revoke-share")?;
    } else {
        println!(
            "Revoked share #{} in vault: {}",
            args.share_number,
            vault_path.display()
        );
        println!(
            "Total revoked shares: {}. Audit history preserved ({} entries).",
            revoked_total, audit_entries
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
            ciphertext: enc.ciphertext.clone(),
        };
        std::fs::write(&path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();
        path
    }

    #[test]
    fn test_revoke_does_not_reuse_nonce() {
        // Regression for the H1 nonce-reuse bug class: revoke re-encrypts the
        // vault under the SAME key (passphrase unchanged) and must use a FRESH
        // nonce, not the original one, or it leaks the audit-log delta.
        let dir = tempdir().unwrap();
        let pw = "revoke-pass-12";
        let vault_path = build_vault(dir.path(), pw, [7u8; 32]);

        let before: Vault = {
            let raw = std::fs::read_to_string(&vault_path).unwrap();
            serde_json::from_str(&raw).unwrap()
        };
        let nonce_before = before.nonce;

        cmd_revoke_share(RevokeShareArgs { share_number: 2 }, &vault_path, pw, false).unwrap();

        let after: Vault = {
            let raw = std::fs::read_to_string(&vault_path).unwrap();
            serde_json::from_str(&raw).unwrap()
        };
        // Nonce MUST change on re-encrypt (same key).
        assert_ne!(
            after.nonce, nonce_before,
            "revoke-share reused the vault nonce — H1 regression"
        );
        // Both the old and new ciphertexts must still decrypt under the same key.
        let key = derive_vault_key(pw.as_bytes(), &before.salt, before.tier).unwrap();
        let enc_before = EncryptedVault {
            version: before.version,
            created_at: before.created_at.clone(),
            tier: before.tier,
            fingerprint: before.fingerprint.clone(),
            salt: before.salt,
            nonce: before.nonce,
            ciphertext: before.ciphertext.clone(),
        };
        let enc_after = EncryptedVault {
            version: after.version,
            created_at: after.created_at.clone(),
            tier: after.tier,
            fingerprint: after.fingerprint.clone(),
            salt: after.salt,
            nonce: after.nonce,
            ciphertext: after.ciphertext.clone(),
        };
        assert!(decrypt_vault_data(&enc_before, &key).is_ok());
        assert!(decrypt_vault_data(&enc_after, &key).is_ok());
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
            ciphertext: v.ciphertext.clone(),
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
