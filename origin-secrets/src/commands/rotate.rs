//! Rotate passphrase command (P2.1) — re-encrypt the vault under a new
//! passphrase without re-initializing, optionally changing the security tier
//! (P2.5). Audit history is preserved and a `RotatePassphrase` entry is
//! appended.

use crate::audit::{AuditEntry, Operation, OperationDetails};
use crate::cli::RotatePassphraseArgs;
use crate::error::Error;
use crate::share::HybridSignature;
use crate::vault::parse_tier;
use crate::vault_handle::VaultHandle;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct RotateResponse {
    ok: bool,
    command: &'static str,
    vault: String,
    from_tier: &'static str,
    to_tier: &'static str,
    audit_entries: usize,
}

const OPERATOR: &str = "origin-secrets-cli";

/// Rotate the vault passphrase (and optionally the tier).
///
/// Decrypts the vault with the *current* passphrase, re-encrypts `VaultData`
/// under the *new* passphrase with a FRESH salt + nonce (forward secrecy) at
/// the requested tier, carries the existing audit log forward, and appends a
/// `RotatePassphrase` entry. The master seed and keys are untouched.
pub fn cmd_rotate_passphrase(
    args: RotatePassphraseArgs,
    vault_path: &Path,
    current_passphrase: &str,
    json: bool,
) -> Result<(), Error> {
    // New passphrase: same resolver policy as every other command, but read
    // from --new-passphrase-file (so the old passphrase stays on -p).
    let new_passphrase = crate::resolve_passphrase(args.new_passphrase_file.as_deref(), false)?;
    if new_passphrase.len() < 12 {
        return Err(Error::PassphraseTooWeak { min_length: 12 });
    }

    // Read + decrypt with the CURRENT passphrase.
    let mut handle = VaultHandle::open(vault_path, current_passphrase)?;
    let old_tier = handle.tier;

    // Resolve the target tier. Default: keep current tier (pure passphrase
    let target_tier = parse_tier(&args.tier).map_err(Error::CryptoError)?;

    // Append the rotation record BEFORE re-encrypting so it lands in history.
    let timestamp = crate::observability::epoch_to_ymd_hms_now();
    // Sign the audit entry with the vault's own hybrid key (derived from the
    // master seed), consistent with how shard/export sign their entries.
    let signer = origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle::from_seed_cached(
        &handle.data().master_seed,
        "origin-secrets/audit/v1",
    )
    .map_err(|e| Error::SignatureGenerationFailed(format!("{e:?}")))?;
    let audit_sig: origin_crypto_sdk::signing::hybrid::Ed25519Falcon1024 =
        signer.sign_hybrid(b"audit:rotate");
    let rotate_entry = AuditEntry {
        entry_id: format!("rotate-{timestamp}"),
        operation: Operation::RotatePassphrase {
            from_tier: old_tier.label().to_string(),
            to_tier: target_tier.label().to_string(),
        },
        key_id: "*".to_string(),
        timestamp: timestamp.clone(),
        operator: OPERATOR.to_string(),
        details: OperationDetails::Success {
            message: format!(
                "Rotated passphrase (tier {} -> {})",
                old_tier.label(),
                target_tier.label()
            ),
        },
        signature: HybridSignature::from_sdk(&audit_sig),
    };
    handle.data_mut().audit_log.push(rotate_entry);
    handle.rotate(&new_passphrase, target_tier)?;
    let audit_entries = handle.data().audit_log.len();

    if json {
        let response = RotateResponse {
            ok: true,
            command: "rotate-passphrase",
            vault: vault_path.display().to_string(),
            from_tier: old_tier.label(),
            to_tier: target_tier.label(),
            audit_entries,
        };
        crate::commands::output::print_json(&response, "rotate-passphrase")?;
    } else {
        println!("Passphrase rotated for vault: {}", vault_path.display());
        println!("Tier: {} -> {}", old_tier.label(), target_tier.label());
        println!("Audit history preserved ({} entries).", audit_entries);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::InitArgs;
    use crate::cli::ShardArgs;
    use crate::commands::init::cmd_init;
    use crate::commands::shard::cmd_shard;
    use crate::crypto::{decrypt_vault_data, derive_vault_key};
    use crate::vault::{MemoryTier, Vault};
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn write_pw(dir: &std::path::Path, name: &str, pw: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("{}\n", pw)).unwrap();
        p
    }

    fn init_vault(dir: &std::path::Path, pw: &str) -> (PathBuf, PathBuf) {
        let vault_path = dir.join("secrets.vault");
        let pw_file = write_pw(dir, "pw.txt", pw);
        cmd_init(
            InitArgs {
                tier: "standard".to_string(),
            },
            &vault_path,
            Some(pw_file.as_path()),
            false,
            false,
        )
        .unwrap();
        (vault_path, pw_file)
    }

    #[test]
    fn test_rotate_passphrase_changes_decryption_key() {
        let dir = tempdir().unwrap();
        let (vault_path, _pw_file) = init_vault(dir.path(), "old-passphrase-123");
        let new_pw = write_pw(dir.path(), "new_pw.txt", "new-passphrase-456");

        let args = RotatePassphraseArgs {
            new_passphrase_file: Some(new_pw),
            tier: "standard".to_string(),
        };
        let result = cmd_rotate_passphrase(args, &vault_path, "old-passphrase-123", false);
        assert!(result.is_ok(), "rotate failed: {:?}", result);

        // The vault must now decrypt ONLY with the new passphrase.
        let raw = std::fs::read_to_string(&vault_path).unwrap();
        let vault: Vault = serde_json::from_str(&raw).unwrap();
        let old_key = derive_vault_key(b"old-passphrase-123", &vault.salt, vault.tier).unwrap();
        let enc = crate::crypto::EncryptedVault {
            version: vault.version,
            created_at: vault.created_at.clone(),
            tier: vault.tier,
            fingerprint: vault.fingerprint.clone(),
            salt: vault.salt,
            nonce: vault.nonce,
            ciphertext: vault.ciphertext.clone(),
        };
        assert!(
            decrypt_vault_data(&enc, &old_key).is_err(),
            "old passphrase should no longer decrypt"
        );
        let new_key = derive_vault_key(b"new-passphrase-456", &vault.salt, vault.tier).unwrap();
        assert!(
            decrypt_vault_data(&enc, &new_key).is_ok(),
            "new passphrase must decrypt"
        );
    }

    #[test]
    fn test_rotate_requires_new_passphrase_strong() {
        let dir = tempdir().unwrap();
        let (vault_path, _pw_file) = init_vault(dir.path(), "old-passphrase-123");
        let weak = write_pw(dir.path(), "weak.txt", "short");

        let args = RotatePassphraseArgs {
            new_passphrase_file: Some(weak),
            tier: "standard".to_string(),
        };
        let result = cmd_rotate_passphrase(args, &vault_path, "old-passphrase-123", false);
        assert!(matches!(result, Err(Error::PassphraseTooWeak { .. })));
    }

    #[test]
    fn test_rotate_preserves_audit_history() {
        let dir = tempdir().unwrap();
        let (vault_path, _pw_file) = init_vault(dir.path(), "old-passphrase-123");
        // Shard to create an audit entry.
        let sargs = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
            force: false,
            expires: None,
        };
        cmd_shard(sargs, &vault_path, "old-passphrase-123", false).unwrap();

        let new_pw = write_pw(dir.path(), "new_pw.txt", "new-passphrase-456");
        let args = RotatePassphraseArgs {
            new_passphrase_file: Some(new_pw),
            tier: "standard".to_string(),
        };
        cmd_rotate_passphrase(args, &vault_path, "old-passphrase-123", false).unwrap();

        // The rotated vault must still carry the Shard entry AND a Rotate entry.
        let raw = std::fs::read_to_string(&vault_path).unwrap();
        let vault: Vault = serde_json::from_str(&raw).unwrap();
        let new_key = derive_vault_key(b"new-passphrase-456", &vault.salt, vault.tier).unwrap();
        let enc = crate::crypto::EncryptedVault {
            version: vault.version,
            created_at: vault.created_at.clone(),
            tier: vault.tier,
            fingerprint: vault.fingerprint.clone(),
            salt: vault.salt,
            nonce: vault.nonce,
            ciphertext: vault.ciphertext.clone(),
        };
        let vd = decrypt_vault_data(&enc, &new_key).unwrap();
        let has_shard = vd
            .audit_log
            .iter()
            .any(|e| matches!(e.operation, Operation::Shard { .. }));
        let has_rotate = vd
            .audit_log
            .iter()
            .any(|e| matches!(e.operation, Operation::RotatePassphrase { .. }));
        assert!(has_shard, "shard entry must survive rotation");
        assert!(has_rotate, "rotate entry must be appended");
        // The original shard entry's integrity (signature) is untouched: still >=2 entries.
        assert!(vd.audit_log.len() >= 2);
    }

    #[test]
    fn test_rotate_upgrades_tier() {
        let dir = tempdir().unwrap();
        let (vault_path, _pw_file) = init_vault(dir.path(), "old-passphrase-123");
        let new_pw = write_pw(dir.path(), "new_pw.txt", "new-passphrase-456");

        let args = RotatePassphraseArgs {
            new_passphrase_file: Some(new_pw),
            tier: "sovereign".to_string(),
        };
        cmd_rotate_passphrase(args, &vault_path, "old-passphrase-123", false).unwrap();

        let raw = std::fs::read_to_string(&vault_path).unwrap();
        let vault: Vault = serde_json::from_str(&raw).unwrap();
        assert_eq!(vault.tier, MemoryTier::Sovereign);

        // Must decrypt with the new passphrase at the new tier.
        let new_key =
            derive_vault_key(b"new-passphrase-456", &vault.salt, MemoryTier::Sovereign).unwrap();
        let enc = crate::crypto::EncryptedVault {
            version: vault.version,
            created_at: vault.created_at.clone(),
            tier: vault.tier,
            fingerprint: vault.fingerprint.clone(),
            salt: vault.salt,
            nonce: vault.nonce,
            ciphertext: vault.ciphertext.clone(),
        };
        assert!(decrypt_vault_data(&enc, &new_key).is_ok());
    }
}
