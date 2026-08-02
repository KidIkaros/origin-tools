//! Vault handle abstraction — encapsulates vault opening, decryption, and
//! re-encryption logic to eliminate duplication across commands.

use crate::crypto::{
    decrypt_vault_data, derive_vault_key, encrypt_vault_data, EncryptedVault, VaultData,
};
use crate::error::Error;
use crate::vault::{MemoryTier, Vault};
use std::io::Write;
use std::path::Path;

/// Write a file through a sibling temporary file and atomic rename.
///
/// This prevents readers from observing a partially written vault, share, or
/// export. The temporary file is created with restrictive permissions where the
/// platform supports them and is removed if the write fails.
pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|e| Error::IoError(format!("create parent directory: {e}")))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| Error::IoError(format!("path has no file name: {}", path.display())))?
        .to_string_lossy();
    let temp_path = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));

    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .map_err(|e| Error::IoError(format!("create temporary file: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::IoError(format!("restrict temporary file permissions: {e}")))?;
        }
        file.write_all(contents)
            .map_err(|e| Error::IoError(format!("write temporary file: {e}")))?;
        file.sync_all()
            .map_err(|e| Error::IoError(format!("sync temporary file: {e}")))?;
        std::fs::rename(&temp_path, path)
            .map_err(|e| Error::IoError(format!("replace {}: {e}", path.display())))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

/// A handle to an opened vault, providing access to decrypted VaultData
/// and methods for atomic re-encryption with audit log updates.
pub struct VaultHandle {
    pub vault_path: std::path::PathBuf,
    pub vault_data: VaultData,
    pub tier: MemoryTier,
    pub salt: [u8; 16],
    pub key: [u8; 32],
    pub original_nonce: [u8; 24],
    pub version: u8,
    pub created_at: String,
    pub fingerprint: String,
}

impl VaultHandle {
    /// Open a vault at `path` using `passphrase`.
    /// Returns the decrypted VaultData and metadata needed for re-encryption.
    pub fn open(path: &Path, passphrase: &str) -> Result<Self, Error> {
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

        Ok(Self {
            vault_path: path.to_path_buf(),
            vault_data,
            tier: vault.tier,
            salt: vault.salt,
            key,
            original_nonce: vault.nonce,
            version: vault.version,
            created_at: vault.created_at.clone(),
            fingerprint: vault.fingerprint.clone(),
        })
    }

    /// Get a reference to the decrypted vault data.
    pub fn data(&self) -> &VaultData {
        &self.vault_data
    }

    /// Get a mutable reference to the vault data for modifications.
    pub fn data_mut(&mut self) -> &mut VaultData {
        &mut self.vault_data
    }

    /// Re-encrypt the vault with a FRESH nonce (critical for XChaCha20-Poly1305 nonce uniqueness).
    /// The salt and tier remain unchanged; only the nonce is regenerated.
    /// This must be called after any mutation to vault_data (audit log, revoked_shares, etc.).
    pub fn save(&mut self) -> Result<(), Error> {
        let fresh_nonce: [u8; 24] = crate::crypto::random_array()?;
        let reencrypted = encrypt_vault_data(
            &self.vault_data,
            &self.key,
            self.salt,
            fresh_nonce,
            self.tier,
        )?;
        let updated_vault = Vault {
            version: reencrypted.version,
            created_at: reencrypted.created_at.clone(),
            tier: reencrypted.tier,
            fingerprint: reencrypted.fingerprint.clone(),
            salt: reencrypted.salt,
            nonce: reencrypted.nonce,
            ciphertext: reencrypted.ciphertext.clone(),
        };
        let updated_json = serde_json::to_string_pretty(&updated_vault)
            .map_err(|e| Error::IoError(format!("serialize vault: {e}")))?;
        atomic_write(&self.vault_path, updated_json.as_bytes())?;
        // Update our cached nonce so subsequent saves also use fresh nonces
        self.original_nonce = fresh_nonce;
        Ok(())
    }

    /// Re-encrypt the vault with a NEW passphrase and optionally a new tier.
    /// Generates fresh salt + nonce for forward secrecy.
    pub fn rotate(&mut self, new_passphrase: &str, new_tier: MemoryTier) -> Result<(), Error> {
        let new_salt: [u8; 16] = crate::crypto::random_array()?;
        let new_nonce: [u8; 24] = crate::crypto::random_array()?;
        let new_key = derive_vault_key(new_passphrase.as_bytes(), &new_salt, new_tier)?;

        let reencrypted =
            encrypt_vault_data(&self.vault_data, &new_key, new_salt, new_nonce, new_tier)?;
        let updated_vault = Vault {
            version: reencrypted.version,
            created_at: reencrypted.created_at.clone(),
            tier: reencrypted.tier,
            fingerprint: reencrypted.fingerprint.clone(),
            salt: reencrypted.salt,
            nonce: reencrypted.nonce,
            ciphertext: reencrypted.ciphertext.clone(),
        };
        let updated_json = serde_json::to_string_pretty(&updated_vault)
            .map_err(|e| Error::IoError(format!("serialize vault: {e}")))?;
        atomic_write(&self.vault_path, updated_json.as_bytes())?;

        // Update internal state
        self.salt = new_salt;
        self.key = new_key;
        self.tier = new_tier;
        self.original_nonce = new_nonce;
        self.fingerprint = reencrypted.fingerprint.clone();
        Ok(())
    }

    /// Append an audit entry and save the vault atomically.
    pub fn append_audit_and_save(&mut self, entry: crate::audit::AuditEntry) -> Result<(), Error> {
        self.vault_data.audit_log.push(entry);
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt_vault_data, VaultData};
    use crate::vault::{MemoryTier, Vault};
    use tempfile::tempdir;

    fn make_vault(dir: &std::path::Path, pw: &str) -> std::path::PathBuf {
        let path = dir.join("secrets.vault");
        let salt: [u8; 16] = [3u8; 16];
        let nonce: [u8; 24] = [4u8; 24];
        let tier = MemoryTier::Standard;
        let key = derive_vault_key(pw.as_bytes(), &salt, tier).unwrap();
        let mut vd = VaultData::new();
        vd.master_seed = [42u8; 32];
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
    fn test_atomic_write_replaces_file_without_partial_content() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("state.json");

        atomic_write(&path, br#"{"version":1}"#).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"version":1}"#);

        atomic_write(&path, br#"{"version":2,"ok":true}"#).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            r#"{"version":2,"ok":true}"#
        );
        let files: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(files, vec![std::ffi::OsString::from("state.json")]);
    }

    #[test]
    fn test_vault_handle_open() {
        let dir = tempdir().unwrap();
        let vault_path = make_vault(dir.path(), "test-passphrase-123");
        let handle = VaultHandle::open(&vault_path, "test-passphrase-123").unwrap();
        assert_eq!(handle.vault_data.master_seed, [42u8; 32]);
        assert_eq!(handle.tier, MemoryTier::Standard);
    }

    #[test]
    fn test_vault_handle_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let vault_path = make_vault(dir.path(), "correct-passphrase-123");
        let result = VaultHandle::open(&vault_path, "wrong-passphrase-123");
        assert!(matches!(result, Err(Error::VaultDecryptionFailed(_))));
    }

    #[test]
    fn test_vault_handle_save_changes_nonce() {
        let dir = tempdir().unwrap();
        let vault_path = make_vault(dir.path(), "test-passphrase-123");
        let mut handle = VaultHandle::open(&vault_path, "test-passphrase-123").unwrap();
        let nonce_before = handle.original_nonce;

        // Mutate and save
        handle
            .vault_data
            .keys
            .insert("test".to_string(), vec![1, 2, 3]);
        handle.save().unwrap();

        let nonce_after = handle.original_nonce;
        assert_ne!(nonce_before, nonce_after, "nonce must change on save");

        // Verify it still decrypts
        let handle2 = VaultHandle::open(&vault_path, "test-passphrase-123").unwrap();
        assert_eq!(handle2.vault_data.keys.get("test"), Some(&vec![1, 2, 3]));
    }

    #[test]
    fn test_vault_handle_rotate() {
        let dir = tempdir().unwrap();
        let vault_path = make_vault(dir.path(), "old-passphrase-123");
        let mut handle = VaultHandle::open(&vault_path, "old-passphrase-123").unwrap();

        handle
            .rotate("new-passphrase-456", MemoryTier::Sovereign)
            .unwrap();

        // Old passphrase should no longer work
        assert!(VaultHandle::open(&vault_path, "old-passphrase-123").is_err());
        // New passphrase should work
        let handle2 = VaultHandle::open(&vault_path, "new-passphrase-456").unwrap();
        assert_eq!(handle2.tier, MemoryTier::Sovereign);
        assert_eq!(handle2.vault_data.master_seed, [42u8; 32]);
    }
}
