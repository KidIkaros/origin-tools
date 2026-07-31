//! Vault encryption and decryption operations

use crate::error::Error;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Encrypted vault data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedVault {
    pub version: u8,
    pub created_at: String,
    pub tier: crate::vault::MemoryTier,
    pub fingerprint: String,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Vault data to be encrypted
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultData {
    pub master_seed: [u8; 32],
    pub keys: std::collections::HashMap<String, Vec<u8>>,
    pub audit_log: Vec<crate::audit::AuditEntry>,
}

impl VaultData {
    pub fn new() -> Self {
        Self {
            master_seed: [0u8; 32],
            keys: std::collections::HashMap::new(),
            audit_log: Vec::new(),
        }
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypt vault data with XChaCha20-Poly1305
pub fn encrypt_vault_data(
    data: &VaultData,
    key: &[u8; 32],
    salt: [u8; 16],
    nonce: [u8; 24],
    tier: crate::vault::MemoryTier,
) -> Result<EncryptedVault, Error> {
    let cipher_key = Key::from_slice(key);
    let cipher_nonce = chacha20poly1305::XNonce::from_slice(&nonce);

    let plaintext = serde_json::to_vec(data)
        .map_err(|e| Error::CryptoError(format!("Failed to serialize vault data: {}", e)))?;

    let cipher = XChaCha20Poly1305::new(cipher_key);
    let ciphertext = cipher
        .encrypt(cipher_nonce, plaintext.as_slice())
        .map_err(|e| Error::CryptoError(format!("Failed to encrypt vault: {}", e)))?;

    // Generate fingerprint
    let mut combined = Vec::with_capacity(salt.len() + nonce.len());
    combined.extend_from_slice(&salt);
    combined.extend_from_slice(&nonce);
    let fingerprint = blake3::hash(&combined);
    let fingerprint_bytes = fingerprint.as_bytes();
    let fingerprint_hex = hex::encode(&fingerprint_bytes[..4]);

    Ok(EncryptedVault {
        version: 1,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string(),
        tier,
        fingerprint: fingerprint_hex,
        salt,
        nonce,
        ciphertext,
    })
}

/// Decrypt vault data from encrypted vault
pub fn decrypt_vault_data(encrypted: &EncryptedVault, key: &[u8; 32]) -> Result<VaultData, Error> {
    let cipher_key = Key::from_slice(key);
    let cipher_nonce = chacha20poly1305::XNonce::from_slice(&encrypted.nonce);

    let cipher = XChaCha20Poly1305::new(cipher_key);
    let plaintext = cipher
        .decrypt(cipher_nonce, encrypted.ciphertext.as_slice())
        .map_err(|e| Error::VaultDecryptionFailed(format!("Failed to decrypt vault: {}", e)))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| Error::VaultCorrupted(format!("Failed to deserialize vault: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_vault_data_new() {
        let data = VaultData::new();
        assert_eq!(data.keys.len(), 0);
        assert_eq!(data.audit_log.len(), 0);
    }

    #[test]
    fn test_vault_data_default() {
        let data = VaultData::default();
        assert_eq!(data.keys.len(), 0);
        assert_eq!(data.audit_log.len(), 0);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut data = VaultData::new();
        data.master_seed = [1u8; 32];
        data.keys.insert("test-key".to_string(), vec![2, 3, 4]);

        let key = [42u8; 32];
        let salt = [1u8; 16];
        let nonce = [2u8; 24];

        let encrypted = encrypt_vault_data(&data, &key, salt, nonce, crate::vault::MemoryTier::Standard).unwrap();
        let decrypted = decrypt_vault_data(&encrypted, &key).unwrap();

        assert_eq!(decrypted.master_seed, data.master_seed);
        assert_eq!(decrypted.keys.get("test-key"), data.keys.get("test-key"));
    }

    #[test]
    fn test_encrypt_decrypt_with_wrong_key() {
        let mut data = VaultData::new();
        data.master_seed = [1u8; 32];

        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let salt = [1u8; 16];
        let nonce = [2u8; 24];

        let encrypted = encrypt_vault_data(&data, &key, salt, nonce, crate::vault::MemoryTier::Standard).unwrap();
        let result = decrypt_vault_data(&encrypted, &wrong_key);

        assert!(matches!(result, Err(Error::VaultDecryptionFailed(_))));
    }

    #[test]
    fn test_encrypted_vault_serialization() {
        let data = VaultData::new();
        let key = [42u8; 32];
        let salt = [1u8; 16];
        let nonce = [2u8; 24];

        let encrypted = encrypt_vault_data(&data, &key, salt, nonce, crate::vault::MemoryTier::Standard).unwrap();

        let serialized = serde_json::to_string(&encrypted).unwrap();
        let deserialized: EncryptedVault = serde_json::from_str(&serialized).unwrap();

        assert_eq!(encrypted.version, deserialized.version);
        assert_eq!(encrypted.fingerprint, deserialized.fingerprint);
    }

    #[test]
    fn test_fingerprint_consistency() {
        let data = VaultData::new();
        let key = [42u8; 32];
        let salt = [1u8; 16];
        let nonce = [2u8; 24];

        let encrypted1 = encrypt_vault_data(&data, &key, salt, nonce, crate::vault::MemoryTier::Standard).unwrap();
        let encrypted2 = encrypt_vault_data(&data, &key, salt, nonce, crate::vault::MemoryTier::Standard).unwrap();

        assert_eq!(encrypted1.fingerprint, encrypted2.fingerprint);
    }

    #[test]
    fn test_fingerprint_differs_with_different_nonce() {
        let data = VaultData::new();
        let key = [42u8; 32];
        let salt = [1u8; 16];
        let nonce1 = [2u8; 24];
        let nonce2 = [3u8; 24];

        let encrypted1 = encrypt_vault_data(&data, &key, salt, nonce1, crate::vault::MemoryTier::Standard).unwrap();
        let encrypted2 = encrypt_vault_data(&data, &key, salt, nonce2, crate::vault::MemoryTier::Standard).unwrap();

        assert_ne!(encrypted1.fingerprint, encrypted2.fingerprint);
    }

    #[test]
    fn test_encrypt_with_many_keys() {
        let mut data = VaultData::new();
        for i in 0..100 {
            data.keys.insert(format!("key-{}", i), vec![i as u8; 32]);
        }

        let key = [42u8; 32];
        let salt = [1u8; 16];
        let nonce = [2u8; 24];

        let encrypted = encrypt_vault_data(&data, &key, salt, nonce, crate::vault::MemoryTier::Standard).unwrap();
        let decrypted = decrypt_vault_data(&encrypted, &key).unwrap();

        assert_eq!(decrypted.keys.len(), 100);
    }

    #[test]
    fn test_tier_is_preserved() {
        let data = VaultData::new();
        let key = [42u8; 32];
        let salt = [1u8; 16];
        let nonce = [2u8; 24];

        let encrypted = encrypt_vault_data(&data, &key, salt, nonce, crate::vault::MemoryTier::Sovereign).unwrap();
        assert_eq!(encrypted.tier, crate::vault::MemoryTier::Sovereign);
    }
}

// Integration tests for init workflow
#[cfg(test)]
mod integration_workflow_tests {
    use super::*;
    use crate::cli::InitArgs;
    use crate::commands::init::cmd_init;
    use crate::vault::MemoryTier;
    use std::path::Path;

    #[test]
    fn test_init_creates_vault_structure() {
        let args = InitArgs {
            tier: "standard".to_string(),
            no_prompt: true,
        };

        if Path::new("~/.origin/secrets.vault").exists() {
            std::fs::remove_file("~/.origin/secrets.vault").ok();
        }

        cmd_init(args).ok();

        let vault_json = std::fs::read_to_string("~/.origin/secrets.vault").unwrap();
        let vault: crate::vault::Vault = serde_json::from_str(&vault_json).unwrap();

        assert_eq!(vault.version, 1);
        assert_eq!(vault.tier, MemoryTier::Standard);
        assert!(!vault.ciphertext.is_empty());

        std::fs::remove_file("~/.origin/secrets.vault").ok();
    }

    #[test]
    fn test_init_with_all_tiers() {
        for tier in ["nano", "standard", "sovereign"] {
            if Path::new("~/.origin/secrets.vault").exists() {
                std::fs::remove_file("~/.origin/secrets.vault").ok();
            }

            let args = InitArgs {
                tier: tier.to_string(),
                no_prompt: true,
            };

            cmd_init(args.clone()).ok();
            let vault_json = std::fs::read_to_string("~/.origin/secrets.vault").unwrap();
            let vault: crate::vault::Vault = serde_json::from_str(&vault_json).unwrap();
            assert_eq!(vault.tier, MemoryTier::from_str(tier).unwrap(), "Tier mismatch for: {}", tier);

            std::fs::remove_file("~/.origin/secrets.vault").ok();
        }
    }

    #[test]
    fn test_init_vault_already_exists() {
        if Path::new("~/.origin/secrets.vault").exists() {
            std::fs::remove_file("~/.origin/secrets.vault").ok();
        }

        let args = InitArgs {
            tier: "standard".to_string(),
            no_prompt: true,
        };

        cmd_init(args.clone()).ok();
        let result = cmd_init(args);
        assert!(matches!(result.unwrap_err(), crate::error::Error::VaultAlreadyExists(_)));

        std::fs::remove_file("~/.origin/secrets.vault").ok();
    }

    #[test]
    fn test_salt_nonce_uniqueness_across_inits() {
        let mut salts = Vec::new();
        let mut nonces = Vec::new();

        for _ in 0..3 {
            if Path::new("~/.origin/secrets.vault").exists() {
                std::fs::remove_file("~/.origin/secrets.vault").ok();
            }

            let args = InitArgs {
                tier: "standard".to_string(),
                no_prompt: true,
            };

            cmd_init(args).ok();
            let vault_json = std::fs::read_to_string("~/.origin/secrets.vault").unwrap();
            let vault: crate::vault::Vault = serde_json::from_str(&vault_json).unwrap();

            salts.push(vault.salt);
            nonces.push(vault.nonce);

            std::fs::remove_file("~/.origin/secrets.vault").ok();
        }

        let unique_salts: std::collections::HashSet<_> = salts.into_iter().collect();
        let unique_nonces: std::collections::HashSet<_> = nonces.into_iter().collect();

        assert_eq!(unique_salts.len(), 3);
        assert_eq!(unique_nonces.len(), 3);
    }
}