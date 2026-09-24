//! Vault encryption and decryption operations
//!
//! All symmetric cryptography is delegated to `origin-crypto-sdk` so this
//! crate builds on the foundation instead of re-implementing it.

use crate::error::Error;
use crate::vault::MemoryTier;
use origin_crypto_sdk::{aead::XChaCha20Poly1305, blake3};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Fill `dest` with cryptographically secure random bytes via the shared
/// `origin_common` adapter, which owns the single `fill_random` boundary to
/// the SDK. Origin-facing secret material (master seed, salt, nonce) MUST be
/// generated through this helper — never via a raw `rand` instance — so every
/// random byte in the system has a single, audited provenance.
pub fn random_bytes(dest: &mut [u8]) -> Result<(), Error> {
    origin_common::random_bytes(dest).map_err(Error::CryptoError)
}

/// Generate an N-byte random array via the shared SDK CSPRNG adapter.
pub fn random_array<const N: usize>() -> Result<[u8; N], Error> {
    origin_common::random_array().map_err(Error::CryptoError)
}

/// Encrypted vault data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedVault {
    pub version: u8,
    pub created_at: String,
    #[serde(with = "origin_common::tier::serde_compat")]
    pub tier: MemoryTier,
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
    /// Share numbers that have been revoked (P3.1). A revoked share is
    /// rejected during `recover` and flagged during `verify`, without needing
    /// to re-shard.
    pub revoked_shares: std::collections::HashSet<u8>,
}

impl VaultData {
    pub fn new() -> Self {
        Self {
            master_seed: [0u8; 32],
            keys: std::collections::HashMap::new(),
            audit_log: Vec::new(),
            revoked_shares: std::collections::HashSet::new(),
        }
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypt vault data with XChaCha20-Poly1305 (origin-crypto-sdk)
pub fn encrypt_vault_data(
    data: &VaultData,
    key: &[u8; 32],
    salt: [u8; 16],
    nonce: [u8; 24],
    tier: MemoryTier,
) -> Result<EncryptedVault, Error> {
    let plaintext = serde_json::to_vec(data)
        .map_err(|e| Error::CryptoError(format!("Failed to serialize vault data: {}", e)))?;

    let ciphertext = XChaCha20Poly1305::encrypt(key, &nonce, &plaintext)
        .map_err(|e| Error::CryptoError(format!("Failed to encrypt vault: {:?}", e)))?;

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
            .map_err(|e| crate::error::Error::CryptoError(format!("system clock error: {e}")))?
            .as_secs()
            .to_string(),
        tier,
        fingerprint: fingerprint_hex,
        salt,
        nonce,
        ciphertext,
    })
}

/// Decrypt vault data from encrypted vault (origin-crypto-sdk)
pub fn decrypt_vault_data(encrypted: &EncryptedVault, key: &[u8; 32]) -> Result<VaultData, Error> {
    let plaintext = XChaCha20Poly1305::decrypt(key, &encrypted.nonce, &encrypted.ciphertext)
        .map_err(|e| Error::VaultDecryptionFailed(format!("Failed to decrypt vault: {:?}", e)))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| Error::VaultCorrupted(format!("Failed to deserialize vault: {}", e)))
}

/// Derive a 32-byte share-encryption key from the vault master seed, keyed by
/// the share number via a domain-separated blake3 (P3.3). This keeps local
/// share files opaque at rest while remaining decryptable by the vault owner.
pub fn derive_share_enc_key(seed: &[u8; 32], share_number: u8) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed);
    hasher.update(b"origin-secrets/share-enc/v1");
    hasher.update(&[share_number]);
    let mut key = [0u8; 32];
    key.copy_from_slice(hasher.finalize().as_bytes());
    key
}

/// Encrypt a `Share` to its on-disk envelope (P3.3) using a fresh nonce.
pub fn encrypt_share(
    share: &crate::share::Share,
    seed: &[u8; 32],
) -> Result<crate::share::EncryptedShare, Error> {
    let key = derive_share_enc_key(seed, share.share_number);
    let nonce: [u8; 24] = random_array()?;
    let plaintext = serde_json::to_vec(share)
        .map_err(|e| Error::CryptoError(format!("serialize share: {e}")))?;
    let ciphertext = XChaCha20Poly1305::encrypt(&key, &nonce, &plaintext)
        .map_err(|e| Error::CryptoError(format!("encrypt share: {e:?}")))?;
    Ok(crate::share::EncryptedShare {
        version: 1,
        nonce,
        ciphertext,
    })
}

/// Decrypt a `Share` from its envelope (P3.3), given the vault master seed.
pub fn decrypt_share(
    enc: &crate::share::EncryptedShare,
    seed: &[u8; 32],
    share_number: u8,
) -> Result<crate::share::Share, Error> {
    let key = derive_share_enc_key(seed, share_number);
    let plaintext =
        XChaCha20Poly1305::decrypt(&key, &enc.nonce, &enc.ciphertext).map_err(|_| {
            Error::ShareCorrupted {
                share_number,
                path: PathBuf::from("<encrypted share>"),
            }
        })?;
    serde_json::from_slice(&plaintext).map_err(|e| Error::ShareCorrupted {
        share_number,
        path: PathBuf::from(format!("deserialize: {e}")),
    })
}

/// Derive a 32-byte vault master key from a passphrase via the SDK's
/// tier-aware Argon2id KDF. Mirrors the derivation used during `init`.
pub fn derive_vault_key(
    passphrase: &[u8],
    salt: &[u8; 16],
    tier: MemoryTier,
) -> Result<[u8; 32], Error> {
    let derived = origin_common::argon2_builder(tier, 32)
        .derive(passphrase, salt)
        .map_err(|e| Error::CryptoError(format!("Failed to derive key: {:?}", e)))?;
    derived
        .as_slice()
        .try_into()
        .map_err(|_| Error::CryptoError("Invalid key length from Argon2".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let encrypted = encrypt_vault_data(&data, &key, salt, nonce, MemoryTier::Standard).unwrap();
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

        let encrypted = encrypt_vault_data(&data, &key, salt, nonce, MemoryTier::Standard).unwrap();
        let result = decrypt_vault_data(&encrypted, &wrong_key);

        assert!(matches!(result, Err(Error::VaultDecryptionFailed(_))));
    }

    #[test]
    fn test_encrypted_vault_serialization() {
        let data = VaultData::new();
        let key = [42u8; 32];
        let salt = [1u8; 16];
        let nonce = [2u8; 24];

        let encrypted = encrypt_vault_data(&data, &key, salt, nonce, MemoryTier::Standard).unwrap();

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

        let encrypted1 =
            encrypt_vault_data(&data, &key, salt, nonce, MemoryTier::Standard).unwrap();
        let encrypted2 =
            encrypt_vault_data(&data, &key, salt, nonce, MemoryTier::Standard).unwrap();

        assert_eq!(encrypted1.fingerprint, encrypted2.fingerprint);
    }

    #[test]
    fn test_fingerprint_differs_with_different_nonce() {
        let data = VaultData::new();
        let key = [42u8; 32];
        let salt = [1u8; 16];
        let nonce1 = [2u8; 24];
        let nonce2 = [3u8; 24];

        let encrypted1 =
            encrypt_vault_data(&data, &key, salt, nonce1, MemoryTier::Standard).unwrap();
        let encrypted2 =
            encrypt_vault_data(&data, &key, salt, nonce2, MemoryTier::Standard).unwrap();

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

        let encrypted = encrypt_vault_data(&data, &key, salt, nonce, MemoryTier::Standard).unwrap();
        let decrypted = decrypt_vault_data(&encrypted, &key).unwrap();

        assert_eq!(decrypted.keys.len(), 100);
    }

    #[test]
    fn test_tier_is_preserved() {
        let data = VaultData::new();
        let key = [42u8; 32];
        let salt = [1u8; 16];
        let nonce = [2u8; 24];

        let encrypted =
            encrypt_vault_data(&data, &key, salt, nonce, MemoryTier::Sovereign).unwrap();
        assert_eq!(encrypted.tier, MemoryTier::Sovereign);
    }
}

// Integration tests for init workflow
#[cfg(test)]
mod integration_workflow_tests {
    use super::*;
    use crate::cli::InitArgs;
    use crate::commands::init::cmd_init;
    use crate::vault::parse_tier;

    /// A passphrase file on disk; cmd_init now requires a passphrase source via
    /// -p/--passphrase-file (it never falls back to a demo string), so the
    /// integration tests must supply one. Written exactly once per process via
    /// a OnceLock so parallel test threads never race on a shared file.
    fn pw_file() -> std::path::PathBuf {
        use std::sync::OnceLock;
        static PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
        PATH.get_or_init(|| {
            let p = std::env::temp_dir().join(format!("osecrets_ci_pw_{}.txt", std::process::id()));
            std::fs::write(&p, "correct horse battery staple\n").unwrap();
            p
        })
        .clone()
    }

    /// Isolated vault path per test (PID + test tag) so parallel test runs
    /// don't collide on a shared `~/.origin/secrets.vault`.
    fn isolated_vault(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "osecrets_ci_vault_{}_{}.vault",
            std::process::id(),
            tag
        ))
    }

    #[test]
    fn test_init_creates_vault_structure() {
        let args = InitArgs {
            tier: "standard".to_string(),
        };
        let vault_path = isolated_vault("struct");

        cmd_init(args, &vault_path, Some(pw_file().as_path()), false, false).ok();

        let vault_json = std::fs::read_to_string(&vault_path).unwrap();
        let vault: crate::vault::Vault = serde_json::from_str(&vault_json).unwrap();

        assert_eq!(vault.version, 1);
        assert_eq!(vault.tier, MemoryTier::Standard);
        assert!(!vault.ciphertext.is_empty());

        std::fs::remove_file(&vault_path).ok();
    }

    #[test]
    fn test_init_with_all_tiers() {
        for tier in ["nano", "standard", "sovereign"] {
            let vault_path = isolated_vault(&format!("tier_{}", tier));

            let args = InitArgs {
                tier: tier.to_string(),
            };

            cmd_init(
                args.clone(),
                &vault_path,
                Some(pw_file().as_path()),
                false,
                false,
            )
            .ok();
            let vault_json = std::fs::read_to_string(&vault_path).unwrap();
            let vault: crate::vault::Vault = serde_json::from_str(&vault_json).unwrap();
            assert_eq!(
                vault.tier,
                parse_tier(tier).unwrap(),
                "Tier mismatch for: {}",
                tier
            );

            std::fs::remove_file(&vault_path).ok();
        }
    }

    #[test]
    fn test_init_vault_already_exists() {
        let vault_path = isolated_vault("exists");

        let args = InitArgs {
            tier: "standard".to_string(),
        };

        cmd_init(
            args.clone(),
            &vault_path,
            Some(pw_file().as_path()),
            false,
            false,
        )
        .ok();
        let result = cmd_init(args, &vault_path, Some(pw_file().as_path()), false, false);
        assert!(matches!(
            result.unwrap_err(),
            crate::error::Error::VaultAlreadyExists(_)
        ));

        std::fs::remove_file(&vault_path).ok();
    }

    #[test]
    fn test_salt_nonce_uniqueness_across_inits() {
        let mut salts = Vec::new();
        let mut nonces = Vec::new();

        for i in 0..3 {
            let vault_path = isolated_vault(&format!("uniq_{}", i));

            let args = InitArgs {
                tier: "standard".to_string(),
            };

            cmd_init(args, &vault_path, Some(pw_file().as_path()), false, false).ok();
            let vault_json = std::fs::read_to_string(&vault_path).unwrap();
            let vault: crate::vault::Vault = serde_json::from_str(&vault_json).unwrap();

            salts.push(vault.salt);
            nonces.push(vault.nonce);

            std::fs::remove_file(&vault_path).ok();
        }

        let unique_salts: std::collections::HashSet<_> = salts.into_iter().collect();
        let unique_nonces: std::collections::HashSet<_> = nonces.into_iter().collect();

        assert_eq!(unique_salts.len(), 3);
        assert_eq!(unique_nonces.len(), 3);
    }
}
