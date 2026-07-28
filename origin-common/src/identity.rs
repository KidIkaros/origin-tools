//! IdentityStore — loads and manages the master identity seed.
//!
//! The master seed is encrypted with Argon2id + XChaCha20-Poly1305 and stored
//! in ~/.origin/identity.seed. This module loads it, derives keys on demand,
//! and provides the foundation for all tools in the suite.

use crate::home::OriginHome;
use origin_crypto_sdk::kdf::Argon2idBuilder;
use origin_crypto_sdk::tier::MemoryTier;
use origin_crypto_sdk::{aead::XChaCha20Poly1305, signing::hybrid::HybridSigningKeyBundle};
use zeroize::Zeroize;

/// Build an Argon2id builder configured for the given tier.
fn tier_argon2(tier: MemoryTier) -> Argon2idBuilder {
    let params = tier.argon2_params(32);
    Argon2idBuilder::new()
        .memory_kib(params.m_cost())
        .iterations(params.t_cost())
        .parallelism(params.p_cost())
}

/// Set Unix file permissions (no-op on non-Unix).
#[cfg(unix)]
fn set_file_permissions(path: &std::path::Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)
        .map_err(|e| format!("cannot set permissions on '{}': {e}", path.display()))
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &std::path::Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

/// The master identity seed, decrypted and ready for use.
pub struct IdentityStore {
    seed: [u8; 32],
    tier: MemoryTier,
}

impl Drop for IdentityStore {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl IdentityStore {
    /// Load the identity from ~/.origin/identity.seed.
    ///
    /// Decrypts the seed with the provided passphrase using the tier stored in the blob.
    pub fn load(home: &OriginHome, passphrase: &str) -> Result<Self, String> {
        let path = home.identity_seed_path();
        if !path.exists() {
            return Err(format!(
                "identity not found at '{}'. Run 'origin-identity init' first.",
                path.display()
            ));
        }

        let blob =
            std::fs::read(&path).map_err(|e| format!("cannot read '{}': {e}", path.display()))?;

        // Decrypt the seed blob.
        // Format: salt (16) + nonce (24) + tier (1) + ciphertext
        if blob.len() < 41 + 16 {
            return Err("identity blob too short".to_string());
        }

        let salt: [u8; 16] = blob[..16].try_into().unwrap();
        let nonce: [u8; 24] = blob[16..40].try_into().unwrap();
        let tier = crate::tier_from_byte(blob[40])?;
        let ciphertext = &blob[41..];

        let mut key = tier_argon2(tier)
            .derive(passphrase.as_bytes(), &salt)
            .map_err(|e| format!("key derivation failed: {e}"))?;

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key[..32]);
        key.zeroize(); // zeroize the Vec

        let seed_bytes = XChaCha20Poly1305::decrypt(&key_arr, &nonce, ciphertext)
            .map_err(|_| "decryption failed (wrong passphrase or corrupt identity)")?;

        key_arr.zeroize(); // zeroize the derived key

        if seed_bytes.len() != 32 {
            return Err(format!("invalid seed length: {}", seed_bytes.len()));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        Ok(Self { seed, tier })
    }

    /// Create a new identity with a fresh seed.
    pub fn create(home: &OriginHome, passphrase: &str, tier: MemoryTier) -> Result<Self, String> {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);

        let store = Self { seed, tier };
        store.save(home, passphrase)?;
        Ok(store)
    }

    /// Save the identity to ~/.origin/identity.seed.
    fn save(&self, home: &OriginHome, passphrase: &str) -> Result<(), String> {
        let path = home.identity_seed_path();

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let mut key = tier_argon2(self.tier)
            .derive(passphrase.as_bytes(), &salt)
            .map_err(|e| format!("key derivation failed: {e}"))?;

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key[..32]);
        key.zeroize(); // zeroize the Vec

        let ciphertext = XChaCha20Poly1305::encrypt(&key_arr, &nonce, &self.seed)
            .map_err(|e| format!("encryption failed: {e}"))?;

        key_arr.zeroize(); // zeroize the derived key

        let mut blob = Vec::with_capacity(16 + 24 + 1 + ciphertext.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.push(crate::tier_to_byte(self.tier));
        blob.extend_from_slice(&ciphertext);

        std::fs::write(&path, &blob)
            .map_err(|e| format!("cannot write '{}': {e}", path.display()))?;

        // Restrict identity file to owner-only read/write
        set_file_permissions(&path, 0o600)?;

        Ok(())
    }

    /// Get the raw seed bytes (will be zeroized on drop).
    pub fn seed_bytes(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Get the memory tier.
    pub fn tier(&self) -> MemoryTier {
        self.tier
    }

    /// Derive a key with domain separation using HKDF-SHA3-256.
    pub fn derive_key(&self, domain: &str, len: usize) -> Result<Vec<u8>, String> {
        use origin_crypto_sdk::hkdf_sha3_256;

        let mut output = vec![0u8; len];
        hkdf_sha3_256(&self.seed, None, domain.as_bytes(), &mut output)
            .map_err(|e| format!("HKDF failed: {e}"))?;
        Ok(output)
    }

    /// Derive a hybrid signing key bundle (Ed25519 + Falcon-1024).
    pub fn hybrid_signing_keys(&self, domain: &str) -> Result<HybridSigningKeyBundle, String> {
        HybridSigningKeyBundle::from_seed(&self.seed, domain)
            .map_err(|e| format!("key generation failed: {e}"))
    }
}
