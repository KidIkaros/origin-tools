// SPDX-License-Identifier: Apache-2.0

//! crypto — encryption at rest for secret-bearing memory nodes.
//!
//! Uses the SDK's XChaCha20-Poly1305 AEAD (never AES-GCM) with a key derived
//! from the master seed via BLAKE3 derive_key (domain-separated, no raw rand).
//! Each encryption gets a fresh nonce from `getrandom`; the nonce is prepended
//! to the ciphertext so decrypt can recover it.
//!
//! Design: sign-then-encrypt. The hybrid signature commits to the *plaintext*
//! body; encryption is a storage concern layered on top, not part of the
//! provenance. A reloaded node verifies its signature against the decrypted
//! body, so ciphertext tampering is caught by AEAD auth *and* sig mismatch.

use origin_crypto_sdk::aead::{generate_nonce, XChaCha20Poly1305};

/// An XChaCha20-Poly1305 cipher keyed from the master seed.
/// Cloneable so `Memory` can hold a copy alongside the signing bundle.
#[derive(Clone)]
pub struct BodyCipher {
    key: [u8; 32],
}

impl BodyCipher {
    /// Derive an encryption key from the master seed using BLAKE3 derive_key
    /// (domain: "origin-memory/body-encryption/v1").
    pub fn from_seed(master_seed: &[u8; 32]) -> Self {
        let key =
            origin_crypto_sdk::blake3::derive_key("origin-memory/body-encryption/v1", master_seed);
        Self { key }
    }

    /// Encrypt plaintext → `nonce ‖ ciphertext` (nonce is 24 bytes, prepended).
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = generate_nonce();
        let ct = XChaCha20Poly1305::encrypt(&self.key, &nonce, plaintext)
            .expect("XChaCha20-Poly1305 encryption failed");
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypt `nonce ‖ ciphertext` → plaintext. Returns None on auth failure
    /// (tampered ciphertext or wrong key).
    pub fn decrypt(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < 24 {
            return None;
        }
        let (nonce, ct) = sealed.split_at(24);
        let mut nonce_arr = [0u8; 24];
        nonce_arr.copy_from_slice(nonce);
        XChaCha20Poly1305::decrypt(&self.key, &nonce_arr, ct).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let cipher = BodyCipher::from_seed(&[99u8; 32]);
        let plaintext = b"Classified: the asset arrived at 0300.";
        let sealed = cipher.encrypt(plaintext);
        let recovered = cipher.decrypt(&sealed).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let cipher = BodyCipher::from_seed(&[99u8; 32]);
        let mut sealed = cipher.encrypt(b"secret");
        // Flip a byte in the ciphertext (after the nonce).
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(
            cipher.decrypt(&sealed).is_none(),
            "tampered ciphertext rejected"
        );
    }

    #[test]
    fn wrong_key_fails() {
        let cipher_a = BodyCipher::from_seed(&[1u8; 32]);
        let cipher_b = BodyCipher::from_seed(&[2u8; 32]);
        let sealed = cipher_a.encrypt(b"secret");
        assert!(cipher_b.decrypt(&sealed).is_none(), "wrong key rejected");
    }
}
