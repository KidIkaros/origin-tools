// SPDX-License-Identifier: Apache-2.0

//! dh — the single X25519 seam for origin-channel.
//!
//! Design rule (ARCHITECTURE.md "one crypto provider"): every crypto
//! primitive should come from `origin-crypto-sdk`. The SDK currently
//! reserves the X25519 algorithm id (0x0602, "via external crate") but does
//! not yet expose a key-agreement API, so this module centralizes the
//! single place that touches `x25519_dalek`. When the SDK ships an X25519
//! surface, only this file changes — `handshake.rs` and `commands.rs` never
//! import dalek types directly.
//!
//! Key bytes are the interchange format everywhere outside this module:
//! `[u8; 32]` secrets, `[u8; 32]` compressed public keys.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{ChannelError, Result};

/// A secret X25519 scalar (32 bytes). Wraps the dalek type so the rest of
/// the crate never names it.
#[derive(Clone)]
pub struct DhSecret(StaticSecret);

/// A public X25519 key (32 bytes, little-endian Montgomery u-coordinate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhPublic([u8; 32]);

impl DhPublic {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl DhSecret {
    /// Deterministic secret from raw bytes (clamping is applied by dalek).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Random secret from the SDK's CSPRNG wrapper.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 32];
        origin_crypto_sdk::fill_random(&mut bytes)
            .map_err(|_| ChannelError::Handshake("OS CSPRNG failed".into()))?;
        Ok(Self(StaticSecret::from(bytes)))
    }

    /// Derive our public key.
    pub fn public(&self) -> DhPublic {
        DhPublic(PublicKey::from(&self.0).to_bytes())
    }

    /// Raw secret bytes (for persistence; handle with care).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// X25519 Diffie-Hellman against the peer's public key → shared secret.
    pub fn diffie_hellman(&self, peer: &DhPublic) -> [u8; 32] {
        self.0.diffie_hellman(&PublicKey::from(peer.0)).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_public_from_secret() {
        let s = DhSecret::from_bytes([7u8; 32]);
        let p1 = s.public();
        let p2 = DhSecret::from_bytes([7u8; 32]).public();
        assert_eq!(p1, p2);
    }

    #[test]
    fn dh_symmetry() {
        let a = DhSecret::from_bytes([1u8; 32]);
        let b = DhSecret::from_bytes([2u8; 32]);
        let ab = a.diffie_hellman(&b.public());
        let ba = b.diffie_hellman(&a.public());
        assert_eq!(ab, ba, "X25519 shared secret must be symmetric");
    }

    #[test]
    fn generate_is_random() {
        let s1 = DhSecret::generate().unwrap();
        let s2 = DhSecret::generate().unwrap();
        assert_ne!(s1.to_bytes(), s2.to_bytes());
    }
}
