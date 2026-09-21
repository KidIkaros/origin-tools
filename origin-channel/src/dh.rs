// SPDX-License-Identifier: Apache-2.0

//! dh — the single X25519 seam for origin-channel.
//!
//! Design rule (ARCHITECTURE.md "one crypto provider"): every crypto
//! primitive comes from `origin-crypto-sdk`. Since SDK v0.7.1-rc.7 the SDK
//! exposes the X25519 key-agreement surface (`origin_crypto_sdk::x25519`,
//! `algorithm_id 0x0602`), and this module is now a thin re-typing of that
//! surface — no `x25519_dalek` dependency remains in this crate.
//!
//! Key bytes are the interchange format everywhere outside this module:
//! `[u8; 32]` secrets, `[u8; 32]` compressed public keys.
//!
//! Hardening inherited from the SDK: secrets are clamped (RFC 7748 §5) and
//! zeroized on drop; `diffie_hellman` **rejects** all-zero/low-order peer
//! keys instead of silently returning a known constant.

use origin_crypto_sdk::x25519::{X25519KeyPair, X25519PublicKey, X25519SharedSecret};

use crate::error::{ChannelError, Result};

/// A secret X25519 scalar (32 bytes, clamped; zeroized on drop).
///
/// Wraps the SDK key pair so the rest of the crate never names SDK
/// internals. The paired public key is held here to keep the SDK type
/// private to this seam.
#[derive(Clone)]
pub struct DhSecret(X25519KeyPair);

/// A public X25519 key (32 bytes, little-endian Montgomery u-coordinate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhPublic(X25519PublicKey);

impl DhPublic {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(X25519PublicKey::from_bytes(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl DhSecret {
    /// Deterministic secret from raw bytes (clamping is applied by the SDK).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        // Infallible for any non-zero scalar; an all-zero input scalar is a
        // caller bug (it cannot arise from generate() or a valid wire key),
        // and X25519 arithmetic against it is meaningless — panic loudly
        // rather than propagate a key that proves nothing.
        Self(X25519KeyPair::from_secret_key(&bytes).expect("all-zero X25519 scalar"))
    }

    /// Random secret from the SDK's CSPRNG boundary.
    pub fn generate() -> Result<Self> {
        Ok(Self(X25519KeyPair::generate().map_err(|e| {
            ChannelError::Key(format!("OS CSPRNG failed: {e}"))
        })?))
    }

    /// Derive our public key.
    pub fn public(&self) -> DhPublic {
        DhPublic(self.0.public_key())
    }

    /// Raw secret bytes (for persistence; handle with care).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.secret_key_bytes()
    }

    /// X25519 Diffie-Hellman against the peer's public key → shared secret.
    ///
    /// # Errors
    ///
    /// Propagates the SDK's hardening: an all-zero result (all-zero or
    /// low-order peer key) is rejected rather than returned. A hostile peer
    /// key is a handshake failure, not a session.
    pub fn diffie_hellman(&self, peer: &DhPublic) -> Result<[u8; 32]> {
        let ss: X25519SharedSecret = self
            .0
            .diffie_hellman(&peer.0)
            .map_err(|e| ChannelError::Key(e.to_string()))?;
        Ok(*ss.as_bytes())
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
        let ab = a.diffie_hellman(&b.public()).unwrap();
        let ba = b.diffie_hellman(&a.public()).unwrap();
        assert_eq!(ab, ba, "X25519 shared secret must be symmetric");
    }

    #[test]
    fn generate_is_random() {
        let s1 = DhSecret::generate().unwrap();
        let s2 = DhSecret::generate().unwrap();
        assert_ne!(s1.to_bytes(), s2.to_bytes());
    }

    /// Hardened behavior inherited from the SDK: a low-order peer point
    /// (u = 1) maps to the all-zero shared secret and must be REJECTED,
    /// not returned as a session key.
    #[test]
    fn low_order_peer_rejected() {
        let a = DhSecret::generate().unwrap();
        let mut low_order = [0u8; 32];
        low_order[0] = 1;
        assert!(a.diffie_hellman(&DhPublic::from_bytes(low_order)).is_err());
    }

    #[test]
    fn all_zero_peer_rejected() {
        let a = DhSecret::generate().unwrap();
        assert!(a.diffie_hellman(&DhPublic::from_bytes([0u8; 32])).is_err());
    }

    /// Wire round-trip: the persistence form rebuilds to the same identity.
    #[test]
    fn secret_bytes_round_trip() {
        let s = DhSecret::generate().unwrap();
        let restored = DhSecret::from_bytes(s.to_bytes());
        assert_eq!(s.public(), restored.public());
    }
}
