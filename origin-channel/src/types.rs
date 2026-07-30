// SPDX-License-Identifier: Apache-2.0

//! Core types for origin-channel sessions.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte session identifier derived from the handshake transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.as_hex()[..16])
    }
}

/// Session lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelState {
    /// No handshake started.
    Idle,
    /// Handshake in progress (initiator sent message 1, or responder awaiting message 1).
    Handshaking,
    /// Handshake complete, ratchet keys derived, ready for encrypted messaging.
    Established,
    /// Session explicitly closed by either party.
    Closed,
}

/// Negotiated cipher suite for the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// XChaCha20-Poly1305 (24-byte nonce, 16-byte tag) — default.
    XChaCha20Poly1305,
}

impl Default for CipherSuite {
    fn default() -> Self {
        CipherSuite::XChaCha20Poly1305
    }
}

impl CipherSuite {
    pub fn as_u8(&self) -> u8 {
        match self {
            CipherSuite::XChaCha20Poly1305 => 0x01,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(CipherSuite::XChaCha20Poly1305),
            _ => None,
        }
    }

    /// Nonce size in bytes.
    pub fn nonce_len(&self) -> usize {
        24
    }

    /// Authentication tag size in bytes.
    pub fn tag_len(&self) -> usize {
        16
    }
}

/// Ratchet key material — zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RatchetKeys {
    /// Root key (32 bytes) — advanced each DH ratchet step.
    pub root: [u8; 32],
    /// Current sending chain key (32 bytes).
    pub send_chain: [u8; 32],
    /// Current receiving chain key (32 bytes).
    pub recv_chain: [u8; 32],
}

impl std::fmt::Debug for RatchetKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetKeys")
            .field("root", &"[redacted]")
            .field("send_chain", &"[redacted]")
            .field("recv_chain", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_hex_and_display() {
        let id = SessionId([0xAB; 32]);
        assert_eq!(id.as_hex(), "abababababababababababababababababababababababababababababababab");
        // Display shows first 16 hex chars
        assert_eq!(format!("{id}"), "abababababababab");
    }

    #[test]
    fn cipher_suite_default_and_props() {
        let suite = CipherSuite::default();
        assert_eq!(suite, CipherSuite::XChaCha20Poly1305);
        assert_eq!(suite.nonce_len(), 24);
        assert_eq!(suite.tag_len(), 16);
        assert_eq!(suite.as_u8(), 0x01);
    }

    #[test]
    fn cipher_suite_from_u8_invalid() {
        assert!(CipherSuite::from_u8(0x00).is_none());
        assert!(CipherSuite::from_u8(0xFF).is_none());
        assert!(CipherSuite::from_u8(0x01).is_some());
    }

    #[test]
    fn ratchet_keys_debug_redacts() {
        let keys = RatchetKeys {
            root: [0x11; 32],
            send_chain: [0x22; 32],
            recv_chain: [0x33; 32],
        };
        let debug = format!("{keys:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("1111"));
    }
}

/// A complete established session.
#[derive(Debug)]
pub struct Session {
    pub id: SessionId,
    pub state: ChannelState,
    pub suite: CipherSuite,
    pub keys: RatchetKeys,
    pub send_seq: u64,
    pub recv_seq: u64,
    /// Our X25519 ephemeral DH keypair for the current ratchet epoch.
    pub dh_private: [u8; 32],
    pub dh_public: [u8; 32],
    /// Peer's most recent DH public key.
    pub peer_dh_public: [u8; 32],
}
