// SPDX-License-Identifier: Apache-2.0

//! Message types and header format for encrypted channel traffic.
//!
//! Encrypted message wire format (inside a length-prefixed frame):
//! ```text
//! ┌──────────┬──────────┬───────────────┬─────────────────────────────┐
//! │ type (1B)│ seq (8B) │ nonce (24B)   │ ciphertext + tag (N + 16B) │
//! └──────────┴──────────┴───────────────┴─────────────────────────────┘
//! ```

use crate::error::{ChannelError, Result};
use crate::types::CipherSuite;

/// Message type tags.
pub const MSG_HANDSHAKE_1: u8 = 0x01;
pub const MSG_HANDSHAKE_2: u8 = 0x02;
pub const MSG_HANDSHAKE_3: u8 = 0x03;
pub const MSG_DATA: u8 = 0x10;
pub const MSG_CLOSE: u8 = 0x20;
pub const MSG_PING: u8 = 0x30;
pub const MSG_PONG: u8 = 0x31;

/// Header size: type (1) + seq (8) + nonce (24) = 33 bytes.
pub const HEADER_SIZE: usize = 33;

/// An encrypted channel message.
#[derive(Debug, Clone)]
pub struct ChannelMessage {
    pub msg_type: u8,
    pub seq: u64,
    pub nonce: [u8; 24],
    /// Ciphertext including the 16-byte AEAD tag.
    pub ciphertext: Vec<u8>,
}

impl ChannelMessage {
    /// Serialize to wire bytes (without the outer length-prefix frame).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.ciphertext.len());
        out.push(self.msg_type);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse from wire bytes (after the outer frame has been stripped).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let suite = CipherSuite::XChaCha20Poly1305;
        let min = HEADER_SIZE + suite.tag_len();
        if data.len() < min {
            return Err(ChannelError::InvalidMessage(format!(
                "message too short: {} bytes (min {min})",
                data.len()
            )));
        }
        let msg_type = data[0];
        let seq = u64::from_be_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&data[9..33]);
        let ciphertext = data[33..].to_vec();
        Ok(ChannelMessage {
            msg_type,
            seq,
            nonce,
            ciphertext,
        })
    }

    /// Total wire size including frame prefix.
    pub fn wire_size(&self) -> usize {
        4 + HEADER_SIZE + self.ciphertext.len()
    }
}

/// A handshake message (unencrypted, carries ephemeral DH public key).
#[derive(Debug, Clone)]
pub struct HandshakeMessage {
    pub msg_type: u8,
    /// X25519 ephemeral public key (32 bytes).
    pub ephemeral_pk: [u8; 32],
    /// Optional encrypted payload (messages 2 and 3).
    pub payload: Vec<u8>,
}

impl HandshakeMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + self.payload.len());
        out.push(self.msg_type);
        out.extend_from_slice(&self.ephemeral_pk);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 33 {
            return Err(ChannelError::Handshake(
                "handshake message too short (need 33+ bytes)".into(),
            ));
        }
        let msg_type = data[0];
        let mut ephemeral_pk = [0u8; 32];
        ephemeral_pk.copy_from_slice(&data[1..33]);
        let payload = data[33..].to_vec();
        Ok(HandshakeMessage {
            msg_type,
            ephemeral_pk,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_message_roundtrip() {
        let msg = ChannelMessage {
            msg_type: MSG_DATA,
            seq: 42,
            nonce: [7u8; 24],
            ciphertext: vec![0xAB; 48], // 32 plaintext + 16 tag
        };
        let bytes = msg.to_bytes();
        let parsed = ChannelMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.msg_type, MSG_DATA);
        assert_eq!(parsed.seq, 42);
        assert_eq!(parsed.nonce, [7u8; 24]);
        assert_eq!(parsed.ciphertext, vec![0xAB; 48]);
    }

    #[test]
    fn handshake_message_roundtrip() {
        let msg = HandshakeMessage {
            msg_type: MSG_HANDSHAKE_1,
            ephemeral_pk: [0x11; 32],
            payload: vec![],
        };
        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), 33);
        let parsed = HandshakeMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.msg_type, MSG_HANDSHAKE_1);
        assert_eq!(parsed.ephemeral_pk, [0x11; 32]);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn handshake_with_payload() {
        let msg = HandshakeMessage {
            msg_type: MSG_HANDSHAKE_2,
            ephemeral_pk: [0x22; 32],
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let bytes = msg.to_bytes();
        let parsed = HandshakeMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn reject_short_channel_message() {
        let result = ChannelMessage::from_bytes(&[0x10; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn reject_short_handshake() {
        let result = HandshakeMessage::from_bytes(&[0x01; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn wire_size_calculation() {
        let msg = ChannelMessage {
            msg_type: MSG_DATA,
            seq: 1,
            nonce: [0u8; 24],
            ciphertext: vec![0xAB; 48],
        };
        // 4 (frame prefix) + 33 (header) + 48 (ciphertext) = 85
        assert_eq!(msg.wire_size(), 4 + HEADER_SIZE + 48);
    }

    // Channel-message golden vector — FORMAT_REGISTRY.md priority 6.
    // The ciphertext is a real XChaCha20-Poly1305 output under a fixed
    // key/nonce so the fixture pins wire layout AND crypto binding.
    #[test]
    fn channel_message_golden_vector_v1() {
        let key = [0x42u8; 32];
        let nonce = [0x33u8; 24];
        let plaintext = b"channel message golden vector";
        let ct = origin_crypto_sdk::aead::XChaCha20Poly1305::encrypt(&key, &nonce, plaintext)
            .expect("encrypt");

        let msg = ChannelMessage {
            msg_type: MSG_DATA,
            seq: 0x0102_0304_0506_0708,
            nonce,
            ciphertext: ct,
        };
        let wire = msg.to_bytes();

        const EXPECTED: &str = "1001020304050607083333333333333333333333333333333333333333333333334174aa6d98325562fec9250135cefbc4faf06e4b229cef331f6d56bbfb8745b2a5e4395951a7ba3a041855c805";
        assert_eq!(hex::encode(&wire), EXPECTED);

        let parsed = ChannelMessage::from_bytes(&hex::decode(EXPECTED).expect("decode golden"))
            .expect("parse golden vector");
        assert_eq!(parsed.msg_type, MSG_DATA);
        assert_eq!(parsed.seq, 0x0102_0304_0506_0708);
        assert_eq!(parsed.nonce, nonce);
        let pt =
            origin_crypto_sdk::aead::XChaCha20Poly1305::decrypt(&key, &nonce, &parsed.ciphertext)
                .expect("decrypt golden vector");
        assert_eq!(pt, plaintext);
    }
}
