// SPDX-License-Identifier: Apache-2.0

//! High-level ratcheted session with AEAD usage-limit enforcement.
//!
//! [`RatchetedSession`] wraps the ratchet key schedule, nonce tracker,
//! replay window, and usage tracker into a single encrypt/decrypt API.
//! When the AEAD usage budget for the current epoch is exhausted, the
//! session refuses further operations and signals that a DH ratchet
//! step (key rotation) is required.

use origin_crypto_sdk::aead::XChaCha20Poly1305;

use crate::error::{ChannelError, Result};
use crate::message::{ChannelMessage, MSG_DATA};
use crate::nonce_tracker::NonceTracker;
use crate::ratchet;
use crate::replay::ReplayWindow;
use crate::types::RatchetKeys;
use crate::usage_limit::{AeadLimits, AeadUsageTracker};

/// A ratcheted messaging session with AEAD usage-limit enforcement.
///
/// # Usage
///
/// ```ignore
/// let mut session = RatchetedSession::new(keys, AeadLimits::default());
/// let msg = session.encrypt(b"hello")?;
/// let plaintext = session.decrypt(&msg)?;
///
/// if session.needs_rotation() {
///     // Perform a DH ratchet step, then:
///     session.rotate(new_keys);
/// }
/// ```
pub struct RatchetedSession {
    keys: RatchetKeys,
    send_nonce: NonceTracker,
    replay: ReplayWindow,
    usage: AeadUsageTracker,
    send_seq: u64,
}

impl RatchetedSession {
    /// Create a session from ratchet keys and usage limits.
    pub fn new(keys: RatchetKeys, limits: AeadLimits) -> Self {
        RatchetedSession {
            keys,
            send_nonce: NonceTracker::new("send"),
            replay: ReplayWindow::new(1024),
            usage: AeadUsageTracker::new(limits),
            send_seq: 0,
        }
    }

    /// Create a session with default usage limits.
    pub fn with_defaults(keys: RatchetKeys) -> Self {
        Self::new(keys, AeadLimits::default())
    }

    /// Encrypt a plaintext message. Returns a [`ChannelMessage`] ready
    /// for framing and transmission.
    ///
    /// Fails with [`ChannelError::UsageLimitExceeded`] if the send
    /// epoch budget is exhausted.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<ChannelMessage> {
        // Check usage budget before encrypting
        self.usage.check_send(plaintext.len())?;

        // Derive a one-time message key and advance the send chain
        let (msg_key, next_chain) = ratchet::derive_message_key(&self.keys.send_chain)?;
        self.keys.send_chain = next_chain;

        // Allocate a unique nonce
        let nonce = self.send_nonce.next_nonce()?;

        // Encrypt
        let ciphertext = XChaCha20Poly1305::encrypt(&msg_key, &nonce, plaintext)
            .map_err(|e| ChannelError::Key(format!("encrypt failed: {e}")))?;

        let seq = self.send_seq;
        self.send_seq += 1;

        Ok(ChannelMessage {
            msg_type: MSG_DATA,
            seq,
            nonce,
            ciphertext,
        })
    }

    /// Decrypt a received message. Returns the plaintext bytes.
    ///
    /// Fails with:
    /// - [`ChannelError::Replay`] if the sequence number was already seen
    /// - [`ChannelError::UsageLimitExceeded`] if the receive epoch budget
    ///   is exhausted
    /// - [`ChannelError::Decryption`] if AEAD authentication fails
    pub fn decrypt(&mut self, msg: &ChannelMessage) -> Result<Vec<u8>> {
        // Replay protection
        self.replay.accept(msg.seq)?;

        // Check usage budget before decrypting
        self.usage.check_recv(msg.ciphertext.len())?;

        // Derive the receive key (same chain derivation as sender)
        let (recv_key, next_chain) = ratchet::derive_message_key(&self.keys.recv_chain)?;
        self.keys.recv_chain = next_chain;

        // Decrypt
        XChaCha20Poly1305::decrypt(&recv_key, &msg.nonce, &msg.ciphertext)
            .map_err(|e| ChannelError::Decryption(format!("AEAD failed: {e}")))
    }

    /// Whether a key rotation is needed (either direction exhausted).
    pub fn needs_rotation(&self) -> bool {
        self.usage.needs_rotation()
    }

    /// Whether the send direction has hit its limit.
    pub fn send_exhausted(&self) -> bool {
        self.usage.send_exhausted()
    }

    /// Whether the receive direction has hit its limit.
    pub fn recv_exhausted(&self) -> bool {
        self.usage.recv_exhausted()
    }

    /// Rotate to new ratchet keys after a DH ratchet step.
    /// Resets all usage counters and the nonce tracker for the new epoch.
    pub fn rotate(&mut self, new_keys: RatchetKeys) {
        self.keys = new_keys;
        self.usage.reset();
        self.send_nonce = NonceTracker::new("send");
        self.send_seq = 0;
    }

    /// Current send message count in this epoch.
    pub fn send_messages(&self) -> u64 {
        self.usage.send_messages()
    }

    /// Current send byte count in this epoch.
    pub fn send_bytes(&self) -> u64 {
        self.usage.send_bytes()
    }

    /// Current receive message count in this epoch.
    pub fn recv_messages(&self) -> u64 {
        self.usage.recv_messages()
    }

    /// Current receive byte count in this epoch.
    pub fn recv_bytes(&self) -> u64 {
        self.usage.recv_bytes()
    }

    /// The configured usage limits.
    pub fn limits(&self) -> &AeadLimits {
        self.usage.limits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> RatchetKeys {
        let secret = [0x42u8; 32];
        ratchet::init_ratchet(&secret, true).unwrap()
    }

    fn peer_keys() -> RatchetKeys {
        let secret = [0x42u8; 32];
        ratchet::init_ratchet(&secret, false).unwrap()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut sender = RatchetedSession::with_defaults(test_keys());
        let mut receiver = RatchetedSession::with_defaults(peer_keys());

        let msg = sender.encrypt(b"hello world").unwrap();
        let plaintext = receiver.decrypt(&msg).unwrap();
        assert_eq!(plaintext, b"hello world");
    }

    #[test]
    fn multiple_messages() {
        let mut sender = RatchetedSession::with_defaults(test_keys());
        let mut receiver = RatchetedSession::with_defaults(peer_keys());

        for i in 0..10u64 {
            let text = format!("message {i}");
            let msg = sender.encrypt(text.as_bytes()).unwrap();
            let decrypted = receiver.decrypt(&msg).unwrap();
            assert_eq!(decrypted, text.as_bytes());
        }

        assert_eq!(sender.send_messages(), 10);
        assert_eq!(receiver.recv_messages(), 10);
    }

    #[test]
    fn replay_rejected() {
        let mut sender = RatchetedSession::with_defaults(test_keys());
        let mut receiver = RatchetedSession::with_defaults(peer_keys());

        let msg = sender.encrypt(b"once").unwrap();
        receiver.decrypt(&msg).unwrap();

        // Same message again → replay
        let result = receiver.decrypt(&msg);
        assert!(matches!(result, Err(ChannelError::Replay(_))));
    }

    #[test]
    fn send_limit_enforced() {
        let limits = AeadLimits::new(3, u64::MAX);
        let mut sender = RatchetedSession::new(test_keys(), limits);

        assert!(sender.encrypt(b"a").is_ok());
        assert!(sender.encrypt(b"b").is_ok());
        assert!(sender.encrypt(b"c").is_ok());
        assert!(sender.send_exhausted());

        let result = sender.encrypt(b"d");
        assert!(matches!(result, Err(ChannelError::UsageLimitExceeded(_))));
    }

    #[test]
    fn recv_limit_enforced() {
        let limits = AeadLimits::new(u64::MAX, 50);
        let mut sender = RatchetedSession::with_defaults(test_keys());
        let mut receiver = RatchetedSession::new(peer_keys(), limits);

        // 30 bytes plaintext → 46 bytes ciphertext
        let msg1 = sender.encrypt(&[0u8; 30]).unwrap();
        assert!(receiver.decrypt(&msg1).is_ok()); // 30 bytes used

        // Another 30 bytes would exceed 50
        let msg2 = sender.encrypt(&[0u8; 30]).unwrap();
        let result = receiver.decrypt(&msg2);
        assert!(matches!(result, Err(ChannelError::UsageLimitExceeded(_))));
    }

    #[test]
    fn rotation_resets_limits() {
        let limits = AeadLimits::new(2, u64::MAX);
        let mut sender = RatchetedSession::new(test_keys(), limits);

        sender.encrypt(b"a").unwrap();
        sender.encrypt(b"b").unwrap();
        assert!(sender.send_exhausted());
        assert!(sender.encrypt(b"c").is_err());

        // Rotate with fresh keys
        let new_secret = [0x99u8; 32];
        let new_keys = ratchet::init_ratchet(&new_secret, true).unwrap();
        sender.rotate(new_keys);

        assert!(!sender.send_exhausted());
        assert_eq!(sender.send_messages(), 0);
        assert!(sender.encrypt(b"c").is_ok());
    }

    #[test]
    fn byte_tracking() {
        let mut sender = RatchetedSession::with_defaults(test_keys());
        sender.encrypt(b"12345").unwrap();
        assert_eq!(sender.send_bytes(), 5);
        sender.encrypt(b"67890").unwrap();
        assert_eq!(sender.send_bytes(), 10);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut sender = RatchetedSession::with_defaults(test_keys());
        let mut receiver = RatchetedSession::with_defaults(peer_keys());

        let mut msg = sender.encrypt(b"secret").unwrap();
        msg.ciphertext[0] ^= 0xFF; // tamper

        let result = receiver.decrypt(&msg);
        assert!(matches!(result, Err(ChannelError::Decryption(_))));
    }
}
