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
    /// Resets all usage counters, the nonce tracker, and the replay
    /// window for the new epoch. This is sound: the new epoch keys make
    /// old-epoch ciphertext undecryptable, so the per-epoch replay window
    /// restarts with the epoch (a resent old-epoch frame fails AEAD
    /// before it reaches the window).
    pub fn rotate(&mut self, new_keys: RatchetKeys) {
        self.keys = new_keys;
        self.usage.reset();
        self.send_nonce = NonceTracker::new("send");
        self.send_seq = 0;
        self.replay = ReplayWindow::new(1024);
    }

    /// Read-only access to the current ratchet keys. Needed by transport
    /// layers (origin-network) that drive DH-ratchet rotation: they mix a
    /// fresh DH shared secret into `keys().root` and call `rotate`.
    pub fn keys(&self) -> &RatchetKeys {
        &self.keys
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

    #[test]
    fn needs_rotation_and_recv_exhausted() {
        let limits = AeadLimits::new(u64::MAX, 20);
        let mut sender = RatchetedSession::with_defaults(test_keys());
        let mut receiver = RatchetedSession::new(peer_keys(), limits);

        assert!(!receiver.needs_rotation());
        assert!(!receiver.recv_exhausted());

        // 10 bytes plaintext → 26 bytes ciphertext → 10 bytes counted
        let msg = sender.encrypt(b"0123456789").unwrap();
        receiver.decrypt(&msg).unwrap();
        assert!(!receiver.recv_exhausted());

        // Another 10 → total 20 → exhausted
        let msg2 = sender.encrypt(b"0123456789").unwrap();
        receiver.decrypt(&msg2).unwrap();
        assert!(receiver.recv_exhausted());
        assert!(receiver.needs_rotation());
    }

    #[test]
    fn limits_accessor() {
        let limits = AeadLimits::new(42, 99);
        let session = RatchetedSession::new(test_keys(), limits);
        assert_eq!(session.limits().max_messages, 42);
        assert_eq!(session.limits().max_bytes, 99);
    }

    #[test]
    fn recv_bytes_tracking() {
        let mut sender = RatchetedSession::with_defaults(test_keys());
        let mut receiver = RatchetedSession::with_defaults(peer_keys());

        let msg = sender.encrypt(b"hello").unwrap();
        receiver.decrypt(&msg).unwrap();
        assert_eq!(receiver.recv_messages(), 1);
        assert_eq!(receiver.recv_bytes(), 5);
    }

    #[test]
    fn rotate_resets_epoch_state() {
        let mut sender = RatchetedSession::with_defaults(test_keys());
        let mut receiver = RatchetedSession::with_defaults(peer_keys());

        // Epoch 1: one message, seq 0 lands in the receiver's window.
        let msg = sender.encrypt(b"epoch-1").unwrap();
        receiver.decrypt(&msg).unwrap();

        // Rotate both to mirrored keys (network layer's dh_ratchet step).
        let fresh_dh = [0x77u8; 32];
        let s_keys = ratchet::dh_ratchet(&sender.keys().root, &fresh_dh).unwrap();
        let r_keys_raw = ratchet::dh_ratchet(&receiver.keys().root, &fresh_dh).unwrap();
        let r_keys = RatchetKeys {
            root: r_keys_raw.root,
            send_chain: r_keys_raw.recv_chain,
            recv_chain: r_keys_raw.send_chain,
        };
        sender.rotate(s_keys);
        receiver.rotate(r_keys);

        // Epoch 2 counters are clean…
        assert_eq!(sender.send_messages(), 0);
        assert_eq!(receiver.recv_messages(), 0);

        // …and the first post-rotation message (seq 0 again) decrypts —
        // the replay window restarted with the epoch.
        let msg2 = sender.encrypt(b"epoch-2").unwrap();
        assert_eq!(receiver.decrypt(&msg2).unwrap(), b"epoch-2");
    }
}
