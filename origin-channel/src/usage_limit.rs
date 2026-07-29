// SPDX-License-Identifier: Apache-2.0

//! AEAD usage-limit enforcement (RFC 9846 §5.2 inspired).
//!
//! Each ratchet epoch (the interval between DH ratchet steps) has a
//! finite budget of messages and bytes. When either budget is exhausted
//! the tracker signals that a key rotation is required and refuses
//! further encryption/decryption until the epoch is reset.
//!
//! Defaults are conservative:
//! - 2^20 (1 048 576) messages per direction per epoch
//! - 2^34 (16 GiB) plaintext bytes per direction per epoch
//!
//! Both are configurable via [`AeadLimits`].

use crate::error::{ChannelError, Result};

/// Default maximum messages per direction per ratchet epoch.
pub const DEFAULT_MAX_MESSAGES: u64 = 1 << 20; // 1 048 576

/// Default maximum plaintext bytes per direction per ratchet epoch.
pub const DEFAULT_MAX_BYTES: u64 = 1 << 34; // 16 GiB

/// Configurable AEAD usage limits for a single ratchet epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadLimits {
    /// Maximum messages per direction before rotation is required.
    pub max_messages: u64,
    /// Maximum plaintext bytes per direction before rotation is required.
    pub max_bytes: u64,
}

impl Default for AeadLimits {
    fn default() -> Self {
        AeadLimits {
            max_messages: DEFAULT_MAX_MESSAGES,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

impl AeadLimits {
    /// Create custom limits.
    pub fn new(max_messages: u64, max_bytes: u64) -> Self {
        AeadLimits {
            max_messages,
            max_bytes,
        }
    }

    /// Very small limits for testing.
    #[cfg(test)]
    pub fn tiny(max_messages: u64, max_bytes: u64) -> Self {
        AeadLimits {
            max_messages,
            max_bytes,
        }
    }
}

/// Per-direction usage counters within a single ratchet epoch.
#[derive(Debug, Clone, Default)]
struct DirectionUsage {
    messages: u64,
    bytes: u64,
}

/// Tracks AEAD usage for both send and receive directions.
///
/// Call [`check_send`](AeadUsageTracker::check_send) before encrypting
/// and [`check_recv`](AeadUsageTracker::check_recv) before decrypting.
/// Both return `Err(UsageLimitExceeded)` when the epoch budget is
/// exhausted. After a DH ratchet step, call
/// [`reset`](AeadUsageTracker::reset) to start a fresh epoch.
#[derive(Debug, Clone)]
pub struct AeadUsageTracker {
    limits: AeadLimits,
    send: DirectionUsage,
    recv: DirectionUsage,
}

impl AeadUsageTracker {
    /// Create a tracker with the given limits.
    pub fn new(limits: AeadLimits) -> Self {
        AeadUsageTracker {
            limits,
            send: DirectionUsage::default(),
            recv: DirectionUsage::default(),
        }
    }

    /// Create a tracker with default limits.
    pub fn with_defaults() -> Self {
        Self::new(AeadLimits::default())
    }

    /// Check whether sending `plaintext_len` bytes is within budget,
    /// and if so, record the usage. Call this **before** encrypting.
    ///
    /// Returns `Err(UsageLimitExceeded)` if either the message count
    /// or byte budget would be exceeded.
    pub fn check_send(&mut self, plaintext_len: usize) -> Result<()> {
        Self::check_and_record(&mut self.send, &self.limits, plaintext_len, "send")
    }

    /// Check whether receiving `ciphertext_len` bytes is within budget,
    /// and if so, record the usage. Call this **before** decrypting.
    ///
    /// The byte budget counts plaintext bytes; since ciphertext =
    /// plaintext + 16-byte tag, we subtract the tag to count plaintext.
    /// If the ciphertext is shorter than the tag (malformed), we count
    /// the full length conservatively.
    pub fn check_recv(&mut self, ciphertext_len: usize) -> Result<()> {
        let plaintext_len = ciphertext_len.saturating_sub(16); // AEAD tag
        Self::check_and_record(&mut self.recv, &self.limits, plaintext_len, "recv")
    }

    fn check_and_record(
        dir: &mut DirectionUsage,
        limits: &AeadLimits,
        plaintext_len: usize,
        direction: &str,
    ) -> Result<()> {
        let new_messages = dir.messages + 1;
        let new_bytes = dir.bytes + plaintext_len as u64;

        if new_messages > limits.max_messages {
            return Err(ChannelError::UsageLimitExceeded(format!(
                "{direction} message limit reached ({}/{})",
                dir.messages, limits.max_messages
            )));
        }
        if new_bytes > limits.max_bytes {
            return Err(ChannelError::UsageLimitExceeded(format!(
                "{direction} byte limit reached ({}/{})",
                dir.bytes, limits.max_bytes
            )));
        }

        dir.messages = new_messages;
        dir.bytes = new_bytes;
        Ok(())
    }

    /// Whether a key rotation is needed (either direction has hit a limit).
    pub fn needs_rotation(&self) -> bool {
        self.direction_exhausted(&self.send) || self.direction_exhausted(&self.recv)
    }

    /// Whether the send direction has hit a limit.
    pub fn send_exhausted(&self) -> bool {
        self.direction_exhausted(&self.send)
    }

    /// Whether the receive direction has hit a limit.
    pub fn recv_exhausted(&self) -> bool {
        self.direction_exhausted(&self.recv)
    }

    fn direction_exhausted(&self, d: &DirectionUsage) -> bool {
        d.messages >= self.limits.max_messages || d.bytes >= self.limits.max_bytes
    }

    /// Reset counters after a DH ratchet step (new epoch).
    pub fn reset(&mut self) {
        self.send = DirectionUsage::default();
        self.recv = DirectionUsage::default();
    }

    /// Current send message count.
    pub fn send_messages(&self) -> u64 {
        self.send.messages
    }

    /// Current send byte count.
    pub fn send_bytes(&self) -> u64 {
        self.send.bytes
    }

    /// Current receive message count.
    pub fn recv_messages(&self) -> u64 {
        self.recv.messages
    }

    /// Current receive byte count.
    pub fn recv_bytes(&self) -> u64 {
        self.recv.bytes
    }

    /// The configured limits.
    pub fn limits(&self) -> &AeadLimits {
        &self.limits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits() {
        let limits = AeadLimits::default();
        assert_eq!(limits.max_messages, 1 << 20);
        assert_eq!(limits.max_bytes, 1 << 34);
    }

    #[test]
    fn fresh_tracker_allows_send() {
        let mut t = AeadUsageTracker::with_defaults();
        assert!(t.check_send(100).is_ok());
        assert_eq!(t.send_messages(), 1);
        assert_eq!(t.send_bytes(), 100);
    }

    #[test]
    fn fresh_tracker_allows_recv() {
        let mut t = AeadUsageTracker::with_defaults();
        // 100 bytes ciphertext → 84 bytes plaintext (16-byte tag)
        assert!(t.check_recv(100).is_ok());
        assert_eq!(t.recv_messages(), 1);
        assert_eq!(t.recv_bytes(), 84);
    }

    #[test]
    fn message_limit_enforced() {
        let mut t = AeadUsageTracker::new(AeadLimits::tiny(3, u64::MAX));
        assert!(t.check_send(1).is_ok()); // 1
        assert!(t.check_send(1).is_ok()); // 2
        assert!(t.check_send(1).is_ok()); // 3
        assert!(t.send_exhausted());
        assert!(t.check_send(1).is_err()); // 4 → rejected
    }

    #[test]
    fn byte_limit_enforced() {
        let mut t = AeadUsageTracker::new(AeadLimits::tiny(u64::MAX, 100));
        assert!(t.check_send(60).is_ok());
        assert!(t.check_send(40).is_ok()); // exactly 100
        assert!(t.send_exhausted());
        assert!(t.check_send(1).is_err()); // over budget
    }

    #[test]
    fn recv_byte_limit_enforced() {
        let mut t = AeadUsageTracker::new(AeadLimits::tiny(u64::MAX, 50));
        // 66 bytes ciphertext → 50 bytes plaintext
        assert!(t.check_recv(66).is_ok());
        assert!(t.recv_exhausted());
        assert!(t.check_recv(17).is_err()); // would be 1 more byte
    }

    #[test]
    fn independent_directions() {
        let mut t = AeadUsageTracker::new(AeadLimits::tiny(1, u64::MAX));
        assert!(t.check_send(10).is_ok());
        assert!(t.send_exhausted());
        // Receive direction is independent
        assert!(!t.recv_exhausted());
        assert!(t.check_recv(26).is_ok());
    }

    #[test]
    fn reset_clears_counters() {
        let mut t = AeadUsageTracker::new(AeadLimits::tiny(1, u64::MAX));
        assert!(t.check_send(10).is_ok());
        assert!(t.send_exhausted());
        t.reset();
        assert!(!t.send_exhausted());
        assert!(!t.recv_exhausted());
        assert_eq!(t.send_messages(), 0);
        assert_eq!(t.send_bytes(), 0);
        assert!(t.check_send(10).is_ok());
    }

    #[test]
    fn needs_rotation_either_direction() {
        let mut t = AeadUsageTracker::new(AeadLimits::tiny(1, u64::MAX));
        assert!(!t.needs_rotation());
        t.check_send(1).unwrap();
        assert!(t.needs_rotation()); // send exhausted
        t.reset();
        assert!(!t.needs_rotation());
        t.check_recv(17).unwrap(); // 1 byte plaintext
        assert!(t.needs_rotation()); // recv exhausted
    }

    #[test]
    fn zero_length_message_counts() {
        let mut t = AeadUsageTracker::new(AeadLimits::tiny(2, u64::MAX));
        assert!(t.check_send(0).is_ok());
        assert_eq!(t.send_messages(), 1);
        assert_eq!(t.send_bytes(), 0);
        assert!(t.check_send(0).is_ok());
        assert!(t.send_exhausted());
    }

    #[test]
    fn recv_short_ciphertext_counts_full() {
        // Ciphertext shorter than tag (malformed) → count full length
        let mut t = AeadUsageTracker::new(AeadLimits::tiny(u64::MAX, 10));
        assert!(t.check_recv(5).is_ok()); // 5 < 16, saturating_sub → 0
        assert_eq!(t.recv_bytes(), 0);
        assert_eq!(t.recv_messages(), 1);
    }
}
