// SPDX-License-Identifier: Apache-2.0

//! Nonce tracking — ensures each (key, nonce) pair is used at most once.
//!
//! XChaCha20-Poly1305 uses 24-byte nonces. We derive nonces from a
//! monotonic counter: nonce = counter (8 bytes LE) ‖ zero padding (16 bytes).
//! Reusing a nonce with the same key is catastrophic for AEAD security,
//! so the tracker enforces strict monotonicity.

use crate::error::{ChannelError, Result};

/// Tracks the next nonce for a direction (send or receive).
#[derive(Debug, Clone)]
pub struct NonceTracker {
    next: u64,
    label: &'static str,
}

impl NonceTracker {
    pub fn new(label: &'static str) -> Self {
        NonceTracker { next: 0, label }
    }

    /// Allocate the next nonce. Increments the internal counter.
    pub fn next_nonce(&mut self) -> Result<[u8; 24]> {
        if self.next == u64::MAX {
            return Err(ChannelError::Other(format!(
                "{} nonce counter exhausted (2^64 messages)",
                self.label
            )));
        }
        let nonce = Self::counter_to_nonce(self.next);
        self.next += 1;
        Ok(nonce)
    }

    /// Current counter value (for diagnostics).
    pub fn counter(&self) -> u64 {
        self.next
    }

    /// Encode a counter as a 24-byte XChaCha20-Poly1305 nonce.
    /// Layout: counter (8 bytes LE) ‖ zeros (16 bytes).
    pub fn counter_to_nonce(counter: u64) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_nonces() {
        let mut tracker = NonceTracker::new("test");
        let n0 = tracker.next_nonce().unwrap();
        let n1 = tracker.next_nonce().unwrap();
        assert_ne!(n0, n1);
        assert_eq!(tracker.counter(), 2);
        // First nonce should be counter=0
        assert_eq!(&n0[..8], &0u64.to_le_bytes());
        assert_eq!(&n1[..8], &1u64.to_le_bytes());
    }

    #[test]
    fn nonce_padding_is_zero() {
        let nonce = NonceTracker::counter_to_nonce(42);
        assert_eq!(&nonce[8..], &[0u8; 16]);
    }
}
