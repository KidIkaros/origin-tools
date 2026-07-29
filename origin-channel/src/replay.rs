// SPDX-License-Identifier: Apache-2.0

//! Replay protection — bounded reordering window.
//!
//! Accepts messages within a sliding window of the highest seen sequence
//! number. Messages below the window floor are rejected as replays.
//! Messages within the window are checked against a bitmap.

use crate::error::{ChannelError, Result};

/// Default window size (number of sequence numbers tracked).
pub const DEFAULT_WINDOW_SIZE: usize = 1024;

/// Sliding-window replay detector.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest sequence number accepted so far.
    highest: u64,
    /// Bitmap of seen offsets relative to (highest - window_size + 1).
    /// Bit i is set if sequence (floor + i) has been seen.
    bitmap: Vec<u64>,
    window_size: usize,
    /// Whether at least one message has been accepted.
    initialized: bool,
}

impl ReplayWindow {
    pub fn new(window_size: usize) -> Self {
        let words = (window_size + 63) / 64;
        ReplayWindow {
            highest: 0,
            bitmap: vec![0u64; words],
            window_size,
            initialized: false,
        }
    }

    /// Check whether a sequence number is acceptable and mark it seen.
    /// Returns Err(Replay) if the message is a duplicate or too old.
    pub fn accept(&mut self, seq: u64) -> Result<()> {
        if !self.initialized {
            // First message ever
            self.initialized = true;
            self.highest = seq;
            self.set_bit(0);
            return Ok(());
        }

        let floor = self.highest.saturating_sub(self.window_size as u64 - 1);

        if seq < floor {
            return Err(ChannelError::Replay(seq));
        }

        if seq > self.highest {
            // Advance window
            let shift = (seq - self.highest) as usize;
            self.advance(shift);
            self.highest = seq;
        }

        let offset = (seq - self.highest.saturating_sub(self.window_size as u64 - 1)) as usize;
        if offset >= self.window_size {
            return Err(ChannelError::Replay(seq));
        }

        if self.get_bit(offset) {
            return Err(ChannelError::Replay(seq));
        }

        self.set_bit(offset);
        Ok(())
    }

    fn advance(&mut self, shift: usize) {
        if shift >= self.window_size {
            // Entire window is stale — clear everything
            for word in self.bitmap.iter_mut() {
                *word = 0;
            }
            return;
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        if word_shift > 0 {
            for i in 0..self.bitmap.len() {
                self.bitmap[i] = if i + word_shift < self.bitmap.len() {
                    self.bitmap[i + word_shift]
                } else {
                    0
                };
            }
        }

        if bit_shift > 0 {
            for i in 0..self.bitmap.len() {
                self.bitmap[i] >>= bit_shift;
                if i + 1 < self.bitmap.len() {
                    self.bitmap[i] |= self.bitmap[i + 1] << (64 - bit_shift);
                }
            }
        }
    }

    fn get_bit(&self, offset: usize) -> bool {
        let word = offset / 64;
        let bit = offset % 64;
        if word >= self.bitmap.len() {
            return false;
        }
        (self.bitmap[word] >> bit) & 1 == 1
    }

    fn set_bit(&mut self, offset: usize) {
        let word = offset / 64;
        let bit = offset % 64;
        if word < self.bitmap.len() {
            self.bitmap[word] |= 1 << bit;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_accepted() {
        let mut w = ReplayWindow::new(64);
        for i in 0..100 {
            assert!(w.accept(i).is_ok(), "seq {i} should be accepted");
        }
    }

    #[test]
    fn duplicate_rejected() {
        let mut w = ReplayWindow::new(64);
        assert!(w.accept(0).is_ok());
        assert!(w.accept(1).is_ok());
        assert!(w.accept(1).is_err()); // duplicate
    }

    #[test]
    fn out_of_order_within_window() {
        let mut w = ReplayWindow::new(64);
        assert!(w.accept(0).is_ok());
        assert!(w.accept(5).is_ok());
        assert!(w.accept(3).is_ok()); // out of order but in window
        assert!(w.accept(3).is_err()); // duplicate
    }

    #[test]
    fn too_old_rejected() {
        let mut w = ReplayWindow::new(64);
        // Advance window far ahead
        assert!(w.accept(0).is_ok());
        assert!(w.accept(200).is_ok());
        // seq 0 is now way below the floor
        assert!(w.accept(0).is_err());
    }

    #[test]
    fn large_jump_clears_window() {
        let mut w = ReplayWindow::new(64);
        assert!(w.accept(0).is_ok());
        assert!(w.accept(1000).is_ok());
        // Old sequences are gone
        assert!(w.accept(999).is_ok()); // within new window
        assert!(w.accept(0).is_err()); // way below floor
    }
}
