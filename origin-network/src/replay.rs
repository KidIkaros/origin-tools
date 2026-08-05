// SPDX-License-Identifier: Apache-2.0

//! Handshake replay protection — the signet-daemon pattern (spec §6.4).
//!
//! Track the first 8 bytes of each inbound handshake frame; reject an
//! identical replayed frame before any expensive ECDH work. The tracker
//! loads from / persists to disk so replays are rejected across restarts.
//!
//! Note: per-SESSION replay is origin-channel's nonce_tracker job; this
//! is per-CONNECTION handshake-frame dedup.

use std::collections::HashSet;
use std::path::Path;

use crate::error::{NetworkError, Result};

/// Number of leading frame bytes tracked as the replay nonce.
pub const REPLAY_NONCE_LEN: usize = 8;

/// File magic for the persisted tracker state.
const MAGIC: &[u8; 4] = b"ONRP";
/// Persisted-state format version.
const FORMAT_VERSION: u8 = 1;

/// Tracks seen handshake frame nonces (first 8 bytes).
#[derive(Default)]
pub struct HandshakeReplayTracker {
    seen: HashSet<[u8; REPLAY_NONCE_LEN]>,
}

impl HandshakeReplayTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check a handshake frame and record its nonce.
    /// Returns `true` if the frame is fresh (not a replay), `false` if it
    /// was seen before. Frames shorter than 8 bytes are always fresh
    /// (cannot collide with a recorded nonce).
    pub fn check_and_track(&mut self, frame: &[u8]) -> bool {
        if frame.len() < REPLAY_NONCE_LEN {
            return true;
        }
        let nonce: [u8; REPLAY_NONCE_LEN] = frame[..REPLAY_NONCE_LEN].try_into().unwrap();
        self.seen.insert(nonce)
    }

    /// Number of tracked nonces.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Persist the tracker state to disk (atomic write via origin-common).
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut buf = Vec::with_capacity(5 + self.seen.len() * REPLAY_NONCE_LEN);
        buf.extend_from_slice(MAGIC);
        buf.push(FORMAT_VERSION);
        for nonce in &self.seen {
            buf.extend_from_slice(nonce);
        }
        origin_common::atomic_write(path, &buf)
            .map_err(|e| NetworkError::Transport(format!("replay state save: {e}")))?;
        Ok(())
    }

    /// Load tracker state from disk. Missing file → empty tracker (first
    /// run). Corrupt file → error (never silently drop replay protection).
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => {
                return Err(NetworkError::Transport(format!("replay state read: {e}")));
            }
        };
        if bytes.len() < 5 {
            return Err(NetworkError::Transport("replay state truncated".into()));
        }
        if &bytes[..4] != MAGIC {
            return Err(NetworkError::Transport("bad replay state magic".into()));
        }
        if bytes[4] != FORMAT_VERSION {
            return Err(NetworkError::Transport(format!(
                "unknown replay state version {}",
                bytes[4]
            )));
        }
        let body = &bytes[5..];
        if body.len() % REPLAY_NONCE_LEN != 0 {
            return Err(NetworkError::Transport(
                "replay state body misaligned".into(),
            ));
        }
        let mut seen = HashSet::new();
        for chunk in body.chunks_exact(REPLAY_NONCE_LEN) {
            let mut nonce = [0u8; REPLAY_NONCE_LEN];
            nonce.copy_from_slice(chunk);
            seen.insert(nonce);
        }
        Ok(Self { seen })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_frame_accepted_once() {
        let mut t = HandshakeReplayTracker::new();
        assert!(t.check_and_track(b"abcdefgh-payload"));
        assert!(!t.check_and_track(b"abcdefgh-other")); // same 8 bytes = replay
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn distinct_frames_tracked() {
        let mut t = HandshakeReplayTracker::new();
        assert!(t.check_and_track(b"frame-01"));
        assert!(t.check_and_track(b"frame-02"));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn short_frames_always_fresh() {
        let mut t = HandshakeReplayTracker::new();
        assert!(t.check_and_track(b"short"));
        assert!(t.check_and_track(b"short")); // < 8 bytes never tracked
        assert!(t.is_empty());
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.bin");

        let mut t = HandshakeReplayTracker::new();
        t.check_and_track(b"nonce-aa-extra");
        t.check_and_track(b"nonce-bb-extra");
        t.save(&path).unwrap();

        let loaded = HandshakeReplayTracker::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        // Replays are still rejected after restart.
        let mut loaded = loaded;
        assert!(!loaded.check_and_track(b"nonce-aa-new"));
        assert!(loaded.check_and_track(b"nonce-cc-new"));
    }

    #[test]
    fn load_missing_file_gives_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.bin");
        let t = HandshakeReplayTracker::load(&path).unwrap();
        assert!(t.is_empty());
    }

    #[test]
    fn load_corrupt_state_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.bin");

        std::fs::write(&path, b"XX").unwrap(); // truncated
        assert!(HandshakeReplayTracker::load(&path).is_err());

        std::fs::write(&path, b"BADG\x01").unwrap(); // wrong magic
        assert!(HandshakeReplayTracker::load(&path).is_err());

        std::fs::write(&path, b"ONRP\x09").unwrap(); // wrong version
        assert!(HandshakeReplayTracker::load(&path).is_err());

        // Misaligned body (5 bytes of nonces is not a multiple of 8).
        let mut bad = Vec::new();
        bad.extend_from_slice(b"ONRP");
        bad.push(1);
        bad.extend_from_slice(&[0u8; 5]);
        std::fs::write(&path, &bad).unwrap();
        assert!(HandshakeReplayTracker::load(&path).is_err());
    }

    #[test]
    fn save_empty_then_load_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        let t = HandshakeReplayTracker::new();
        t.save(&path).unwrap();
        let loaded = HandshakeReplayTracker::load(&path).unwrap();
        assert!(loaded.is_empty());
    }
}
