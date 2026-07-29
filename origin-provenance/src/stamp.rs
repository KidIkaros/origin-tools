// SPDX-License-Identifier: Apache-2.0

//! Provenance stamps — cryptographic fingerprints for files.
//!
//! A stamp binds a file's content hash to a timestamp and an optional
//! Ed25519 signature, producing a tamper-evident record of the file's
//! state at a point in time.

use serde::{Deserialize, Serialize};

use origin_crypto_sdk::sha3_256;

use crate::error::{ProvenanceError, Result};

/// Stamp format version.
pub const STAMP_VERSION: u8 = 1;

/// A provenance stamp for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stamp {
    /// Format version.
    pub version: u8,
    /// SHA3-256 hash of the file content (hex-encoded).
    pub content_hash: String,
    /// File size in bytes.
    pub size: u64,
    /// Unix timestamp (seconds) when the stamp was created.
    pub timestamp: u64,
    /// Optional Ed25519 signature over the stamp payload (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Optional signer identity fingerprint (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

impl Stamp {
    /// Create a stamp for the given file content.
    pub fn new(content: &[u8], timestamp: u64) -> Self {
        Stamp {
            version: STAMP_VERSION,
            content_hash: hex::encode(sha3_256(content)),
            size: content.len() as u64,
            timestamp,
            signature: None,
            signer: None,
        }
    }

    /// Create a stamp by reading a file from disk.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read(path)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(Stamp::new(&content, timestamp))
    }

    /// The canonical bytes that get signed: version ‖ hash ‖ size ‖ timestamp.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(self.version);
        payload.extend_from_slice(self.content_hash.as_bytes());
        payload.extend_from_slice(&self.size.to_le_bytes());
        payload.extend_from_slice(&self.timestamp.to_le_bytes());
        payload
    }

    /// Verify that a content hash matches this stamp.
    pub fn verify_content(&self, content: &[u8]) -> bool {
        let hash = hex::encode(sha3_256(content));
        hash == self.content_hash && content.len() as u64 == self.size
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| ProvenanceError::InvalidStamp(e.to_string()))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| ProvenanceError::InvalidStamp(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_roundtrip() {
        let content = b"hello provenance";
        let stamp = Stamp::new(content, 1700000000);
        assert!(stamp.verify_content(content));
        assert!(!stamp.verify_content(b"tampered"));

        let json = stamp.to_json().unwrap();
        let parsed = Stamp::from_json(&json).unwrap();
        assert_eq!(parsed.content_hash, stamp.content_hash);
        assert_eq!(parsed.size, stamp.size);
        assert_eq!(parsed.timestamp, stamp.timestamp);
    }

    #[test]
    fn signing_payload_deterministic() {
        let stamp = Stamp::new(b"data", 42);
        let p1 = stamp.signing_payload();
        let p2 = stamp.signing_payload();
        assert_eq!(p1, p2);
        assert!(!p1.is_empty());
    }

    #[test]
    fn different_content_different_hash() {
        let a = Stamp::new(b"file A", 1);
        let b = Stamp::new(b"file B", 1);
        assert_ne!(a.content_hash, b.content_hash);
    }
}
