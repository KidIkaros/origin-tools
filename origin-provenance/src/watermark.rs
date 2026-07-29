// SPDX-License-Identifier: Apache-2.0

//! Watermarks — provenance markers embedded in file metadata.
//!
//! A watermark is a small JSON payload appended to the end of a file,
//! delimited by a magic marker. It records the content hash of the
//! original file (before watermarking) and a timestamp.
//!
//! Format:
//! ```text
//! [original file bytes]
//! \n---ORIGIN-PROVENANCE-v1---\n
//! {"content_hash":"…","size":…,"timestamp":…}\n
//! ---END-ORIGIN-PROVENANCE---\n
//! ```

use serde::{Deserialize, Serialize};

use origin_crypto_sdk::sha3_256;

use crate::error::{ProvenanceError, Result};

const MARKER_START: &str = "\n---ORIGIN-PROVENANCE-v1---\n";
const MARKER_END: &str = "---END-ORIGIN-PROVENANCE---\n";

/// A watermark record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Watermark {
    /// SHA3-256 hash of the original content (before watermark).
    pub content_hash: String,
    /// Original file size in bytes.
    pub size: u64,
    /// Unix timestamp when the watermark was applied.
    pub timestamp: u64,
    /// Optional label (e.g. signer identity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Watermark {
    /// Create a watermark for the given content.
    pub fn new(content: &[u8], label: Option<String>) -> Self {
        Watermark {
            content_hash: hex::encode(sha3_256(content)),
            size: content.len() as u64,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            label,
        }
    }

    /// Embed this watermark into file content, returning the watermarked bytes.
    pub fn embed(&self, content: &[u8]) -> Result<Vec<u8>> {
        let json = serde_json::to_string(self)
            .map_err(|e| ProvenanceError::InvalidStamp(e.to_string()))?;
        let mut out = Vec::with_capacity(content.len() + MARKER_START.len() + json.len() + MARKER_END.len() + 1);
        out.extend_from_slice(content);
        out.extend_from_slice(MARKER_START.as_bytes());
        out.extend_from_slice(json.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(MARKER_END.as_bytes());
        Ok(out)
    }

    /// Extract a watermark from watermarked content.
    /// Returns (watermark, original_content).
    pub fn extract(data: &[u8]) -> Result<(Self, Vec<u8>)> {
        let start_marker = MARKER_START.as_bytes();
        let end_marker = MARKER_END.as_bytes();

        // Find start marker in raw bytes (avoids UTF-8 lossy position mismatch)
        let start_pos = data
            .windows(start_marker.len())
            .position(|w| w == start_marker)
            .ok_or_else(|| ProvenanceError::InvalidStamp("no watermark marker found".into()))?;

        let json_start = start_pos + start_marker.len();
        let end_pos = data[json_start..]
            .windows(end_marker.len())
            .position(|w| w == end_marker)
            .ok_or_else(|| ProvenanceError::InvalidStamp("no watermark end marker".into()))?
            + json_start;

        let json_bytes = &data[json_start..end_pos];
        let json_str = std::str::from_utf8(json_bytes)
            .map_err(|e| ProvenanceError::InvalidStamp(format!("watermark not valid UTF-8: {e}")))?
            .trim();
        let watermark: Watermark = serde_json::from_str(json_str)
            .map_err(|e| ProvenanceError::InvalidStamp(format!("bad watermark JSON: {e}")))?;

        let original = data[..start_pos].to_vec();
        Ok((watermark, original))
    }

    /// Check whether data contains a watermark.
    pub fn has_watermark(data: &[u8]) -> bool {
        let text = String::from_utf8_lossy(data);
        text.contains(MARKER_START)
    }

    /// Verify that the watermark's hash matches the extracted original content.
    pub fn verify(&self, original: &[u8]) -> bool {
        let hash = hex::encode(sha3_256(original));
        hash == self.content_hash && original.len() as u64 == self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_and_extract() {
        let content = b"important document content";
        let wm = Watermark::new(content, Some("test-signer".into()));
        let watermarked = wm.embed(content).unwrap();

        assert!(Watermark::has_watermark(&watermarked));
        assert!(!Watermark::has_watermark(content));

        let (extracted, original) = Watermark::extract(&watermarked).unwrap();
        assert_eq!(original, content);
        assert!(extracted.verify(&original));
        assert_eq!(extracted.label.as_deref(), Some("test-signer"));
    }

    #[test]
    fn tamper_detection() {
        let content = b"original data";
        let wm = Watermark::new(content, None);
        let watermarked = wm.embed(content).unwrap();

        let (extracted, original) = Watermark::extract(&watermarked).unwrap();
        assert!(extracted.verify(&original));
        assert!(!extracted.verify(b"tampered data"));
    }

    #[test]
    fn no_watermark_returns_error() {
        let result = Watermark::extract(b"plain file with no watermark");
        assert!(result.is_err());
    }

    #[test]
    fn binary_content_watermark() {
        let content: Vec<u8> = (0..=255).collect();
        let wm = Watermark::new(&content, None);
        let watermarked = wm.embed(&content).unwrap();
        let (extracted, original) = Watermark::extract(&watermarked).unwrap();
        assert_eq!(original, content);
        assert!(extracted.verify(&original));
    }
}
