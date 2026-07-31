//! Share data structures and operations

use serde::{Deserialize, Serialize};

/// Hybrid signature (Ed25519 + Falcon-1024)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HybridSignature {
    pub ed25519: Vec<u8>,
    pub falcon1024: Vec<u8>,
}

/// Share file format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Share {
    pub version: u8,
    pub key_id: String,
    pub share_number: u8,
    pub threshold: u8,
    pub total_shares: u8,
    pub share_data: Vec<u8>,
    pub fingerprint: String,
    pub signature: HybridSignature,
    pub created_at: String,
    pub recipient: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_signature_roundtrip() {
        let sig = HybridSignature {
            ed25519: vec![1u8; 64],
            falcon1024: vec![2u8; 1332],
        };

        let serialized = serde_json::to_string(&sig).unwrap();
        let deserialized: HybridSignature = serde_json::from_str(&serialized).unwrap();

        assert_eq!(sig.ed25519, deserialized.ed25519);
        assert_eq!(sig.falcon1024, deserialized.falcon1024);
    }

    #[test]
    fn test_share_roundtrip() {
        let share = Share {
            version: 1,
            key_id: "test-key".to_string(),
            share_number: 1,
            threshold: 3,
            total_shares: 5,
            share_data: vec![1, 2, 3, 4, 5],
            fingerprint: "abc123".to_string(),
            signature: HybridSignature {
                ed25519: vec![1u8; 64],
                falcon1024: vec![2u8; 1332],
            },
            created_at: "2026-07-30T21:27:45Z".to_string(),
            recipient: Some("alice@company.com".to_string()),
        };

        let serialized = serde_json::to_string(&share).unwrap();
        let deserialized: Share = serde_json::from_str(&serialized).unwrap();

        assert_eq!(share.key_id, deserialized.key_id);
        assert_eq!(share.share_number, deserialized.share_number);
        assert_eq!(share.threshold, deserialized.threshold);
        assert_eq!(share.recipient, deserialized.recipient);
    }
}