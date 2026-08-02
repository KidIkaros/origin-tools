//! Unit tests for Share structures

use crate::share::{HybridSignature, Share};

#[test]
fn test_share_creation() {
    let share = Share {
        version: 1,
        key_id: "test-key".to_string(),
        share_number: 1,
        threshold: 3,
        total_shares: 5,
        share_data: vec![1, 2, 3, 4],
        fingerprint: "abc123".to_string(),
        signature: HybridSignature {
            ed25519: vec![5, 6, 7, 8],
            falcon1024: vec![9, 10, 11, 12],
        },
        created_at: "2026-07-30T21:27:45Z".to_string(),
        recipient: Some("alice@example.com".to_string()),
        expires_at: None,
        verifier: None,
    };

    assert_eq!(share.share_number, 1);
    assert_eq!(share.threshold, 3);
    assert_eq!(share.total_shares, 5);
    assert_eq!(share.share_data, vec![1, 2, 3, 4]);
}

#[test]
fn test_share_serialization_roundtrip() {
    let share = Share {
        version: 1,
        key_id: "test-key".to_string(),
        share_number: 2,
        threshold: 3,
        total_shares: 5,
        share_data: vec![1, 2, 3, 4, 5],
        fingerprint: "def456".to_string(),
        signature: HybridSignature {
            ed25519: vec![10, 20, 30],
            falcon1024: vec![40, 50, 60],
        },
        created_at: "2026-07-30T21:27:45Z".to_string(),
        recipient: Some("bob@example.com".to_string()),
        expires_at: None,
        verifier: None,
    };

    let serialized = serde_json::to_string(&share).unwrap();
    let deserialized: Share = serde_json::from_str(&serialized).unwrap();

    assert_eq!(share.share_number, deserialized.share_number);
    assert_eq!(share.threshold, deserialized.threshold);
    assert_eq!(share.total_shares, deserialized.total_shares);
    assert_eq!(share.share_data, deserialized.share_data);
    assert_eq!(share.recipient, deserialized.recipient);
    assert_eq!(share.signature.ed25519, deserialized.signature.ed25519);
    assert_eq!(
        share.signature.falcon1024,
        deserialized.signature.falcon1024
    );
}

#[test]
fn test_hybrid_signature_serialization() {
    let sig = HybridSignature {
        ed25519: vec![1, 2, 3],
        falcon1024: vec![4, 5, 6],
    };

    let serialized = serde_json::to_string(&sig).unwrap();
    let deserialized: HybridSignature = serde_json::from_str(&serialized).unwrap();

    assert_eq!(sig.ed25519, deserialized.ed25519);
    assert_eq!(sig.falcon1024, deserialized.falcon1024);
}

#[test]
fn test_share_roundtrip_file() {
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let path = temp_file.path();

    let share = Share {
        version: 1,
        key_id: "test-key".to_string(),
        share_number: 3,
        threshold: 3,
        total_shares: 5,
        share_data: vec![100, 101, 102],
        fingerprint: "ghi789".to_string(),
        signature: HybridSignature {
            ed25519: vec![200, 201],
            falcon1024: vec![202, 203],
        },
        created_at: "2026-07-30T21:27:45Z".to_string(),
        recipient: Some("carol@example.com".to_string()),
        expires_at: None,
        verifier: None,
    };

    let serialized = serde_json::to_string(&share).unwrap();
    std::fs::write(path, serialized).unwrap();

    let read_back = std::fs::read_to_string(path).unwrap();
    let deserialized: Share = serde_json::from_str(&read_back).unwrap();

    assert_eq!(share.share_number, deserialized.share_number);
    assert_eq!(share.recipient, deserialized.recipient);
}

#[test]
fn test_share_edge_cases() {
    // Test with threshold > total_shares (invalid but should still serialize)
    let share = Share {
        version: 1,
        key_id: "test-key".to_string(),
        share_number: 1,
        threshold: 5,
        total_shares: 3,
        share_data: vec![],
        fingerprint: "jkl012".to_string(),
        signature: HybridSignature {
            ed25519: vec![],
            falcon1024: vec![],
        },
        created_at: "2026-07-30T21:27:45Z".to_string(),
        recipient: None,
        expires_at: None,
        verifier: None,
    };

    let serialized = serde_json::to_string(&share).unwrap();
    let deserialized: Share = serde_json::from_str(&serialized).unwrap();

    assert_eq!(share.threshold, deserialized.threshold);
    assert_eq!(share.total_shares, deserialized.total_shares);
}

#[test]
fn test_share_with_large_data() {
    let large_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

    let share = Share {
        version: 1,
        key_id: "test-key".to_string(),
        share_number: 4,
        threshold: 3,
        total_shares: 5,
        share_data: large_data.clone(),
        fingerprint: "mno345".to_string(),
        signature: HybridSignature {
            ed25519: vec![1, 2, 3, 4, 5],
            falcon1024: vec![6, 7, 8, 9, 10],
        },
        created_at: "2026-07-30T21:27:45Z".to_string(),
        recipient: Some("dave@example.com".to_string()),
        expires_at: None,
        verifier: None,
    };

    let serialized = serde_json::to_string(&share).unwrap();
    let deserialized: Share = serde_json::from_str(&serialized).unwrap();

    assert_eq!(share.share_data, deserialized.share_data);
}

#[test]
fn test_share_with_unicode_recipient() {
    let share = Share {
        version: 1,
        key_id: "test-key".to_string(),
        share_number: 1,
        threshold: 2,
        total_shares: 4,
        share_data: vec![1, 2],
        fingerprint: "pqr678".to_string(),
        signature: HybridSignature {
            ed25519: vec![3, 4],
            falcon1024: vec![5, 6],
        },
        created_at: "2026-07-30T21:27:45Z".to_string(),
        recipient: Some("用户@example.com".to_string()),
        expires_at: None,
        verifier: None,
    };

    let serialized = serde_json::to_string(&share).unwrap();
    let deserialized: Share = serde_json::from_str(&serialized).unwrap();

    assert_eq!(share.recipient, deserialized.recipient);
}

#[test]
fn test_hybrid_signature_empty() {
    let sig = HybridSignature {
        ed25519: vec![],
        falcon1024: vec![],
    };

    let serialized = serde_json::to_string(&sig).unwrap();
    let deserialized: HybridSignature = serde_json::from_str(&serialized).unwrap();

    assert_eq!(sig.ed25519, deserialized.ed25519);
    assert_eq!(sig.falcon1024, deserialized.falcon1024);
}

#[test]
fn test_share_various_numbers() {
    for i in 0..10 {
        let share = Share {
            version: 1,
            key_id: "test-key".to_string(),
            share_number: i,
            threshold: 3,
            total_shares: 5,
            share_data: vec![i; 10],
            fingerprint: format!("fp-{}", i),
            signature: HybridSignature {
                ed25519: vec![i; 5],
                falcon1024: vec![i + 1; 5],
            },
            created_at: "2026-07-30T21:27:45Z".to_string(),
            recipient: Some(format!("share-{}.example.com", i)),
            expires_at: None,
            verifier: None,
        };

        let serialized = serde_json::to_string(&share).unwrap();
        let deserialized: Share = serde_json::from_str(&serialized).unwrap();

        assert_eq!(share.share_number, deserialized.share_number);
    }
}

#[test]
fn test_share_without_recipient() {
    let share = Share {
        version: 1,
        key_id: "test-key".to_string(),
        share_number: 1,
        threshold: 3,
        total_shares: 5,
        share_data: vec![1, 2, 3],
        fingerprint: "stu901".to_string(),
        signature: HybridSignature {
            ed25519: vec![1, 2],
            falcon1024: vec![3, 4],
        },
        created_at: "2026-07-30T21:27:45Z".to_string(),
        recipient: None,
        expires_at: None,
        verifier: None,
    };

    let serialized = serde_json::to_string(&share).unwrap();
    let deserialized: Share = serde_json::from_str(&serialized).unwrap();

    assert_eq!(share.recipient, deserialized.recipient);
    assert!(deserialized.recipient.is_none());
}
