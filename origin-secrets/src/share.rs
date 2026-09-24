//! Share data structures and operations

use origin_crypto_sdk::pqc::falcon1024::FalconSignature;
use origin_crypto_sdk::signing::hybrid::Ed25519Falcon1024;
use origin_crypto_sdk::CryptoError;
use origin_crypto_sdk::Ed25519Signature;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Hybrid signature (Ed25519 + Falcon-1024)
///
/// Stored as raw bytes for JSON persistence; convert to/from the SDK's
/// [`Ed25519Falcon1024`] via [`HybridSignature::to_sdk`] / [`from_sdk`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct HybridSignature {
    pub ed25519: Vec<u8>,
    pub falcon1024: Vec<u8>,
}

impl HybridSignature {
    /// Build from the SDK's typed hybrid signature.
    pub fn from_sdk(sig: &Ed25519Falcon1024) -> Self {
        Self {
            ed25519: sig.ed25519_sig.to_bytes().to_vec(),
            falcon1024: sig.falcon_sig.as_bytes().to_vec(),
        }
    }

    /// Reconstruct the SDK's typed hybrid signature for verification.
    pub fn to_sdk(&self) -> Result<Ed25519Falcon1024, CryptoError> {
        let ed25519_sig = Ed25519Signature::from_bytes(
            self.ed25519
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidParameter("bad ed25519 sig length".into()))?,
        );
        let falcon_sig = FalconSignature::from_bytes(&self.falcon1024)?;
        Ok(Ed25519Falcon1024 {
            ed25519_sig,
            falcon_sig,
        })
    }
}

/// Share file format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
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
    /// ISO-8601 expiry time (P3.2). When set and in the past, the share is
    /// rejected by `verify` and `recover`. `None` means no expiry.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Verifier public keys (P3.4) enabling full hybrid-sig verification
    /// WITHOUT the vault. Embedded at share time so any holder can verify
    /// offline. `None` for legacy/plaintext shares (verify falls back to
    /// structural-only when no vault and no verifier is present).
    #[serde(default)]
    pub verifier: Option<ShareVerifier>,
}

/// Public keys needed to verify a share's hybrid signature, embedded in the
/// share file so verification does not require the vault (P3.4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct ShareVerifier {
    pub ed25519: Vec<u8>,
    pub falcon1024: Vec<u8>,
}

impl ShareVerifier {
    pub fn ed25519_pk(&self) -> Result<origin_crypto_sdk::Ed25519VerifyingKey, CryptoError> {
        let bytes: [u8; 32] = self
            .ed25519
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidParameter("bad ed25519 pubkey length".into()))?;
        origin_crypto_sdk::Ed25519VerifyingKey::from_bytes(&bytes)
            .map_err(|e| CryptoError::InvalidParameter(format!("{e}")))
    }

    pub fn falcon_pk(
        &self,
    ) -> Result<origin_crypto_sdk::pqc::falcon1024::FalconPublicKey, CryptoError> {
        origin_crypto_sdk::pqc::falcon1024::FalconPublicKey::from_bytes(&self.falcon1024)
    }
}

/// On-disk envelope for an encrypted share (P3.3). The inner `Share` JSON is
/// sealed with XChaCha20-Poly1305 under a key derived from the vault master
/// seed, so local shares are opaque at rest. Readers decrypt when the vault is
/// available and fall back to plaintext for backward compatibility / exported
/// shares.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedShare {
    pub version: u8,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle;

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
    fn test_hybrid_signature_sdk_roundtrip() {
        // Deterministic seed -> stable keypair (no slow keygen in path beyond one derive)
        let seed = [7u8; 32];
        let bundle =
            HybridSigningKeyBundle::from_seed(&seed, "origin-secrets/test").expect("valid seed");
        let sdk_sig = bundle.sign_hybrid(b"vault-master-key");
        let stored = HybridSignature::from_sdk(&sdk_sig);
        let restored = stored.to_sdk().expect("rebuild from bytes");
        // Field equality proves byte-preserving conversion
        assert_eq!(stored.ed25519, restored.ed25519_sig.to_bytes().to_vec());
        assert_eq!(stored.falcon1024, restored.falcon_sig.as_bytes().to_vec());
    }

    #[test]
    fn test_share_json_golden_vector_v1() {
        let share = Share {
            version: 1,
            key_id: "test-key".to_string(),
            share_number: 1,
            threshold: 3,
            total_shares: 5,
            share_data: vec![1, 2, 3],
            fingerprint: "abc123".to_string(),
            signature: HybridSignature {
                ed25519: vec![4, 5],
                falcon1024: vec![6, 7],
            },
            created_at: "2026-07-30T21:27:45Z".to_string(),
            recipient: Some("alice@company.com".to_string()),
            expires_at: Some("2027-01-01T00:00:00Z".to_string()),
            verifier: Some(ShareVerifier {
                ed25519: vec![8, 9],
                falcon1024: vec![10, 11],
            }),
        };
        assert_eq!(
            serde_json::to_string(&share).unwrap(),
            r#"{"version":1,"key_id":"test-key","share_number":1,"threshold":3,"total_shares":5,"share_data":[1,2,3],"fingerprint":"abc123","signature":{"ed25519":[4,5],"falcon1024":[6,7]},"created_at":"2026-07-30T21:27:45Z","recipient":"alice@company.com","expires_at":"2027-01-01T00:00:00Z","verifier":{"ed25519":[8,9],"falcon1024":[10,11]}}"#
        );
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
            expires_at: None,
            verifier: None,
        };

        let serialized = serde_json::to_string(&share).unwrap();
        let deserialized: Share = serde_json::from_str(&serialized).unwrap();

        assert_eq!(share.key_id, deserialized.key_id);
        assert_eq!(share.share_number, deserialized.share_number);
        assert_eq!(share.threshold, deserialized.threshold);
        assert_eq!(share.recipient, deserialized.recipient);
    }
}
