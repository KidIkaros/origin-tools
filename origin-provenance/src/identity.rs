// SPDX-License-Identifier: Apache-2.0

//! Signer identity for OPM manifests (spec §3).
//!
//! A `Signer` binds a hybrid signing bundle to its stable fingerprint.
//! Signature production goes through `try_sign_hybrid` exclusively — the
//! panicking `sign_hybrid` is banned in this crate (spec §1).

use crate::encoding::{signer_fingerprint, SIGNER_DOMAIN};
use origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle;
use origin_crypto_sdk::signing::wire::HybridSig;

/// Public key material carried inside signed structures (P-03 schema
/// amendment — same transitive-authentication pattern as origin-identity
/// spec S2 and ticket 08: a fingerprint is a commitment to keys; carrying
/// the keys lets an offline verifier recompute and check the commitment).
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignerKeys {
    /// Hex Ed25519 public key (64 chars).
    pub ed25519_pk: String,
    /// Hex Falcon-1024 public key (3586 chars).
    pub falcon_pk: String,
}

/// A manifest signer: hybrid key bundle + derived fingerprint.
pub struct Signer {
    bundle: HybridSigningKeyBundle,
    fingerprint: [u8; 32],
}

impl SignerKeys {
    /// Base64 (S4 convention) ↔ `HybridSig`, re-exposed from `Signer` for
    /// structures that carry keys without a signer instance (P-03 pattern
    /// consumers such as license tokens).
    pub fn hybrid_sig_to_base64(sig: &HybridSig) -> crate::error::Result<String> {
        Signer::hybrid_sig_to_base64(sig)
    }

    /// Decode a base64 S4 string back into a `HybridSig`.
    pub fn hybrid_sig_from_base64(s: &str) -> crate::error::Result<HybridSig> {
        Signer::hybrid_sig_from_base64(s)
    }
}

impl Signer {
    /// Derive a signer from a 32-byte seed (spec §3 domain).
    pub fn from_seed(seed: &[u8; 32]) -> origin_crypto_sdk::Result<Self> {
        let bundle = HybridSigningKeyBundle::from_seed(seed, SIGNER_DOMAIN)?;
        let fingerprint = signer_fingerprint(
            &bundle.ed25519_pk().as_bytes()[..]
                .try_into()
                .expect("ed25519 pk is 32 bytes"),
            bundle.falcon1024_pk().as_bytes(),
        )?;
        Ok(Self {
            bundle,
            fingerprint,
        })
    }

    /// Hex-encoded signer fingerprint (64 chars).
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }

    /// Raw fingerprint bytes (the value that enters checkpoint payloads).
    pub fn fingerprint_raw(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Public keys as raw bytes: `(ed25519(32), falcon(1793))`.
    pub fn pk_bytes(&self) -> ([u8; 32], Vec<u8>) {
        (
            *self.bundle.ed25519_pk().as_bytes(),
            self.bundle.falcon1024_pk().as_bytes().to_vec(),
        )
    }

    /// The key material embedded in signed structures (P-03 amendment).
    pub fn public_keys(&self) -> SignerKeys {
        let (ed, falcon) = self.pk_bytes();
        SignerKeys {
            ed25519_pk: hex::encode(ed),
            falcon_pk: hex::encode(falcon),
        }
    }

    /// Sign `msg` with the hybrid bundle (fallible path only).
    pub fn sign(&self, msg: &[u8]) -> origin_crypto_sdk::Result<HybridSig> {
        Ok(HybridSig::from_sig(&self.bundle.try_sign_hybrid(msg)?))
    }

    /// Base64 (standard alphabet, padded) of `HybridSig::encode` — the S4
    /// manifest convention. Inverse of [`Self::hybrid_sig_from_base64`].
    pub fn hybrid_sig_to_base64(sig: &HybridSig) -> crate::error::Result<String> {
        let mut buf = Vec::new();
        sig.encode(&mut buf)
            .map_err(|e| crate::error::ProvenanceError::SignatureError(e.to_string()))?;
        use base64::Engine as _;
        Ok(base64::engine::general_purpose::STANDARD.encode(&buf))
    }

    /// Decode a base64 S4 string back into a `HybridSig`.
    pub fn hybrid_sig_from_base64(s: &str) -> crate::error::Result<HybridSig> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| {
                crate::error::ProvenanceError::SignatureError(format!(
                    "bad base64 hybrid signature: {e}"
                ))
            })?;
        let mut pos = 0usize;
        HybridSig::decode(&raw, &mut pos)
            .map_err(|e| crate::error::ProvenanceError::SignatureError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_A: [u8; 32] = [1u8; 32];
    const SEED_B: [u8; 32] = [2u8; 32];

    #[test]
    fn signer_deterministic_and_distinct() {
        let a = Signer::from_seed(&SEED_A).expect("seed derives");
        let a2 = Signer::from_seed(&SEED_A).expect("seed derives");
        let b = Signer::from_seed(&SEED_B).expect("seed derives");
        assert_eq!(a.fingerprint_hex(), a2.fingerprint_hex());
        assert_ne!(a.fingerprint_hex(), b.fingerprint_hex());
        assert_eq!(a.fingerprint_hex().len(), 64);
    }

    #[test]
    fn pk_sizes_match_spec() {
        let a = Signer::from_seed(&SEED_A).expect("seed derives");
        let (ed, falcon) = a.pk_bytes();
        assert_eq!(ed.len(), 32);
        // Falcon-1024 pk: 1793 bytes (Python-measured, ticket 08).
        assert_eq!(falcon.len(), 1793);
    }

    #[test]
    fn fingerprint_matches_encoding_recipe() {
        // Signer's fingerprint must equal the standalone encoding recipe
        // over the same public keys (identity ↔ encoding coherence).
        let a = Signer::from_seed(&SEED_A).expect("seed derives");
        let (ed, falcon) = a.pk_bytes();
        let expect = signer_fingerprint(&ed, &falcon).expect("recipe total");
        assert_eq!(a.fingerprint_raw(), expect);
    }

    #[test]
    fn sign_verify_roundtrip_via_wire() {
        let a = Signer::from_seed(&SEED_A).expect("seed derives");
        let (ed, falcon) = a.pk_bytes();
        let msg = b"origin-provenance:checkpoint:v1-roundtrip";
        let sig = a.sign(msg).expect("try_sign_hybrid ok");
        sig.verify(&ed, &falcon, msg).expect("both halves verify");
        // Tampered message must fail.
        assert!(sig.verify(&ed, &falcon, b"tampered").is_err());
    }

    #[test]
    fn base64_s4_roundtrip() {
        let a = Signer::from_seed(&SEED_A).expect("seed derives");
        let sig = a.sign(b"s4 roundtrip").expect("sign ok");
        let b64 = Signer::hybrid_sig_to_base64(&sig).expect("encode ok");
        let back = Signer::hybrid_sig_from_base64(&b64).expect("decode ok");
        assert_eq!(sig, back);
        // Standard alphabet + padding: no URL-safe chars, padded length.
        assert!(b64.ends_with('=') || b64.len().is_multiple_of(4));
        assert!(!b64.contains('-') && !b64.contains('_'));
    }
}
