// SPDX-License-Identifier: Apache-2.0

//! api — the typed library surface for origin-schnorr.
//!
//! EC Schnorr zero-knowledge proofs as plain function calls over in-memory
//! bytes. File I/O and identity resolution stay in the CLI layer
//! (`commands.rs`); these functions operate on keys and messages so any
//! application can plug in its own key management.
//!
//! Design rules (see ARCHITECTURE.md):
//! - One crypto provider: all proofs go through the SDK's `ec_schnorr` —
//!   nothing is re-implemented here.
//! - Errors are typed (`SchnorrError`), never `String`.

use crate::error::{Result, SchnorrError};
use origin_crypto_sdk::ec_schnorr::{self, EcSchnorrProof};

/// Deterministic keypair from a 32-byte seed.
///
/// Returns `(secret_key, public_key)`; the public key is a 33-byte
/// compressed SEC1 point.
pub fn keypair(seed: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    ec_schnorr::generate_keypair(seed)
}

/// Generate a zero-knowledge proof of knowledge of `secret` for `message`.
///
/// The public key is derived inside the SDK (`P = secret·G`) — a
/// caller-supplied key could be mismatched, producing a proof that can
/// never verify.
pub fn prove(secret: &[u8; 32], message: &[u8]) -> Result<EcSchnorrProof> {
    ec_schnorr::prove(secret, message).map_err(|e| SchnorrError::Proof(e.to_string()))
}

/// Verify a proof. `Ok(false)` means the proof is invalid (not an error).
pub fn verify(proof: &EcSchnorrProof, public_key: &[u8], message: &[u8]) -> Result<bool> {
    if public_key.is_empty() {
        return Err(SchnorrError::Validation("public_key is empty".into()));
    }
    ec_schnorr::verify(proof, public_key, message)
        .map_err(|e| SchnorrError::Verification(e.to_string()))
}

/// Batch-verify many proofs (cheaper than N individual verifies).
pub fn batch_verify(
    proofs: &[EcSchnorrProof],
    public_keys: &[Vec<u8>],
    messages: &[Vec<u8>],
) -> Result<bool> {
    if proofs.len() != public_keys.len() || proofs.len() != messages.len() {
        return Err(SchnorrError::Validation(format!(
            "length mismatch: {} proofs, {} keys, {} messages",
            proofs.len(),
            public_keys.len(),
            messages.len()
        )));
    }
    if proofs.is_empty() {
        return Err(SchnorrError::Validation("proof list is empty".into()));
    }
    ec_schnorr::batch_verify(proofs, public_keys, messages)
        .map_err(|e| SchnorrError::Verification(e.to_string()))
}

/// Parse a proof from the JSON shape the CLI writes:
/// `{ "commitment": "<hex>", "response": "<hex>" }`.
pub fn proof_from_json(content: &str) -> Result<EcSchnorrProof> {
    let value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| SchnorrError::Validation(format!("cannot parse proof JSON: {e}")))?;
    let commitment = hex::decode(
        value["commitment"]
            .as_str()
            .ok_or_else(|| SchnorrError::Validation("missing proof.commitment".into()))?,
    )
    .map_err(|e| SchnorrError::Validation(format!("invalid commitment hex: {e}")))?;
    let response = hex::decode(
        value["response"]
            .as_str()
            .ok_or_else(|| SchnorrError::Validation("missing proof.response".into()))?,
    )
    .map_err(|e| SchnorrError::Validation(format!("invalid response hex: {e}")))?;
    Ok(EcSchnorrProof {
        commitment,
        response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed_byte: u8) -> ([u8; 32], Vec<u8>) {
        super::keypair(&[seed_byte; 32])
    }

    #[test]
    fn prove_verify_roundtrip() {
        let (sk, pk) = keypair(42);
        let proof = prove(&sk, b"hello").unwrap();
        assert!(verify(&proof, &pk, b"hello").unwrap());
    }

    #[test]
    fn tampered_message_fails() {
        let (sk, pk) = keypair(42);
        let proof = prove(&sk, b"original").unwrap();
        assert!(!verify(&proof, &pk, b"tampered").unwrap());
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _) = keypair(1);
        let (_, pk2) = keypair(2);
        let proof = prove(&sk, b"msg").unwrap();
        assert!(!verify(&proof, &pk2, b"msg").unwrap());
    }

    #[test]
    fn batch_length_mismatch_rejected() {
        let (sk, _pk) = keypair(42);
        let proof = prove(&sk, b"msg").unwrap();
        let err = batch_verify(&[proof], &[], &[]).unwrap_err();
        assert!(err.to_string().contains("length mismatch"));
    }

    #[test]
    fn batch_roundtrip() {
        let (sk, pk) = keypair(42);
        let proofs = vec![prove(&sk, b"a").unwrap(), prove(&sk, b"b").unwrap()];
        let keys = vec![pk.clone(), pk.clone()];
        let msgs = vec![b"a".to_vec(), b"b".to_vec()];
        assert!(batch_verify(&proofs, &keys, &msgs).unwrap());
    }

    #[test]
    fn json_roundtrip() {
        let (sk, _pk) = keypair(42);
        let proof = prove(&sk, b"json").unwrap();
        let json = serde_json::json!({
            "commitment": hex::encode(&proof.commitment),
            "response": hex::encode(&proof.response),
        })
        .to_string();
        let parsed = proof_from_json(&json).unwrap();
        assert_eq!(parsed.commitment, proof.commitment);
        assert_eq!(parsed.response, proof.response);
    }

    #[test]
    fn json_missing_field_rejected() {
        let err = proof_from_json("{\"commitment\":\"00\"}").unwrap_err();
        assert!(err.to_string().contains("proof.response"));
    }
}
