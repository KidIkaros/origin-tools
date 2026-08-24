// SPDX-License-Identifier: Apache-2.0

//! Operator identity (P2): hybrid-sign orders and events with the suite
//! identity and encrypt event bodies in origin-common envelopes.
//!
//! One identity, one home: the operator's `~/.origin/identity.seed` is
//! loaded via `origin-common::IdentityStore`, and a domain-derived hybrid
//! bundle (`origin-crypto-sdk` Ed25519 + Falcon-1024) signs money
//! movements. The envelope key is a separate domain-derived key, so
//! encrypting a checkout never reuses a signing key.
//!
//! Signatures use the `origin-crypto-sdk` `HybridSig` wire format (the sole
//! crypto provider); the signer's public keys are embedded in the signed
//! object so verification works offline (the origin-secrets pattern).

use origin_common::{Envelope, IdentityStore, MemoryTier, OriginHome, PayloadType};
use origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle;
use origin_crypto_sdk::signing::wire::HybridSig;

use crate::error::{Error, Result};
use crate::event::{PaymentEvent, PaymentOrder};

/// Domain for the payments signing bundle.
pub const PAYMENTS_DOMAIN: &str = "payments";
/// Domain for the payments envelope encryption key.
pub const PAYMENTS_ENVELOPE_DOMAIN: &str = "payments-envelope";

/// The signer's public keys, embedded in signed objects for offline
/// verification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OrderSigner {
    /// Ed25519 verifying key (32 bytes).
    pub ed_pk: [u8; 32],
    /// Falcon-1024 public key (wire bytes).
    pub falcon_pk: Vec<u8>,
    /// Bundle domain ("payments").
    pub domain: String,
}

/// Loaded operator keys: the hybrid signing bundle plus the envelope key.
pub struct OperatorKeys {
    pub bundle: HybridSigningKeyBundle,
    pub envelope_key: [u8; 32],
}

/// Load operator keys from the default home (`~/.origin` or `$ORIGIN_HOME`).
pub fn load_operator_keys(passphrase: &str) -> Result<OperatorKeys> {
    let home = OriginHome::load().map_err(|e| Error::CryptoError {
        details: format!("loading origin home: {e}"),
    })?;
    load_operator_keys_from(&home, passphrase)
}

/// Load operator keys from an explicit home (tests / multi-profile).
pub fn load_operator_keys_from(home: &OriginHome, passphrase: &str) -> Result<OperatorKeys> {
    if !home.identity_seed_path().exists() {
        return Err(Error::IdentityNotFound);
    }
    let store = IdentityStore::load(home, passphrase).map_err(|e| Error::CryptoError {
        details: format!("unlocking identity: {e}"),
    })?;
    let bundle = store
        .hybrid_signing_keys(PAYMENTS_DOMAIN)
        .map_err(|e| Error::CryptoError { details: e })?;
    let key_vec = store
        .derive_key(PAYMENTS_ENVELOPE_DOMAIN, 32)
        .map_err(|e| Error::CryptoError { details: e })?;
    let envelope_key: [u8; 32] = key_vec.try_into().map_err(|_| Error::CryptoError {
        details: "envelope key must be 32 bytes".to_string(),
    })?;
    Ok(OperatorKeys {
        bundle,
        envelope_key,
    })
}

/// Sign an order's `signed_body()` with the hybrid bundle and embed the
/// signer's public keys.
pub fn sign_order(order: &mut PaymentOrder, keys: &OperatorKeys) -> Result<()> {
    let sig = keys
        .bundle
        .try_sign_hybrid(&order.signed_body())
        .map_err(|e| Error::CryptoError {
            details: e.to_string(),
        })?;
    let hybrid = HybridSig::from_sig(&sig);
    let mut encoded = Vec::new();
    hybrid
        .encode(&mut encoded)
        .map_err(|e| Error::CryptoError {
            details: e.to_string(),
        })?;
    order.signature = Some(encoded);
    order.signer = Some(OrderSigner {
        ed_pk: keys.bundle.ed25519_pk().to_bytes(),
        falcon_pk: keys.bundle.falcon1024_pk().as_bytes().to_vec(),
        domain: PAYMENTS_DOMAIN.to_string(),
    });
    Ok(())
}

/// Verify an order's hybrid signature against its embedded signer keys.
///
/// - `Ok(true)` — signature valid;
/// - `Ok(false)` — signature invalid (tampered or wrong keys);
/// - `Err` — unsigned order or a malformed signature blob.
pub fn verify_order(order: &PaymentOrder) -> Result<bool> {
    let signer = order.signer.as_ref().ok_or_else(|| Error::Unsigned {
        payment_order_id: order.payment_order_id.clone(),
    })?;
    let sig_bytes = order.signature.as_ref().ok_or_else(|| Error::Unsigned {
        payment_order_id: order.payment_order_id.clone(),
    })?;
    let sig = HybridSig::decode(sig_bytes, &mut 0).map_err(|e| Error::CryptoError {
        details: format!("decoding signature: {e}"),
    })?;
    Ok(sig
        .verify(&signer.ed_pk, &signer.falcon_pk, &order.signed_body())
        .is_ok())
}

/// Sign an event's canonical JSON body (the envelope covers the signed
/// event, so integrity and authenticity compose).
pub fn sign_event(event: &mut PaymentEvent, keys: &OperatorKeys) -> Result<()> {
    let body = serde_json::to_vec(event).map_err(|e| Error::CryptoError {
        details: format!("serializing event body: {e}"),
    })?;
    let sig = keys
        .bundle
        .try_sign_hybrid(&body)
        .map_err(|e| Error::CryptoError {
            details: e.to_string(),
        })?;
    let hybrid = HybridSig::from_sig(&sig);
    let mut encoded = Vec::new();
    hybrid
        .encode(&mut encoded)
        .map_err(|e| Error::CryptoError {
            details: e.to_string(),
        })?;
    event.signature = Some(encoded);
    event.signer = Some(OrderSigner {
        ed_pk: keys.bundle.ed25519_pk().to_bytes(),
        falcon_pk: keys.bundle.falcon1024_pk().as_bytes().to_vec(),
        domain: PAYMENTS_DOMAIN.to_string(),
    });
    Ok(())
}

/// Encrypt an event body into an origin-common Envelope (XChaCha20-Poly1305,
/// LZ4-compressed), returning the serialized envelope bytes.
pub fn encrypt_event(event: &PaymentEvent, keys: &OperatorKeys) -> Result<Vec<u8>> {
    let plaintext = serde_json::to_vec(event).map_err(|e| Error::CryptoError {
        details: format!("serializing event: {e}"),
    })?;
    let env = Envelope::encrypt(
        &plaintext,
        &keys.envelope_key,
        MemoryTier::Nano,
        PayloadType::Signed,
        true,
    )
    .map_err(|e| Error::CryptoError { details: e })?;
    Ok(env.to_bytes())
}

/// Decrypt a serialized Envelope back into the original event.
pub fn decrypt_event(bytes: &[u8], keys: &OperatorKeys) -> Result<PaymentEvent> {
    let env = Envelope::from_bytes(bytes).map_err(|e| Error::CryptoError { details: e })?;
    let plain = env
        .decrypt(&keys.envelope_key)
        .map_err(|e| Error::CryptoError { details: e })?;
    serde_json::from_slice(&plain).map_err(|e| Error::CryptoError {
        details: format!("decoding event: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::PaymentOrder;

    fn test_keys() -> (tempfile::TempDir, OperatorKeys) {
        let dir = tempfile::tempdir().unwrap();
        let home = OriginHome::with_root(dir.path().join("home")).unwrap();
        let _store = IdentityStore::create(&home, "test-pass", MemoryTier::Nano).unwrap();
        let keys = load_operator_keys_from(&home, "test-pass").unwrap();
        (dir, keys)
    }

    #[test]
    fn no_identity_is_identity_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let home = OriginHome::with_root(dir.path().join("home")).unwrap();
        let err = load_operator_keys_from(&home, "pass")
            .err()
            .expect("expected error");
        assert!(matches!(err, Error::IdentityNotFound));
    }

    #[test]
    fn order_sign_verify_roundtrip() {
        let (_dir, keys) = test_keys();
        let mut order = PaymentOrder::new("c1", "mesh-1", "3.15", "USD");
        assert!(order.signature.is_none());
        sign_order(&mut order, &keys).unwrap();
        assert!(order.signature.is_some());
        assert!(order.signer.is_some());
        assert!(verify_order(&order).unwrap());

        // Tampering with a signed field breaks verification.
        order.amount = "9.99".to_string();
        assert_eq!(verify_order(&order).unwrap(), false);
    }

    #[test]
    fn unsigned_order_is_unsigned_error() {
        let order = PaymentOrder::new("c1", "mesh-1", "1.00", "USD");
        assert!(matches!(
            verify_order(&order).unwrap_err(),
            Error::Unsigned { .. }
        ));
    }

    #[test]
    fn event_sign_and_envelope_roundtrip() {
        let (_dir, keys) = test_keys();
        let mut event = PaymentEvent::new(
            "co-1",
            "buyer",
            "merchant",
            vec![PaymentOrder::new("co-1", "mesh-1", "1.00", "USD")],
        );
        sign_event(&mut event, &keys).unwrap();
        assert!(event.signature.is_some());
        assert!(event.signer.is_some());

        let original = event.clone();
        let bytes = encrypt_event(&event, &keys).unwrap();
        event.envelope = Some(bytes.clone());
        assert!(event.envelope.is_some());

        let dec = decrypt_event(&bytes, &keys).unwrap();
        assert_eq!(dec, original);
    }
}
