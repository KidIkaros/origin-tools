// SPDX-License-Identifier: Apache-2.0

//! P2: hybrid signing (Ed25519 + Falcon-1024) of orders and events, and
//! origin-common Envelope encryption of event bodies — via the operator
//! identity (`~/.origin/identity.seed`).

use origin_common::{IdentityStore, MemoryTier, OriginHome};
use origin_payments::event::{PaymentEvent, PaymentOrder};
use origin_payments::identity::{
    decrypt_event, encrypt_event, load_operator_keys_from, sign_event, sign_order, verify_order,
};

fn test_home() -> (tempfile::TempDir, OriginHome) {
    let dir = tempfile::tempdir().unwrap();
    let home = OriginHome::with_root(dir.path().join("home")).unwrap();
    let _store = IdentityStore::create(&home, "test-pass", MemoryTier::Nano).unwrap();
    (dir, home)
}

#[test]
fn order_sign_verify_roundtrip() {
    let (_dir, home) = test_home();
    let keys = load_operator_keys_from(&home, "test-pass").unwrap();

    let mut order = PaymentOrder::new("c1", "mesh-1", "3.15", "USD");
    assert!(order.signature.is_none());
    sign_order(&mut order, &keys).unwrap();
    assert!(order.signature.is_some());
    assert!(order.signer.is_some());
    assert!(verify_order(&order).unwrap());

    // Tampering with a signed field breaks verification (no false pass).
    order.amount = "9.99".to_string();
    assert_eq!(verify_order(&order).unwrap(), false);
}

#[test]
fn wrong_passphrase_fails_to_unlock() {
    let (_dir, home) = test_home();
    let err = load_operator_keys_from(&home, "wrong-pass")
        .err()
        .expect("expected error");
    assert!(err.to_string().contains("unlocking identity"));
}

#[test]
fn event_sign_and_envelope_roundtrip() {
    let (_dir, home) = test_home();
    let keys = load_operator_keys_from(&home, "test-pass").unwrap();

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

    let dec = decrypt_event(&bytes, &keys).unwrap();
    assert_eq!(dec, original, "envelope round-trips the signed event");
}

#[test]
fn tampered_envelope_fails_decrypt() {
    let (_dir, home) = test_home();
    let keys = load_operator_keys_from(&home, "test-pass").unwrap();
    let event = PaymentEvent::new(
        "co-2",
        "buyer",
        "merchant",
        vec![PaymentOrder::new("co-2", "mesh-2", "2.00", "USD")],
    );
    let mut bytes = encrypt_event(&event, &keys).unwrap();
    // Flip a byte in the ciphertext — AEAD must reject it.
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    assert!(
        decrypt_event(&bytes, &keys).is_err(),
        "tampered envelope must fail AEAD"
    );
}
