// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-schnorr` as a foundational dependency.
//!
//! EC-Schnorr zero-knowledge proofs through the typed library API
//! (`origin_schnorr::api`): keygen → prove (knowledge of a secret over a
//! message) → verify, plus batch-verify and JSON round-trip. Negative
//! paths return typed results — no process exits, no stdout parsing.
//!
//! Run with: `cargo run -p origin-schnorr --example dogfood`

use origin_schnorr::{batch_verify, keypair, proof_from_json, prove, verify};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = b"knowledge-of-secret message";

    // ── keygen: deterministic from a 32-byte seed ─────────────────────
    let (secret, public) = keypair(&[0x42u8; 32]);
    let (secret2, public2) = keypair(&[0x42u8; 32]);
    assert_eq!(secret, secret2, "keygen must be deterministic");
    assert_eq!(public, public2);
    println!("✓ keypair (deterministic from seed, 33-byte compressed public key)");

    // ── prove → verify round-trip ─────────────────────────────────────
    let proof = prove(&secret, message)?;
    assert!(verify(&proof, &public, message)?, "proof must verify");
    println!("✓ prove → verify round-trip");

    // ── JSON round-trip (the wire shape the CLI writes) ───────────────
    let json = serde_json::json!({
        "commitment": hex::encode(&proof.commitment),
        "response": hex::encode(&proof.response),
        "public_key": hex::encode(&public),
    });
    let parsed = proof_from_json(&json.to_string())?;
    assert_eq!(parsed.commitment, proof.commitment);
    assert_eq!(parsed.response, proof.response);
    assert!(verify(&parsed, &public, message)?);
    println!("✓ proof_from_json round-trip verifies");

    // ── negative paths are typed results, not exits ───────────────────
    let tampered = origin_crypto_sdk::ec_schnorr::EcSchnorrProof {
        commitment: proof.commitment.clone(),
        response: {
            let mut r = proof.response.clone();
            r[0] ^= 0xff;
            r
        },
    };
    assert!(
        !verify(&tampered, &public, message)?,
        "tampered proof must not verify"
    );
    assert!(
        !verify(&proof, &public, b"a different message")?,
        "wrong message must not verify"
    );
    let (_, pk2) = keypair(&[0x07u8; 32]);
    assert!(!verify(&proof, &pk2, message)?, "wrong key must not verify");
    println!("✓ tampered proof / wrong message / wrong key all rejected (Ok(false))");

    // ── batch verify (3 proofs, all valid) ────────────────────────────
    let mut proofs = Vec::new();
    let mut keys = Vec::new();
    let mut msgs = Vec::new();
    for i in 0..3u8 {
        let (sk, pk) = keypair(&[i; 32]);
        let msg = format!("batch message {i}").into_bytes();
        proofs.push(prove(&sk, &msg)?);
        keys.push(pk);
        msgs.push(msg);
    }
    assert!(batch_verify(&proofs, &keys, &msgs)?, "batch must verify");
    println!("✓ batch_verify (3 proofs, single call)");

    // ── typed validation errors ───────────────────────────────────────
    let err = batch_verify(&proofs, &keys, &[]).unwrap_err();
    assert!(err.to_string().contains("length mismatch"));
    println!("✓ length mismatch rejected → SchnorrError::Validation");

    println!("\norigin-schnorr dogfood OK — usable as a foundational dependency");
    Ok(())
}
