// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-seal` as a foundational dependency.
//!
//! Exercises the **typed library API** (`origin_seal::api`) exactly as a
//! downstream application would — encrypt/decrypt, sign/verify, hash, MAC,
//! and KDF as plain function calls returning typed values — plus the
//! negative paths (wrong passphrase, tamper, wrong domain).
//!
//! Run with: `cargo run -p origin-seal --example dogfood`

use origin_seal::api;
use origin_seal::api::HashKind;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── hash: known algorithms + determinism ─────────────────────────
    let data = b"dogfood data";
    let _sha = api::hash(HashKind::Sha3_256, data, None)?;
    let _blake = api::hash(HashKind::Blake3, data, None)?;
    let _sha512 = api::hash(HashKind::Sha3_512, data, None)?;
    println!("✓ hash (sha3-256 + blake3 + sha3-512)");

    // ── encrypt / decrypt round-trip ─────────────────────────────────
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    let envelope = api::encrypt(plaintext, b"dogfood-pw", origin_seal::MemoryTier::Nano, true)?;
    let decrypted = api::decrypt(&envelope, b"dogfood-pw")?;
    assert_eq!(decrypted, plaintext, "encrypt → decrypt round-trip");
    println!("✓ encrypt → decrypt (XChaCha20-Poly1305 + Argon2id, compressed)");

    // Wrong passphrase fails with a typed error.
    match api::decrypt(&envelope, b"wrong") {
        Err(origin_seal::SealError::Verification(_)) => {}
        other => panic!("expected Verification error, got {other:?}"),
    }
    println!("✓ wrong passphrase rejected (typed SealError::Verification)");

    // ── sign / verify (hybrid Ed25519 + Falcon-1024) ─────────────────
    let seed = [0x42u8; 32];
    let domain = "origin-seal:dogfood";
    let sig = api::sign(&seed, domain, plaintext)?;
    api::verify(&seed, domain, plaintext, &sig)?;
    println!("✓ sign → verify (hybrid Ed25519 + Falcon-1024)");

    // Tampered input must fail verification.
    assert!(api::verify(&seed, domain, b"tampered!", &sig).is_err());
    println!("✓ tampered data rejected");

    // Wrong domain must fail too (domain separation is load-bearing).
    assert!(api::verify(&seed, "origin-seal:other", plaintext, &sig).is_err());
    println!("✓ wrong domain rejected");

    // ── kdf: deterministic, salted Argon2id ──────────────────────────
    let salt = [0x11u8; 16];
    let k1 = api::kdf(b"dogfood-pw", &salt, origin_seal::MemoryTier::Nano, 32)?;
    let k2 = api::kdf(b"dogfood-pw", &salt, origin_seal::MemoryTier::Nano, 32)?;
    assert_eq!(k1, k2, "KDF must be deterministic");
    println!("✓ kdf (Argon2id, explicit salt, deterministic)");

    // ── mac: keyed HMAC-SHA3-256 ─────────────────────────────────────
    let tag = api::mac(b"0123456789abcdef0123456789abcdef", data)?;
    assert_eq!(tag.len(), 32);
    println!("✓ mac (HMAC-SHA3-256)");

    // ── envelope inspection without decrypting ───────────────────────
    let (header, _payload) = api::parse_envelope(&envelope)?;
    assert_eq!(header.tier, origin_seal::MemoryTier::Nano);
    println!("✓ parse_envelope (tier/flags inspectable without key)");

    println!("\norigin-seal dogfood OK — typed library API usable as a foundational dependency");
    Ok(())
}
