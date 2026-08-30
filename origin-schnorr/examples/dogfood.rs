// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-schnorr` as a foundational dependency.
//!
//! EC-Schnorr zero-knowledge proofs through the public `cli` +
//! `commands` dispatch: keygen → prove (knowledge of a secret over a
//! message) → verify, plus a batch-verify path. Negative verification
//! is checked through the SDK (`ec_schnorr::verify`) because the CLI
//! exits on invalid proofs by design.
//!
//! Run with: `cargo run -p origin-schnorr --example dogfood`

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::Parser;
use origin_crypto_sdk::ec_schnorr;
use origin_schnorr::cli::Cli;
use origin_schnorr::commands;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join("origin-dogfood-schnorr");
    let dir = base.join(format!(
        "{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn dispatch(args: &[&str]) -> Result<(), String> {
    let cli = Cli::parse_from(args);
    commands::dispatch(cli)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = scratch("run");

    // Deterministic keypair from a seed.
    let (secret, public) = ec_schnorr::generate_keypair(&[0x42u8; 32]);
    let secret_hex = hex::encode(secret);
    let public_hex = hex::encode(&public);

    // ── keygen: same seed → same keypair ─────────────────────────────
    dispatch(&[
        "origin-schnorr",
        "keygen",
        "--seed=4242424242424242424242424242424242424242424242424242424242424242",
    ])?;
    println!("✓ keygen (deterministic from seed)");

    // ── prove → verify round-trip ────────────────────────────────────
    let msg_path = dir.join("msg.bin");
    std::fs::write(&msg_path, b"knowledge-of-secret message")?;
    dispatch(&[
        "origin-schnorr",
        "prove",
        &format!("--secret={secret_hex}"),
        &format!("--public={public_hex}"),
        &format!("--input={}", msg_path.display()),
    ])?;
    println!("✓ prove (ZK proof printed above)");

    // Rebuild the proof via the SDK (what cmd_prove calls internally)
    // so we can hand cmd_verify a real proof file.
    let proof = ec_schnorr::prove(&secret, &public, b"knowledge-of-secret message")
        .map_err(|e| e.to_string())?;
    let proof_json = serde_json::json!({
        "commitment": hex::encode(&proof.commitment),
        "response": hex::encode(&proof.response),
        "public_key": public_hex,
    });
    let proof_file = dir.join("proof.json");
    std::fs::write(&proof_file, serde_json::to_string_pretty(&proof_json)?)?;

    // cmd_verify takes the message as HEX.
    dispatch(&[
        "origin-schnorr",
        "verify",
        &format!("--proof={}", proof_file.display()),
        &format!("--public={public_hex}"),
        &format!("--message={}", hex::encode(b"knowledge-of-secret message")),
    ])?;
    println!("✓ prove → verify round-trip");

    // ── negative path (SDK-level, since the CLI exits on invalid) ────
    let tampered = ec_schnorr::EcSchnorrProof {
        commitment: proof.commitment.clone(),
        response: {
            let mut r = proof.response.clone();
            r[0] ^= 0xff;
            r
        },
    };
    assert!(
        !ec_schnorr::verify(&tampered, &public, b"knowledge-of-secret message").unwrap(),
        "tampered proof must not verify"
    );
    assert!(
        !ec_schnorr::verify(&proof, &public, b"a different message").unwrap(),
        "wrong message must not verify"
    );
    println!("✓ tampered proof / wrong message rejected (SDK verify)");

    // ── batch verify (3 proofs, all valid) ───────────────────────────
    let mut items = Vec::new();
    for i in 0..3u8 {
        let (sk, pk) = ec_schnorr::generate_keypair(&[i; 32]);
        let msg = format!("batch message {i}").into_bytes();
        let p = ec_schnorr::prove(&sk, &pk, &msg).map_err(|e| e.to_string())?;
        items.push(serde_json::json!({
            "proof": { "commitment": hex::encode(&p.commitment), "response": hex::encode(&p.response) },
            "public_key": hex::encode(&pk),
            "message": hex::encode(&msg),
        }));
    }
    let batch_file = dir.join("batch.json");
    std::fs::write(&batch_file, serde_json::to_string(&items)?)?;
    dispatch(&[
        "origin-schnorr",
        "batch-verify",
        &format!("--input={}", batch_file.display()),
    ])?;
    println!("✓ batch-verify (3 proofs)");

    println!("\norigin-schnorr dogfood OK — usable as a foundational dependency");
    Ok(())
}
