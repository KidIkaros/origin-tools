// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-stealth` as a foundational dependency.
//!
//! Stealth addresses + identity-bound proof-of-work through the public
//! `cli` + `commands` dispatch: master key derivation, per-index stealth
//! addresses, and a solve → verify PoW round-trip (difficulty 14 keeps
//! the example fast while proving the full pipeline).
//!
//! Run with: `cargo run -p origin-stealth --example dogfood`

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::Parser;
use origin_crypto_sdk::seed::SeedHandle;
use origin_crypto_sdk::stealth::{kdf, pow};
use origin_stealth::cli::Cli;
use origin_stealth::commands;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join("origin-dogfood-stealth");
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
    // Re-invoked by the bad-proof probe: verify only that proof and let
    // the CLI's exit code speak for itself.
    if let Ok(bad) = std::env::var("ORIGIN_STEALTH_DOGFOOD_BAD") {
        return dispatch(&[
            "origin-stealth",
            "verify",
            &format!("--proof={bad}"),
            "--index=3",
        ])
        .map_err(|e| e.into());
    }

    let dir = scratch("run");
    let seed_hex = hex::encode([0x42u8; 32]);

    // ── master: derive stealth master keys from a seed ───────────────
    dispatch(&["origin-stealth", "master", &format!("--seed={seed_hex}")])?;
    println!("✓ master (viewing / spending / ephemeral keys)");

    // ── address: per-index one-time addresses ────────────────────────
    dispatch(&[
        "origin-stealth",
        "address",
        &format!("--seed={seed_hex}"),
        "--index=0",
    ])?;
    dispatch(&[
        "origin-stealth",
        "address",
        &format!("--seed={seed_hex}"),
        "--index=7",
    ])?;
    println!("✓ address at indices 0 and 7");

    // ── solve → verify: identity-bound PoW round-trip ────────────────
    // cmd_solve prints the proof JSON to stdout; we rebuild the same
    // proof from the same seed via the SDK (stealth::pow::solve is what
    // cmd_solve calls) and hand the file to cmd_verify.
    let handle = SeedHandle::new(&[0x42u8; 32], None);
    let seed_bytes = handle.as_bytes().unwrap();
    let pk = origin_crypto_sdk::sha3_256(seed_bytes);
    let dest_hint = 3u64.to_le_bytes();
    let (proof, iterations) = pow::solve(&pk, &dest_hint, 14).map_err(|e| e.to_string())?;

    let proof_json = serde_json::json!({
        "index": 3,
        "difficulty": 14,
        "iterations": iterations,
        "nonce": hex::encode(proof.nonce),
        "extra": hex::encode(proof.extra),
        "counter": proof.counter,
        "identity_pk": hex::encode(pk),
    });
    let proof_file = dir.join("proof.json");
    std::fs::write(&proof_file, serde_json::to_string_pretty(&proof_json)?)?;

    dispatch(&[
        "origin-stealth",
        "verify",
        &format!("--proof={}", proof_file.display()),
        "--index=3",
    ])?;
    println!("✓ solve → verify (identity-bound PoW, {iterations} iterations)");

    // A proof bound to a different identity_pk must fail. `cmd_verify` is
    // not embeddable — it prints INVALID and calls process::exit(1) rather
    // than returning an error — so probe it in a subprocess.
    let other_pk = origin_crypto_sdk::sha3_256(&[0x99u8; 32]);
    let (bad_proof, bad_iters) =
        pow::solve(&other_pk, &dest_hint, 14).map_err(|e| e.to_string())?;
    let bad_json = serde_json::json!({
        "index": 3,
        "difficulty": 14,
        "iterations": bad_iters,
        "nonce": hex::encode(bad_proof.nonce),
        "extra": hex::encode(bad_proof.extra),
        "counter": bad_proof.counter,
        "identity_pk": hex::encode(pk),
    });
    let bad_file = dir.join("bad-proof.json");
    std::fs::write(&bad_file, serde_json::to_string_pretty(&bad_json)?)?;
    let exe = std::env::current_exe()?;
    let status = std::process::Command::new(exe)
        .env("ORIGIN_STEALTH_DOGFOOD_BAD", bad_file.to_str().unwrap())
        .status()?;
    assert_eq!(
        status.code(),
        Some(1),
        "wrong-identity proof must be rejected (CLI exits 1)"
    );
    println!("✓ mismatched identity_pk proof rejected");

    // Sanity: the typed derivation API is usable directly too.
    let _master = kdf::derive_stealth_master(&handle).map_err(|e| e.to_string())?;
    let _addr = kdf::derive_stealth_from_seed(&handle, 42).map_err(|e| e.to_string())?;
    println!("✓ typed kdf API (derive_stealth_master / derive_stealth_from_seed)");

    println!("\norigin-stealth dogfood OK — usable as a foundational dependency");
    Ok(())
}
