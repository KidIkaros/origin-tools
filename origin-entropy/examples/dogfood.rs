// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-entropy` as a foundational dependency.
//!
//! Entropy auditing through the public `cli` + `commands` dispatch:
//! analyze a genuinely random sample (Shannon / chi-squared / min-entropy)
//! and check it against the quality gate for a 256-bit seed; then confirm
//! a biased sample fails the same gate.
//!
//! Run with: `cargo run -p origin-entropy --example dogfood`

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::Parser;
use origin_entropy::cli::Cli;
use origin_entropy::commands;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join("origin-dogfood-entropy");
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
    // Re-invoked by the biased-check probe below: run only that path and
    // surface whether the gate correctly rejects it.
    if std::env::var_os("ORIGIN_ENTROPY_DOGFOOD_BIASED").is_some() {
        let dir = scratch("biased-probe");
        let biased_path = dir.join("biased.bin");
        std::fs::write(&biased_path, vec![0x00u8; 4096])?;
        dispatch(&[
            "origin-entropy",
            "check",
            &format!("--input={}", biased_path.display()),
            "--bits=256",
            "--format=json",
        ])?;
        return Err("biased sample unexpectedly passed the quality gate".into());
    }

    let dir = scratch("run");

    // A genuinely random sample from the SDK CSPRNG. 4096 bytes keeps the
    // statistical gates meaningful: at 256 bytes the Shannon estimate is
    // biased low and `check` flakes against its own 7.5 bits/byte gate.
    let mut random = vec![0u8; 4096];
    origin_crypto_sdk::fill_random(&mut random).map_err(|e| e.to_string())?;
    let random_path = dir.join("random.bin");
    std::fs::write(&random_path, &random)?;

    // ── analyze: full metric set (Shannon / chi-squared / min-entropy) ─
    dispatch(&[
        "origin-entropy",
        "analyze",
        &format!("--input={}", random_path.display()),
        "--format=json",
    ])?;
    println!("✓ analyze (random sample)");

    // ── check: quality gate for a 256-bit seed ───────────────────────
    // cmd_check exits(1) on failure rather than returning an error, so a
    // failing gate terminates this process loudly — exactly what we want
    // for the honest path (the random sample must pass).
    dispatch(&[
        "origin-entropy",
        "check",
        &format!("--input={}", random_path.display()),
        "--bits=256",
        "--format=json",
    ])?;
    println!("✓ check passes for a random 4096-byte seed");

    // ── biased sample must fail the same gate ────────────────────────
    // cmd_check is not embeddable (process::exit on failure), so probe it
    // in a subprocess and assert the exit code.
    let exe = std::env::current_exe()?;
    let status = std::process::Command::new(exe)
        .env("ORIGIN_ENTROPY_DOGFOOD_BIASED", "1")
        .status()?;
    assert_eq!(
        status.code(),
        Some(1),
        "biased sample must fail the quality gate with exit code 1"
    );
    println!("✓ biased sample correctly rejected (CLI exits 1)");

    println!("\norigin-entropy dogfood OK — usable as a foundational dependency");
    Ok(())
}
