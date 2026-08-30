// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-archive` as a foundational dependency.
//!
//! Atomic compress-then-encrypt archives (zstd + ChaCha20-BLAKE3)
//! through the public `cli` + `commands` dispatch: archive → inspect
//! (header only, no decryption) → unarchive, plus the negative path
//! (wrong passphrase).
//!
//! Run with: `cargo run -p origin-archive --example dogfood`

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::Parser;
use origin_archive::cli::Cli;
use origin_archive::commands;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join("origin-dogfood-archive");
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
    let pw = dir.join("pw.txt");
    std::fs::write(&pw, "dogfood-archive-pass\n")?;
    let pw = pw.to_str().unwrap().to_string();

    let plaintext = "payload that compresses well: ".repeat(200);
    let pt_path = dir.join("pt.txt");
    std::fs::write(&pt_path, &plaintext)?;

    // ── archive: compress + encrypt to a container file ──────────────
    dispatch(&[
        "origin-archive",
        "archive",
        &format!("--input={}", pt_path.display()),
        &format!("--output={}", dir.join("archive.bin").display()),
        &format!("--passphrase-file={pw}"),
        "--tier=nano",
        "--compressor=zstd",
    ])?;
    let archive = dir.join("archive.bin");
    assert!(archive.exists(), "archive container written");
    let archived_len = std::fs::metadata(&archive)?.len();
    assert!(
        archived_len < plaintext.len() as u64,
        "repetitive payload must compress ({archived_len} < {})",
        plaintext.len()
    );
    println!("✓ archive → container ({archived_len} bytes, compressed)");

    // ── inspect: read the header without the passphrase ──────────────
    dispatch(&[
        "origin-archive",
        "inspect",
        &format!("--input={}", archive.display()),
    ])?;
    println!("✓ inspect (header metadata, no decryption)");

    // ── unarchive: decrypt + decompress, byte-exact ──────────────────
    let out_path = dir.join("out.txt");
    dispatch(&[
        "origin-archive",
        "unarchive",
        &format!("--input={}", archive.display()),
        &format!("--output={}", out_path.display()),
        &format!("--passphrase-file={pw}"),
        "--tier=nano",
    ])?;
    let recovered = std::fs::read_to_string(&out_path)?;
    assert_eq!(recovered, plaintext, "archive → unarchive round-trip");
    println!("✓ unarchive → byte-exact round-trip");

    // Wrong passphrase must fail.
    let bad_pw = dir.join("bad.txt");
    std::fs::write(&bad_pw, "wrong\n")?;
    let bad = dispatch(&[
        "origin-archive",
        "unarchive",
        &format!("--input={}", archive.display()),
        &format!("--output={}", dir.join("bad.txt").display()),
        &format!("--passphrase-file={}", bad_pw.display()),
        "--tier=nano",
    ]);
    assert!(bad.is_err(), "unarchive with a wrong passphrase must fail");
    println!("✓ wrong passphrase rejected");

    println!("\norigin-archive dogfood OK — usable as a foundational dependency");
    Ok(())
}
