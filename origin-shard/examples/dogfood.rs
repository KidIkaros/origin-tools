// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-shard` as a foundational dependency.
//!
//! Reed-Solomon K-of-N secret sharing through the public `cli` +
//! `commands` dispatch: split a secret into 5 shards, recover with only
//! 3 of them, and confirm the degraded path (2 shards) fails.
//!
//! Run with: `cargo run -p origin-shard --example dogfood`

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::Parser;
use origin_shard::cli::Cli;
use origin_shard::commands;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join("origin-dogfood-shard");
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
    let secret = "master-secret-material-0123456789abcdef";
    let secret_path = dir.join("secret.bin");
    std::fs::write(&secret_path, secret)?;

    let shards_dir = dir.join("shards");
    std::fs::create_dir_all(&shards_dir)?;
    let shards_s = shards_dir.to_str().unwrap().to_string();

    // ── split: 3 data shards + 2 parity shards (5 total) ─────────────
    dispatch(&[
        "origin-shard",
        "split",
        &format!("--input={}", secret_path.display()),
        &format!("--output={shards_s}"),
        "--data-shards=3",
        "--parity-shards=2",
    ])?;
    // 5 shard files + metadata.json (the split manifest) land in the dir.
    let shard_count = std::fs::read_dir(&shards_dir)?
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("shard_")
        })
        .count();
    assert_eq!(shard_count, 5, "split must produce 5 shard files");
    println!("✓ split → {shard_count} shards + metadata.json on disk");

    // Recover with any 3 of 5: keep shards 2,3,4 (drop 0 and 1). The
    // metadata.json manifest travels with the subset.
    let subset = dir.join("subset");
    std::fs::create_dir_all(&subset)?;
    let mut names: Vec<_> = std::fs::read_dir(&shards_dir)?
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    for name in names.iter().skip(2) {
        std::fs::copy(shards_dir.join(name), subset.join(name))?;
    }
    std::fs::copy(
        shards_dir.join("metadata.json"),
        subset.join("metadata.json"),
    )?;
    let recovered_path = dir.join("recovered.bin");
    dispatch(&[
        "origin-shard",
        "recover",
        &format!("--input={}", subset.to_str().unwrap()),
        &format!("--output={}", recovered_path.display()),
        "--data-shards=3",
        "--parity-shards=2",
    ])?;
    let recovered = std::fs::read_to_string(&recovered_path)?;
    assert_eq!(recovered, secret, "3-of-5 shards must recover the secret");
    println!("✓ recover from a 3-of-5 subset (byte-exact)");

    // Too few shards must fail.
    let too_few = dir.join("too-few");
    std::fs::create_dir_all(&too_few)?;
    let mut names: Vec<_> = std::fs::read_dir(&shards_dir)?
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    for name in names.iter().take(2) {
        std::fs::copy(shards_dir.join(name), too_few.join(name))?;
    }
    std::fs::copy(
        shards_dir.join("metadata.json"),
        too_few.join("metadata.json"),
    )?;
    let bad = dispatch(&[
        "origin-shard",
        "recover",
        &format!("--input={}", too_few.to_str().unwrap()),
        "--data-shards=3",
        "--parity-shards=2",
    ]);
    assert!(bad.is_err(), "2 of 5 shards must not recover the secret");
    println!("✓ 2-of-5 subset correctly rejected");

    println!("\norigin-shard dogfood OK — usable as a foundational dependency");
    Ok(())
}
