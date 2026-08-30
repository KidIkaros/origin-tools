// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-vcs` as a foundational dependency.
//!
//! The git-like DVCS through its public `cli` + `commands` dispatch —
//! the exact surface the `origin-vcs` binary (and a downstream tool
//! embedding file versioning) uses. Walks the daily workflow:
//! init → add → status → commit → log → tag → branch → verify → mmr,
//! with signed, encrypted-at-rest objects.
//!
//! Run with: `cargo run -p origin-vcs --example dogfood`

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::Parser;
use origin_vcs::cli::Cli;
use origin_vcs::commands;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join("origin-dogfood-vcs");
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
    let work = scratch("repo");
    let seed_hex = hex::encode([0x77u8; 32]);
    let seed = format!("--seed={seed_hex}");
    let seed_ref = seed.as_str();
    std::env::set_current_dir(&work)?;

    // ── init: encrypted-at-rest store + signed refs ──────────────────
    // `--seed` supplies the signing key; the at-rest storage key is
    // derived from the same seed (no passphrase prompt needed).
    dispatch(&["origin-vcs", "init", "--branch=main", seed_ref])?;
    assert!(work.join(".origin-vcs").exists(), "store directory created");
    println!(
        "✓ init → encrypted store at {}",
        work.join(".origin-vcs").display()
    );

    // ── add → status → commit (signed) ───────────────────────────────
    std::fs::write(work.join("README.md"), "# dogfood repo\n")?;
    std::fs::create_dir_all(work.join("src"))?;
    std::fs::write(work.join("src/main.rs"), "fn main() {}\n")?;
    dispatch(&["origin-vcs", "add", ".", seed_ref])?;
    dispatch(&["origin-vcs", "status", seed_ref])?;
    dispatch(&[
        "origin-vcs",
        "commit",
        "-m",
        "initial commit",
        seed_ref,
        "--author=Dogfood <dogfood@example.com>",
    ])?;
    println!("✓ add → status → signed commit");

    // Second commit on a second file.
    std::fs::write(work.join("src/lib.rs"), "pub fn lib() {}\n")?;
    dispatch(&["origin-vcs", "add", "src/lib.rs", seed_ref])?;
    dispatch(&[
        "origin-vcs",
        "commit",
        "-m",
        "add lib module",
        seed_ref,
        "--author=Dogfood <dogfood@example.com>",
    ])?;

    // ── log / show / tag / branch ────────────────────────────────────
    dispatch(&["origin-vcs", "log", "--oneline", seed_ref])?;
    dispatch(&["origin-vcs", "tag", "v0.1.0", seed_ref])?;
    dispatch(&["origin-vcs", "branch", "feature", seed_ref])?;
    dispatch(&["origin-vcs", "log", "--oneline", "--from=feature", seed_ref])?;
    println!("✓ log / tag / branch");

    // ── verify: signature + object hashes + refs + MMR ───────────────
    dispatch(&["origin-vcs", "verify", seed_ref])?;
    dispatch(&["origin-vcs", "mmr", seed_ref])?;
    println!("✓ verify (signatures, hashes, refs, MMR) + mmr root");

    // ── checkout the branch, make a commit, merge back ───────────────
    dispatch(&["origin-vcs", "checkout", "feature", seed_ref])?;
    std::fs::write(work.join("feature.txt"), "feature work\n")?;
    dispatch(&["origin-vcs", "add", "feature.txt", seed_ref])?;
    dispatch(&[
        "origin-vcs",
        "commit",
        "-m",
        "feature work",
        seed_ref,
        "--author=Dogfood <dogfood@example.com>",
    ])?;
    dispatch(&["origin-vcs", "checkout", "main", seed_ref])?;
    dispatch(&["origin-vcs", "merge", "feature", seed_ref])?;
    dispatch(&["origin-vcs", "log", "--oneline", seed_ref])?;
    assert!(
        work.join("feature.txt").exists(),
        "merged file in working tree"
    );
    println!("✓ branch → commit → merge (feature into main)");

    // ── gc leaves history intact ─────────────────────────────────────
    dispatch(&["origin-vcs", "gc", seed_ref])?;
    dispatch(&["origin-vcs", "verify", seed_ref])?;
    println!("✓ gc + verify after prune");

    // ── typed object layer is usable directly ────────────────────────
    let tree = origin_vcs::object::Tree::new();
    let blob = origin_vcs::object::Blob {
        data: b"hello".to_vec(),
    };
    let blob_id = origin_vcs::object::blob_address(&blob);
    let tree_id = origin_vcs::object::tree_address(&tree);
    assert_eq!(blob_id.len(), 32);
    assert_eq!(origin_vcs::object::hex(&tree_id).len(), 64);
    println!("✓ typed object layer (Blob/Tree addressing)");

    println!("\norigin-vcs dogfood OK — usable as a foundational dependency");
    Ok(())
}
