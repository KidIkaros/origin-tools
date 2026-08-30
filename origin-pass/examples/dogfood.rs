// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-pass` as a foundational dependency.
//!
//! The encrypted password vault + 2FA authenticator, consumed through
//! its public `cli` + `commands` surface (the same dispatch the binary
//! and the unified `origin` binary use): init → add (password + TOTP)
//! → get → list → code → change-passphrase, plus the negative path
//! (wrong passphrase).
//!
//! Run with: `cargo run -p origin-pass --example dogfood`

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::Parser;
use origin_pass::cli::Cli;
use origin_pass::commands;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join("origin-dogfood-pass");
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
    let vault = dir.join("vault.opass");
    let vault_s = vault.to_str().unwrap().to_string();

    let pw = dir.join("pw.txt");
    std::fs::write(&pw, "dogfood-vault-pass\n")?;
    let pw = pw.to_str().unwrap().to_string();

    // ── init: create the encrypted vault ─────────────────────────────
    dispatch(&[
        "origin-pass",
        "init",
        &format!("--vault={vault_s}"),
        "--tier=nano",
        &format!("--passphrase-file={pw}"),
    ])?;
    assert!(vault.exists(), "vault file must exist after init");
    println!("✓ init → encrypted vault at {}", vault.display());

    // Wrong passphrase must fail on read.
    let bad_pw = dir.join("bad.txt");
    std::fs::write(&bad_pw, "wrong\n")?;
    let bad = dispatch(&[
        "origin-pass",
        "get",
        &format!("--vault={vault_s}"),
        "any",
        &format!("--passphrase-file={}", bad_pw.display()),
    ]);
    assert!(bad.is_err(), "get with a wrong passphrase must fail");
    println!("✓ wrong passphrase rejected");

    // ── add: password entry (secret via file, never argv) ────────────
    let secret = dir.join("secret.txt");
    std::fs::write(&secret, "correct-horse-battery-staple\n")?;
    dispatch(&[
        "origin-pass",
        "add",
        &format!("--vault={vault_s}"),
        "github.com",
        "--type=password",
        &format!("--secret-file={}", secret.display()),
        &format!("--passphrase-file={pw}"),
        "--url=https://github.com",
    ])?;
    println!("✓ add (password entry)");

    // ── add: TOTP 2FA entry ──────────────────────────────────────────
    // RFC 4226/6238 test secret: base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    // (the ascii "12345678901234567890" secret).
    let otp_secret = dir.join("otp-secret.txt");
    std::fs::write(&otp_secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n")?;
    dispatch(&[
        "origin-pass",
        "add",
        &format!("--vault={vault_s}"),
        "github-2fa",
        "--type=otp",
        &format!("--secret-file={}", otp_secret.display()),
        &format!("--passphrase-file={pw}"),
    ])?;
    println!("✓ add (TOTP entry)");

    // ── get / list / code ────────────────────────────────────────────
    dispatch(&[
        "origin-pass",
        "get",
        &format!("--vault={vault_s}"),
        "github.com",
        &format!("--passphrase-file={pw}"),
    ])?;
    dispatch(&[
        "origin-pass",
        "list",
        &format!("--vault={vault_s}"),
        &format!("--passphrase-file={pw}"),
    ])?;
    // A 6-digit TOTP code for the current time window.
    dispatch(&[
        "origin-pass",
        "code",
        &format!("--vault={vault_s}"),
        "github-2fa",
        &format!("--passphrase-file={pw}"),
        "--quiet",
    ])?;
    println!("✓ get / list / code (TOTP)");

    // ── change-passphrase: re-encrypt the vault header ───────────────
    let pw2 = dir.join("pw2.txt");
    std::fs::write(&pw2, "new-vault-pass\n")?;
    dispatch(&[
        "origin-pass",
        "change-passphrase",
        &format!("--vault={vault_s}"),
        &format!("--passphrase-file={pw}"),
        &format!("--new-passphrase-file={}", pw2.display()),
    ])?;
    // Old passphrase must now fail; new one must unlock get.
    let old_fails = dispatch(&[
        "origin-pass",
        "get",
        &format!("--vault={vault_s}"),
        "github.com",
        &format!("--passphrase-file={pw}"),
    ]);
    assert!(
        old_fails.is_err(),
        "old passphrase must fail after rotation"
    );
    dispatch(&[
        "origin-pass",
        "get",
        &format!("--vault={vault_s}"),
        "github.com",
        &format!("--passphrase-file={}", pw2.display()),
    ])?;
    println!("✓ change-passphrase (old password rejected, new works)");

    println!("\norigin-pass dogfood OK — usable as a foundational dependency");
    Ok(())
}
