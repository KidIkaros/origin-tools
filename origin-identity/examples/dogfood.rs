// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-identity` as a foundational dependency.
//!
//! A downstream project can consume this crate exactly the way the
//! standalone binary does: parse a `Cli` (clap) and hand it to
//! `commands::dispatch`. That public surface is what this example
//! exercises — keygen → export-pubkey → sign → verify → list →
//! rename → rotate-passphrase — plus the negative paths (wrong
//! passphrase, tampered signature).
//!
//! Run with: `cargo run -p origin-identity --example dogfood`

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::Parser;
use origin_crypto_sdk::{
    blob::recover_seed, signing::hybrid::HybridSigningKeyBundle, tier::MemoryTier,
};
use origin_identity::cli::{Cli, Commands, KeygenArgs, SignArgs, VerifyArgs};
use origin_identity::commands;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join("origin-dogfood-identity");
    let dir = base.join(format!(
        "{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Parse argv (as the binary does) and dispatch. Returns the CLI result.
fn dispatch(args: &[&str]) -> Result<(), String> {
    let cli = Cli::parse_from(args);
    commands::dispatch(cli)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = scratch("run");
    let id_dir = dir.join("identities");
    std::fs::create_dir_all(&id_dir)?;
    let id_dir = id_dir.to_str().unwrap().to_string();
    let pw = dir.join("pw.txt");
    std::fs::write(&pw, "dogfood-pw\n")?;
    let pw = pw.to_str().unwrap().to_string();

    // ── keygen: creates an encrypted blob on disk ────────────────────
    dispatch(&[
        "origin-identity",
        "keygen",
        "--name=alice",
        &format!("--dir={id_dir}"),
        "--tier=nano",
        "--no-phrase",
        &format!("--passphrase-file={pw}"),
    ])?;
    let blob_path = PathBuf::from(&id_dir).join("alice.id");
    assert!(blob_path.exists(), "alice.id must exist after keygen");
    let blob = std::fs::read(&blob_path)?;
    assert_eq!(&blob[..4], b"ORGB", "identity blob uses the SDK v2 format");
    println!("✓ keygen → encrypted blob at {}", blob_path.display());

    // Wrong passphrase must be rejected by sign (blob decryption).
    let bad_pw = dir.join("bad-pw.txt");
    std::fs::write(&bad_pw, "wrong\n")?;
    let bad_pw = bad_pw.to_str().unwrap().to_string();
    let bad = dispatch(&[
        "origin-identity",
        "sign",
        "--name=alice",
        &format!("--dir={id_dir}"),
        "--tier=nano",
        "--message=hello",
        &format!("--passphrase-file={bad_pw}"),
    ]);
    assert!(bad.is_err(), "sign with a wrong passphrase must fail");
    println!("✓ wrong passphrase rejected");

    // ── export-pubkey: public material only ──────────────────────────
    dispatch(&[
        "origin-identity",
        "export-pubkey",
        "--name=alice",
        &format!("--dir={id_dir}"),
        "--tier=nano",
        "--domain=origin-identity:v1",
        &format!("--passphrase-file={pw}"),
    ])?;
    println!("✓ export-pubkey → hybrid public keys printed above");

    // ── sign + verify round-trip ─────────────────────────────────────
    // cmd_sign prints its JSON signature to stdout; to drive the real
    // verify path we build the identical signature file from the same
    // seed (HybridSigningKeyBundle::from_seed + sign_hybrid is exactly
    // what cmd_sign does internally), then hand it to cmd_verify.
    dispatch(&[
        "origin-identity",
        "sign",
        "--name=alice",
        &format!("--dir={id_dir}"),
        "--tier=nano",
        "--message=dogfood message",
        &format!("--passphrase-file={pw}"),
    ])?;

    let seed = recover_seed(&blob, b"dogfood-pw", MemoryTier::Nano)
        .map_err(|_| "blob should decrypt with the right passphrase")?;
    let bundle = HybridSigningKeyBundle::from_seed(&seed, "origin-identity:v1")
        .map_err(|e| format!("key bundle failed: {e}"))?;
    let sig = bundle.sign_hybrid(b"dogfood message");
    let sig_json = serde_json::json!({
        "ed25519": hex::encode(sig.ed25519_sig.to_bytes()),
        "falcon1024": hex::encode(sig.falcon_sig.as_bytes()),
        "domain": "origin-identity:v1",
    });
    let sig_file = dir.join("sig.json");
    std::fs::write(&sig_file, serde_json::to_string_pretty(&sig_json)?)?;

    // verify via the library dispatch → prints "valid".
    dispatch(&[
        "origin-identity",
        "verify",
        "--name=alice",
        &format!("--dir={id_dir}"),
        "--tier=nano",
        "--message=dogfood message",
        &format!("--signature={}", sig_file.display()),
        &format!("--passphrase-file={pw}"),
    ])?;
    println!("✓ sign → verify round-trip (hybrid Ed25519 + Falcon-1024)");

    // Tampered message must fail verification.
    let bad_verify = dispatch(&[
        "origin-identity",
        "verify",
        "--name=alice",
        &format!("--dir={id_dir}"),
        "--tier=nano",
        "--message=tampered message",
        &format!("--signature={}", sig_file.display()),
        &format!("--passphrase-file={pw}"),
    ]);
    assert!(
        bad_verify.is_err(),
        "verify of a tampered message must fail"
    );
    println!("✓ tampered message rejected");

    // ── lifecycle: list / show / rename / rotate-passphrase ──────────
    dispatch(&[
        "origin-identity",
        "list",
        &format!("--dir={id_dir}"),
        "--names-only",
    ])?;
    dispatch(&[
        "origin-identity",
        "show",
        "--name=alice",
        &format!("--dir={id_dir}"),
    ])?;

    dispatch(&[
        "origin-identity",
        "rename",
        "alice",
        "alice-renamed",
        &format!("--dir={id_dir}"),
    ])?;
    assert!(!blob_path.exists(), "old blob gone after rename");
    assert!(
        PathBuf::from(&id_dir).join("alice-renamed.id").exists(),
        "renamed blob exists"
    );

    let pw2 = dir.join("pw2.txt");
    std::fs::write(&pw2, "new-passphrase\n")?;
    dispatch(&[
        "origin-identity",
        "rotate-passphrase",
        "--name=alice-renamed",
        &format!("--dir={id_dir}"),
        "--tier=nano",
        &format!("--passphrase-file={pw}"),
        &format!("--new-passphrase-file={}", pw2.display()),
    ])?;
    // Old passphrase must now fail; new one must work.
    let old_fails = dispatch(&[
        "origin-identity",
        "export-pubkey",
        "--name=alice-renamed",
        &format!("--dir={id_dir}"),
        "--tier=nano",
        &format!("--passphrase-file={pw}"),
    ]);
    assert!(
        old_fails.is_err(),
        "old passphrase must fail after rotation"
    );
    dispatch(&[
        "origin-identity",
        "export-pubkey",
        "--name=alice-renamed",
        &format!("--dir={id_dir}"),
        "--tier=nano",
        &format!("--passphrase-file={}", pw2.display()),
    ])?;
    println!("✓ list / show / rename / rotate-passphrase");

    // Prove the CLI arg structs are usable directly (typed dependency).
    let _keygen_args = KeygenArgs {
        name: "typed".into(),
        tier: "nano".into(),
        dir: id_dir.clone(),
        passphrase_file: Some(pw.clone()),
        no_phrase: true,
        phrase_output: None,
    };
    let _sign_args = SignArgs {
        name: "typed".into(),
        message: "m".into(),
        domain: "origin-identity:v1".into(),
        output: origin_identity::cli::OutputFormat::Json,
        tier: "nano".into(),
        passphrase_file: Some(pw),
        dir: id_dir.clone(),
        hex: false,
    };
    let _verify_args = VerifyArgs {
        name: "typed".into(),
        message: "m".into(),
        signature: "sig.json".into(),
        domain: "origin-identity:v1".into(),
        tier: "nano".into(),
        passphrase_file: Some(pw2.to_str().unwrap().to_string()),
        dir: id_dir.clone(),
        hex: false,
    };
    let _cmd: Commands = Commands::Show(origin_identity::cli::ShowArgs {
        name: "alice-renamed".into(),
        dir: id_dir,
        format: origin_identity::cli::ShowFormat::Json,
    });
    println!("✓ CLI arg structs are constructible by downstream code");

    println!("\norigin-identity dogfood OK — usable as a foundational dependency");
    Ok(())
}
