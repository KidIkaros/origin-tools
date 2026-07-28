// SPDX-License-Identifier: Apache-2.0

//! Suite-level integration tests.
//!
//! These exercise **cross-tool composition** through the real CLI binaries:
//!   - origin-seed     -> derive a child seed from the suite identity
//!   - origin-seal     -> encrypt/decrypt/sign/verify using the suite identity
//!   - origin-schnorr  -> prove/verify from the suite identity
//!   - origin-shard    -> split/recover a sealed payload
//!   - origin-proof    -> append to an MMR and verify a proof
//!
//! Binaries are located relative to the test's own binary
//! (`target/debug/origin-proof`), so this works under `cargo test` without
//! hard-coding absolute paths.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::io::Write;

use tempfile::TempDir;

/// Set up a real suite identity at ~/.origin/identity.seed so the
/// `--identity` cross-tool paths have something to load.
///
/// Uses the public `origin-common` API so we don't re-implement the blob
/// crypto in the test. Safe to call repeatedly (overwrites).
fn ensure_identity(passphrase: &str) {
    use origin_common::{IdentityStore, OriginHome, MemoryTier};
    let home = OriginHome::load().expect("origin home");
    // Remove any stale seed so create() writes fresh.
    let path = home.identity_seed_path();
    let _ = std::fs::remove_file(&path);
    IdentityStore::create(&home, passphrase, MemoryTier::Standard)
        .expect("create identity");
}

/// Locate a sibling `origin-*` binary next to the current test executable.
fn bin(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    let mut dir = exe.parent().expect("exe parent").to_path_buf();
    loop {
        let candidate = dir.join(name);
        if candidate.exists() {
            return candidate;
        }
        let deps_candidate = dir.join("deps").join(name);
        if deps_candidate.exists() {
            return deps_candidate;
        }
        match dir.parent() {
            Some(p) => dir = p.to_path_buf(),
            None => break,
        }
    }
    panic!("could not locate binary {name} near {exe:?}");
}

fn run(bin: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {bin:?} {args:?}: {e}"))
}

fn run_stdin(bin: &Path, args: &[&str], stdin_data: &[u8]) -> std::process::Output {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {bin:?}: {e}"));
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_data)
        .unwrap();
    child.wait_with_output().unwrap()
}

fn write_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, content).expect("write temp file");
    p
}

fn path_str(p: &Path) -> String {
    p.to_str().expect("utf-8 path").to_string()
}

fn stdout_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

// ---------------------------------------------------------------------------
// 1. identity -> seed derive determinism
// ---------------------------------------------------------------------------

#[test]
fn identity_seed_derivation_is_deterministic() {
    let seed = bin("origin-seed");
    let dir = TempDir::new().unwrap();
    let pw = write_file(&dir, "pw.txt", b"test-passphrase");
    ensure_identity("test-passphrase");

    let a = run(
        &seed,
        &[
            "derive",
            "--identity",
            "--domain",
            "suite-test",
            "--passphrase-file",
            &path_str(&pw),
        ],
    );
    assert!(a.status.success(), "derive a: {}", stdout_of(&a));

    let b = run(
        &seed,
        &[
            "derive",
            "--identity",
            "--domain",
            "suite-test",
            "--passphrase-file",
            &path_str(&pw),
        ],
    );
    assert!(b.status.success(), "derive b: {}", stdout_of(&b));
    assert_eq!(
        stdout_of(&a),
        stdout_of(&b),
        "same identity+domain must derive same seed"
    );

    // Different domain -> different child seed.
    let c = run(
        &seed,
        &[
            "derive",
            "--identity",
            "--domain",
            "other-domain",
            "--passphrase-file",
            &path_str(&pw),
        ],
    );
    assert!(c.status.success());
    assert_ne!(
        stdout_of(&a),
        stdout_of(&c),
        "different domains must derive different seeds"
    );
}

// ---------------------------------------------------------------------------
// 2. identity -> seal sign/verify
// ---------------------------------------------------------------------------

#[test]
fn identity_seal_sign_verify_roundtrip() {
    let seal = bin("origin-seal");
    let dir = TempDir::new().unwrap();
    let pw = write_file(&dir, "pw.txt", b"test-passphrase");
    let msg = write_file(&dir, "msg.txt", b"hello from the suite");
    ensure_identity("test-passphrase");

    let sig = run(&seal, &[
        "sign",
        "--identity",
        "--input",
        &path_str(&msg),
        "--passphrase-file",
        &path_str(&pw),
        "--format",
        "hex",
    ]);
    assert!(sig.status.success(), "sign: {}", stdout_of(&sig));
    let sig_path = write_file(&dir, "sig.bin", &sig.stdout);

    let v = run(&seal, &[
        "verify",
        "--identity",
        "--input",
        &path_str(&msg),
        "--signature",
        &path_str(&sig_path),
        "--passphrase-file",
        &path_str(&pw),
    ]);
    assert!(v.status.success(), "verify: {}", stdout_of(&v));
    assert_eq!(stdout_of(&v), "OK");
}

#[test]
fn identity_seal_encrypt_decrypt_roundtrip() {
    let seal = bin("origin-seal");
    let dir = TempDir::new().unwrap();
    let pw = write_file(&dir, "pw.txt", b"test-passphrase");
    let pt = write_file(&dir, "pt.txt", b"top secret payload");
    let ct = dir.path().join("ct.bin");
    let out = dir.path().join("out.txt");
    ensure_identity("test-passphrase");

    let enc = run(&seal, &[
        "encrypt",
        "--identity",
        "--input",
        &path_str(&pt),
        "--output",
        &path_str(&ct),
        "--passphrase-file",
        &path_str(&pw),
        "--tier",
        "nano",
    ]);
    assert!(enc.status.success(), "encrypt: {}", stdout_of(&enc));

    let dec = run(&seal, &[
        "decrypt",
        "--identity",
        "--input",
        &path_str(&ct),
        "--output",
        &path_str(&out),
        "--passphrase-file",
        &path_str(&pw),
        "--tier",
        "nano",
    ]);
    assert!(dec.status.success(), "decrypt: {}", stdout_of(&dec));
    assert_eq!(std::fs::read(&out).unwrap(), b"top secret payload");
}

// ---------------------------------------------------------------------------
// 3. identity -> schnorr prove/verify
// ---------------------------------------------------------------------------

#[test]
fn identity_schnorr_prove_verify() {
    let schnorr = bin("origin-schnorr");
    let dir = TempDir::new().unwrap();
    let pw = write_file(&dir, "pw.txt", b"test-passphrase");
    let challenge = write_file(&dir, "challenge.bin", b"auth-challenge-123");
    ensure_identity("test-passphrase");

    // Prove with the suite identity (keys derived from identity).
    let proof = run(&schnorr, &[
        "prove",
        "--identity",
        "--input",
        &path_str(&challenge),
        "--passphrase-file",
        &path_str(&pw),
    ]);
    assert!(proof.status.success(), "prove: {}", stdout_of(&proof));
    let proof_path = write_file(&dir, "proof.json", &proof.stdout);

    // Verify with the suite identity (pubkey derived from same identity) and the
    // same challenge. The message arg is the hex of the challenge bytes.
    let challenge_hex = hex::encode(b"auth-challenge-123");
    let v = run(&schnorr, &[
        "verify",
        "--identity",
        "--proof",
        &path_str(&proof_path),
        "--message",
        &challenge_hex,
        "--passphrase-file",
        &path_str(&pw),
    ]);
    assert!(v.status.success(), "verify: {}", stdout_of(&v));
    assert_eq!(stdout_of(&v), "OK");
}

// ---------------------------------------------------------------------------
// 4. seed -> seal -> shard roundtrip
// ---------------------------------------------------------------------------

#[test]
fn seal_then_shard_roundtrip() {
    let seal = bin("origin-seal");
    let shard = bin("origin-shard");
    let dir = TempDir::new().unwrap();
    let pw = write_file(&dir, "pw.txt", b"test-passphrase");
    let pt = write_file(&dir, "pt.txt", b"data that must survive lossy transport");
    let ct = dir.path().join("ct.bin");
    let shards = dir.path().join("shards");
    let recovered_ct = dir.path().join("recovered_ct.bin");
    let recovered_pt = dir.path().join("recovered_pt.txt");

    let enc = run(&seal, &[
        "encrypt",
        "--identity",
        "--input",
        &path_str(&pt),
        "--output",
        &path_str(&ct),
        "--passphrase-file",
        &path_str(&pw),
        "--tier",
        "nano",
    ]);
    assert!(enc.status.success());

    let split = run(&shard, &[
        "split",
        "--input",
        &path_str(&ct),
        "--output",
        &path_str(&shards),
        "--data-shards",
        "3",
        "--parity-shards",
        "2",
    ]);
    assert!(split.status.success(), "split: {}", stdout_of(&split));

    // NOTE: the SDK Reed-Solomon `decode` supports a clean round-trip
    // (split -> recover all shards) but its erasure-recovery path for
    // missing shards is untested in the SDK. We exercise the valid
    // composition here; lossy recovery would need a tested RS layer.
    let recover = run(&shard, &[
        "recover",
        "--input",
        &path_str(&shards),
        "--output",
        &path_str(&recovered_ct),
        "--data-shards",
        "3",
        "--parity-shards",
        "2",
    ]);
    assert!(recover.status.success(), "recover: {}", stdout_of(&recover));
    assert_eq!(
        std::fs::read(&ct).unwrap(),
        std::fs::read(&recovered_ct).unwrap(),
        "recovered ciphertext must be byte-identical"
    );

    let dec = run(&seal, &[
        "decrypt",
        "--identity",
        "--input",
        &path_str(&recovered_ct),
        "--output",
        &path_str(&recovered_pt),
        "--passphrase-file",
        &path_str(&pw),
        "--tier",
        "nano",
    ]);
    assert!(dec.status.success());
    assert_eq!(
        std::fs::read(&recovered_pt).unwrap(),
        b"data that must survive lossy transport"
    );
}

// ---------------------------------------------------------------------------
// 5. shard -> proof: append recovered data hash to an MMR
// ---------------------------------------------------------------------------

#[test]
fn shard_then_proof_append_verify() {
    let shard = bin("origin-shard");
    let proof = bin("origin-proof");
    let dir = TempDir::new().unwrap();
    let data = write_file(&dir, "data.bin", b"integrity-sensitive record");
    let shards = dir.path().join("shards");
    let recovered = dir.path().join("recovered.bin");
    let mmr_store = dir.path().join("mmr.json");

    let split = run(&shard, &[
        "split",
        "--input",
        &path_str(&data),
        "--output",
        &path_str(&shards),
        "--data-shards",
        "2",
        "--parity-shards",
        "1",
    ]);
    assert!(split.status.success());
    // NOTE: see `seal_then_shard_roundtrip` — the SDK RS `decode` only
    // supports a clean (no-loss) round-trip in practice; lossy recovery
    // is untested upstream, so we exercise the valid composition.
    let recover = run(&shard, &[
        "recover",
        "--input",
        &path_str(&shards),
        "--output",
        &path_str(&recovered),
        "--data-shards",
        "2",
        "--parity-shards",
        "1",
    ]);
    assert!(recover.status.success());
    assert_eq!(
        std::fs::read(&recovered).unwrap(),
        std::fs::read(&data).unwrap()
    );

    // Append the recovered data's BLAKE3 hash to a fresh MMR.
    let leaf_hex = hex::encode(b"integrity-sensitive record");
    let append = run(&proof, &[
        "append",
        "--state",
        &path_str(&mmr_store),
        "--data",
        &leaf_hex,
        "--output",
        &path_str(&mmr_store),
    ]);
    assert!(append.status.success(), "append: {}", stdout_of(&append));

    // Root must be a well-formed 32-byte (64 hex) BLAKE3 digest.
    let root = run(&proof, &["root", "--state", &path_str(&mmr_store)]);
    assert!(root.status.success(), "root: {}", stdout_of(&root));
    let root_hex = stdout_of(&root);
    assert!(!root_hex.is_empty(), "MMR root must not be empty");
    assert_eq!(root_hex.len(), 64, "BLAKE3 root is 32 bytes / 64 hex chars");

    // Generate a membership proof for leaf 0 and verify it against the root.
    let prove = run(&proof, &[
        "prove",
        "--state",
        &path_str(&mmr_store),
        "--index",
        "0",
    ]);
    assert!(prove.status.success(), "prove: {}", stdout_of(&prove));
    let proof_path = write_file(&dir, "proof.json", &prove.stdout);

    let verify = run(&proof, &[
        "verify",
        "--proof",
        &path_str(&proof_path),
        "--root",
        &root_hex,
    ]);
    assert!(verify.status.success(), "verify: {}", stdout_of(&verify));
    assert_eq!(stdout_of(&verify), "OK");
}
