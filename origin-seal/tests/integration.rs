// SPDX-License-Identifier: Apache-2.0

//! Shell-out integration tests for the `origin-seal` CLI binary.
//!
//! These exercise the **real clap dispatch + main.rs path**, not the
//! Rust API. They are the regression net for wiring bugs (arg parsing,
//! stdin/stdout plumbing, envelope framing, exit codes) that pure unit
//! tests in `src/commands.rs::tests` cannot catch.
//!
//! Every test writes passphrases/keys to files (never argv) and invokes
//! `env!("CARGO_BIN_EXE_origin-seal")` via `std::process::Command`.

use std::process::{Command, Stdio};

use tempfile::TempDir;

/// Path to the compiled `origin-seal` binary, set by cargo for integration tests.
fn seal_bin() -> &'static str {
    env!("CARGO_BIN_EXE_origin-seal")
}

/// Write `content` to `dir/name` and return the path.
fn write_file(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, content).expect("write temp file");
    p
}

/// Write raw bytes to `dir/name` and return the path.
fn write_bytes(dir: &TempDir, name: &str, content: &[u8]) -> std::path::PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, content).expect("write temp bytes");
    p
}

fn path_str(p: &std::path::Path) -> String {
    p.to_str().expect("utf-8 path").to_string()
}

use wait_timeout::ChildExt;

/// Spawn `origin-seal` with the given args, bounding wall-clock time to 60s.
///
/// A hung `seal` (e.g. `verify` spinning on a bad seed/domain path) fails the
/// test fast with a clear message instead of freezing the whole suite. 60s is
/// generous for Argon2 + Falcon but finite.
fn run_with_timeout(args: &[&str]) -> std::process::Output {
    let mut child = Command::new(seal_bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn origin-seal {args:?}: {e}"));
    match child
        .wait_timeout(std::time::Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("wait on origin-seal {args:?}: {e}"))
    {
        Some(status) => child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("collect origin-seal output {args:?}: {e}")),
        None => {
            let _ = child.kill();
            panic!("origin-seal {args:?} exceeded 60s wall-clock — possible hang (killed child)");
        }
    }
}

/// Sign and write the signature to `out_path` (stdout redirected to the file),
/// bounded by the same 60s liveness guard as `run_with_timeout`.
fn sign_to_file(args: &[&str], out_path: &std::path::Path) {
    let mut child = Command::new(seal_bin())
        .args(args)
        .stdout(Stdio::from(
            std::fs::File::create(out_path).expect("create sig file"),
        ))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn origin-seal sign {args:?}: {e}"));
    match child
        .wait_timeout(std::time::Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("wait on origin-seal sign {args:?}: {e}"))
    {
        Some(_) => {
            child
                .wait_with_output()
                .unwrap_or_else(|e| panic!("collect origin-seal sign output {args:?}: {e}"));
        }
        None => {
            let _ = child.kill();
            panic!(
                "origin-seal sign {args:?} exceeded 60s wall-clock — possible hang (killed child)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// hash
// ---------------------------------------------------------------------------

#[test]
fn hash_sha3_256_known_vector() {
    // SHA3-256("hello") — known answer.
    let out = Command::new(seal_bin())
        .args(["hash", "--algo", "sha3-256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.as_mut().unwrap().write_all(b"hello").unwrap();
            c.wait_with_output()
        })
        .expect("run seal hash");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim(),
        "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"
    );
}

#[test]
fn hash_blake3_deterministic() {
    let dir = TempDir::new().unwrap();
    let inp = write_file(&dir, "in.txt", "deterministic input");
    let run = || {
        let out = Command::new(seal_bin())
            .args(["hash", "--algo", "blake3", "-i", &path_str(&inp)])
            .output()
            .expect("run");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(run(), run());
}

// ---------------------------------------------------------------------------
// encrypt / decrypt
// ---------------------------------------------------------------------------

#[test]
fn encrypt_decrypt_roundtrip() {
    let dir = TempDir::new().unwrap();
    let pt = write_file(&dir, "pt.txt", "the quick brown fox");
    let pw = write_file(&dir, "pw.txt", "correct horse");
    let ct = dir.path().join("ct.bin");
    let out = dir.path().join("out.txt");

    let enc = Command::new(seal_bin())
        .args([
            "encrypt",
            "-i",
            &path_str(&pt),
            "-o",
            &path_str(&ct),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
        ])
        .output()
        .expect("encrypt");
    assert!(
        enc.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let dec = Command::new(seal_bin())
        .args([
            "decrypt",
            "-i",
            &path_str(&ct),
            "-o",
            &path_str(&out),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
        ])
        .output()
        .expect("decrypt");
    assert!(
        dec.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&dec.stderr)
    );

    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        "the quick brown fox"
    );
}

#[test]
fn decrypt_wrong_passphrase_fails() {
    let dir = TempDir::new().unwrap();
    let pt = write_file(&dir, "pt.txt", "secret");
    let pw = write_file(&dir, "pw.txt", "right");
    let bad = write_file(&dir, "bad.txt", "wrong");
    let ct = dir.path().join("ct.bin");

    Command::new(seal_bin())
        .args([
            "encrypt",
            "-i",
            &path_str(&pt),
            "-o",
            &path_str(&ct),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
        ])
        .output()
        .expect("encrypt");

    let dec = Command::new(seal_bin())
        .args([
            "decrypt",
            "-i",
            &path_str(&ct),
            "--passphrase-file",
            &path_str(&bad),
            "--tier",
            "nano",
        ])
        .output()
        .expect("decrypt");
    assert!(!dec.status.success());
    let stderr = String::from_utf8_lossy(&dec.stderr);
    assert!(
        stderr.contains("wrong passphrase or corrupt"),
        "stderr: {stderr}"
    );
}

#[test]
fn decrypt_tier_mismatch_fails() {
    let dir = TempDir::new().unwrap();
    let pt = write_file(&dir, "pt.txt", "secret");
    let pw = write_file(&dir, "pw.txt", "pw");
    let ct = dir.path().join("ct.bin");

    Command::new(seal_bin())
        .args([
            "encrypt",
            "-i",
            &path_str(&pt),
            "-o",
            &path_str(&ct),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
        ])
        .output()
        .expect("encrypt");

    let dec = Command::new(seal_bin())
        .args([
            "decrypt",
            "-i",
            &path_str(&ct),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "sovereign",
        ])
        .output()
        .expect("decrypt");
    assert!(!dec.status.success());
    assert!(String::from_utf8_lossy(&dec.stderr).contains("tier mismatch"));
}

#[test]
fn encrypt_compress_roundtrip() {
    let dir = TempDir::new().unwrap();
    let big = "compressible line\n".repeat(200);
    let pt = write_file(&dir, "pt.txt", &big);
    let pw = write_file(&dir, "pw.txt", "pw");
    let ct = dir.path().join("ct.bin");

    let enc = Command::new(seal_bin())
        .args([
            "encrypt",
            "-i",
            &path_str(&pt),
            "-o",
            &path_str(&ct),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
            "--compress",
        ])
        .output()
        .expect("encrypt");
    assert!(enc.status.success());

    // Compressed envelope must be smaller than plaintext.
    let ct_len = std::fs::metadata(&ct).unwrap().len() as usize;
    assert!(
        ct_len < big.len(),
        "ct {ct_len} not smaller than pt {}",
        big.len()
    );

    let dec = Command::new(seal_bin())
        .args([
            "decrypt",
            "-i",
            &path_str(&ct),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
        ])
        .output()
        .expect("decrypt");
    assert!(dec.status.success());
    assert_eq!(String::from_utf8_lossy(&dec.stdout), big);
}

// ---------------------------------------------------------------------------
// sign / verify
// ---------------------------------------------------------------------------

const TEST_SEED: &str = "0000000000000000000000000000000000000000000000000000000000000001";

#[test]
fn sign_verify_json_roundtrip() {
    let dir = TempDir::new().unwrap();
    let msg = write_file(&dir, "msg.txt", "message to sign");
    let sig = dir.path().join("sig.json");

    let s = sign_to_file(
        &[
            "sign",
            "-i",
            &path_str(&msg),
            "--seed",
            TEST_SEED,
            "--domain",
            "test",
            "--format",
            "json",
        ],
        &sig,
    );
    // sign_to_file returns () on success; surface a sign failure clearly.
    let _ = s;

    let v = run_with_timeout(&[
        "verify",
        "-i",
        &path_str(&msg),
        "--signature",
        &path_str(&sig),
        "--seed",
        TEST_SEED,
        "--domain",
        "test",
    ]);
    assert!(
        v.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&v.stderr)
    );
    assert!(String::from_utf8_lossy(&v.stdout).contains("OK"));
}

#[test]
fn sign_verify_hex_wire_roundtrip() {
    let dir = TempDir::new().unwrap();
    let msg = write_file(&dir, "msg.txt", "hex wire message");
    let sig = dir.path().join("sig.hex");

    sign_to_file(
        &[
            "sign",
            "-i",
            &path_str(&msg),
            "--seed",
            TEST_SEED,
            "--domain",
            "test",
            "--format",
            "hex",
        ],
        &sig,
    );

    let v = run_with_timeout(&[
        "verify",
        "-i",
        &path_str(&msg),
        "--signature",
        &path_str(&sig),
        "--seed",
        TEST_SEED,
        "--domain",
        "test",
    ]);
    assert!(
        v.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&v.stderr)
    );
}

#[test]
fn verify_tampered_message_fails() {
    let dir = TempDir::new().unwrap();
    let msg = write_file(&dir, "msg.txt", "original");
    let tampered = write_file(&dir, "tampered.txt", "tampered");
    let sig = dir.path().join("sig.json");

    sign_to_file(
        &[
            "sign",
            "-i",
            &path_str(&msg),
            "--seed",
            TEST_SEED,
            "--domain",
            "test",
            "--format",
            "json",
        ],
        &sig,
    );

    let v = run_with_timeout(&[
        "verify",
        "-i",
        &path_str(&tampered),
        "--signature",
        &path_str(&sig),
        "--seed",
        TEST_SEED,
        "--domain",
        "test",
    ]);
    assert!(!v.status.success());
    assert!(String::from_utf8_lossy(&v.stderr).contains("FAILED"));
}

#[test]
fn verify_wrong_domain_fails() {
    let dir = TempDir::new().unwrap();
    let msg = write_file(&dir, "msg.txt", "domain-bound");
    let sig = dir.path().join("sig.json");

    sign_to_file(
        &[
            "sign",
            "-i",
            &path_str(&msg),
            "--seed",
            TEST_SEED,
            "--domain",
            "domain-a",
            "--format",
            "json",
        ],
        &sig,
    );

    let v = run_with_timeout(&[
        "verify",
        "-i",
        &path_str(&msg),
        "--signature",
        &path_str(&sig),
        "--seed",
        TEST_SEED,
        "--domain",
        "domain-b",
    ]);
    assert!(!v.status.success(), "verify should fail across domains");
}

// ---------------------------------------------------------------------------
// kdf / mac
// ---------------------------------------------------------------------------

#[test]
fn kdf_deterministic_with_fixed_salt() {
    let dir = TempDir::new().unwrap();
    let pw = write_file(&dir, "pw.txt", "kdf-pass");
    let run = || {
        let out = Command::new(seal_bin())
            .args([
                "kdf",
                "--passphrase-file",
                &path_str(&pw),
                "--salt",
                "00112233445566778899aabbccddeeff",
                "--tier",
                "nano",
            ])
            .output()
            .expect("kdf");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    assert_eq!(run(), run());
}

#[test]
fn mac_deterministic() {
    let dir = TempDir::new().unwrap();
    let inp = write_file(&dir, "in.txt", "mac data");
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let run = || {
        let out = Command::new(seal_bin())
            .args(["mac", "-i", &path_str(&inp), "--key", key])
            .output()
            .expect("mac");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let a = run();
    assert_eq!(a.len(), 64, "HMAC-SHA3-256 hex should be 64 chars");
    assert_eq!(a, run());
}

// ---------------------------------------------------------------------------
// error handling
// ---------------------------------------------------------------------------

#[test]
fn decrypt_garbage_input_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    // 64 bytes: long enough to pass the length gate, wrong magic.
    let garbage = write_bytes(&dir, "garbage.bin", &[0x41u8; 64]);
    let pw = write_file(&dir, "pw.txt", "pw");

    let dec = Command::new(seal_bin())
        .args([
            "decrypt",
            "-i",
            &path_str(&garbage),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
        ])
        .output()
        .expect("decrypt");
    assert!(!dec.status.success());
    assert!(String::from_utf8_lossy(&dec.stderr).contains("bad magic"));
}

#[test]
fn decrypt_too_short_input_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    let short = write_bytes(&dir, "short.bin", b"tiny");
    let pw = write_file(&dir, "pw.txt", "pw");

    let dec = Command::new(seal_bin())
        .args([
            "decrypt",
            "-i",
            &path_str(&short),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
        ])
        .output()
        .expect("decrypt");
    assert!(!dec.status.success());
    assert!(String::from_utf8_lossy(&dec.stderr).contains("too short"));
}

#[test]
fn unknown_tier_rejected() {
    let dir = TempDir::new().unwrap();
    let pt = write_file(&dir, "pt.txt", "x");
    let pw = write_file(&dir, "pw.txt", "pw");

    let enc = Command::new(seal_bin())
        .args([
            "encrypt",
            "-i",
            &path_str(&pt),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "ultra",
        ])
        .output()
        .expect("encrypt");
    assert!(!enc.status.success());
    assert!(String::from_utf8_lossy(&enc.stderr).contains("unknown tier"));
}

// ---------------------------------------------------------------------------
// streaming
// ---------------------------------------------------------------------------

#[test]
fn stream_roundtrip_multi_chunk() {
    let dir = TempDir::new().unwrap();
    // 2.5 MiB of random data → 3 chunks at 1 MiB.
    let data: Vec<u8> = (0..2_621_440).map(|i| (i % 251) as u8).collect();
    let pt = write_bytes(&dir, "big.bin", &data);
    let pw = write_file(&dir, "pw.txt", "stream-pw");
    let seal = dir.path().join("big.seal");
    let out = dir.path().join("big.out");

    let enc = Command::new(seal_bin())
        .args([
            "encrypt",
            "-i",
            &path_str(&pt),
            "-o",
            &path_str(&seal),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
            "--stream",
            "--chunk-size",
            "1048576",
        ])
        .output()
        .expect("encrypt");
    assert!(
        enc.status.success(),
        "encrypt stderr: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let dec = Command::new(seal_bin())
        .args([
            "decrypt",
            "-i",
            &path_str(&seal),
            "-o",
            &path_str(&out),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
        ])
        .output()
        .expect("decrypt");
    assert!(
        dec.status.success(),
        "decrypt stderr: {}",
        String::from_utf8_lossy(&dec.stderr)
    );

    let recovered = std::fs::read(&out).expect("read out");
    assert_eq!(recovered, data, "stream round-trip mismatch");
}

#[test]
fn stream_truncation_detected() {
    let dir = TempDir::new().unwrap();
    let data: Vec<u8> = (0..3_000_000).map(|i| (i % 199) as u8).collect();
    let pt = write_bytes(&dir, "big.bin", &data);
    let pw = write_file(&dir, "pw.txt", "pw");
    let seal = dir.path().join("big.seal");
    let out = dir.path().join("big.out");

    Command::new(seal_bin())
        .args([
            "encrypt",
            "-i",
            &path_str(&pt),
            "-o",
            &path_str(&seal),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
            "--stream",
            "--chunk-size",
            "1048576",
        ])
        .output()
        .expect("encrypt");

    // Chop the last 100 bytes — removes the sentinel and part of a chunk.
    let full = std::fs::read(&seal).expect("read seal");
    let truncated = &full[..full.len() - 100];
    let trunc_path = write_bytes(&dir, "big.trunc.seal", truncated);

    let dec = Command::new(seal_bin())
        .args([
            "decrypt",
            "-i",
            &path_str(&trunc_path),
            "-o",
            &path_str(&out),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
        ])
        .output()
        .expect("decrypt");
    assert!(!dec.status.success(), "truncated stream must fail");
    assert!(String::from_utf8_lossy(&dec.stderr).contains("truncat"));
}

#[test]
fn stream_and_compress_mutually_exclusive() {
    let dir = TempDir::new().unwrap();
    let pt = write_file(&dir, "pt.txt", "data");
    let pw = write_file(&dir, "pw.txt", "pw");

    let enc = Command::new(seal_bin())
        .args([
            "encrypt",
            "-i",
            &path_str(&pt),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
            "--stream",
            "--compress",
        ])
        .output()
        .expect("encrypt");
    assert!(!enc.status.success());
    assert!(String::from_utf8_lossy(&enc.stderr).contains("mutually exclusive"));
}

#[test]
fn stream_wrong_passphrase_fails() {
    let dir = TempDir::new().unwrap();
    let data: Vec<u8> = (0..2_000_000).map(|i| (i % 127) as u8).collect();
    let pt = write_bytes(&dir, "big.bin", &data);
    let pw = write_file(&dir, "pw.txt", "correct");
    let bad = write_file(&dir, "bad.txt", "wrong");
    let seal = dir.path().join("big.seal");
    let out = dir.path().join("big.out");

    Command::new(seal_bin())
        .args([
            "encrypt",
            "-i",
            &path_str(&pt),
            "-o",
            &path_str(&seal),
            "--passphrase-file",
            &path_str(&pw),
            "--tier",
            "nano",
            "--stream",
            "--chunk-size",
            "1048576",
        ])
        .output()
        .expect("encrypt");

    let dec = Command::new(seal_bin())
        .args([
            "decrypt",
            "-i",
            &path_str(&seal),
            "-o",
            &path_str(&out),
            "--passphrase-file",
            &path_str(&bad),
            "--tier",
            "nano",
        ])
        .output()
        .expect("decrypt");
    assert!(!dec.status.success());
    assert!(String::from_utf8_lossy(&dec.stderr).contains("decryption failed"));
}
