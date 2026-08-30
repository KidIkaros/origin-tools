// SPDX-License-Identifier: Apache-2.0

//! Integration tests for origin-archive — end-to-end CLI roundtrips.
//!
//! These tests exercise the full CLI path (archive → unarchive) with various
//! parameters to ensure the tool is production-ready.

use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Get the path to the origin-archive binary.
fn archive_bin() -> &'static str {
    // CARGO_BIN_EXE_origin-archive is set by cargo for integration tests.
    env!("CARGO_BIN_EXE_origin-archive")
}

/// Generate a unique temp directory for this test invocation.
fn tmp_dir() -> String {
    let id = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("/tmp/oa_test_{id}_{n}")
}

/// Generate incompressible (random) data for tests that need multiple chunks.
fn random_data(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    origin_crypto_sdk::fill_random(&mut buf).unwrap();
    buf
}

/// Run origin-archive archive, then unarchive, and verify roundtrip.
fn roundtrip(data: &[u8], passphrase: &str, tier: &str, compressor: &str) {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();

    let input = format!("{dir}/input.bin");
    let enc = format!("{dir}/archive.enc");
    let output = format!("{dir}/output.bin");
    let pp = format!("{dir}/pass.txt");

    std::fs::write(&input, data).unwrap();
    std::fs::write(&pp, passphrase).unwrap();

    let bin = archive_bin();
    let out = Command::new(bin)
        .args([
            "archive",
            "--input",
            &input,
            "--output",
            &enc,
            "--passphrase-file",
            &pp,
            "--tier",
            tier,
            "--compressor",
            compressor,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "archive failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(bin)
        .args([
            "unarchive",
            "--input",
            &enc,
            "--output",
            &output,
            "--passphrase-file",
            &pp,
            "--tier",
            tier,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "unarchive failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let recovered = std::fs::read(&output).unwrap();
    assert_eq!(data, &recovered[..], "roundtrip data mismatch");

    // Verify inspect works on the archive.
    let out = Command::new(bin)
        .args(["inspect", "--input", &enc])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("OZDC"), "inspect should show magic");
}

#[test]
fn test_roundtrip_zstd_nano() {
    roundtrip(b"hello archive test", "test-pass", "nano", "zstd");
}

#[test]
fn test_roundtrip_deflate_standard() {
    roundtrip(
        b"deflate + standard tier test",
        "test-pass-std",
        "standard",
        "deflate",
    );
}

#[test]
fn test_roundtrip_sovereign_zstd() {
    roundtrip(
        b"sovereign + zstd test",
        "test-pass-sol",
        "sovereign",
        "zstd",
    );
}

#[test]
fn test_roundtrip_empty() {
    roundtrip(b"", "empty-pass", "nano", "zstd");
}

#[test]
fn test_roundtrip_large_multichunk() {
    // 200KB of random (incompressible) data — spans multiple 64KB chunks.
    let data = random_data(200_000);
    roundtrip(&data, "large-pass", "nano", "zstd");
}

#[test]
fn test_wrong_passphrase_fails() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();

    let input = format!("{dir}/input.txt");
    let enc = format!("{dir}/archive.enc");
    let pp = format!("{dir}/correct.txt");
    let pp_wrong = format!("{dir}/wrong.txt");

    std::fs::write(&input, b"secret data").unwrap();
    std::fs::write(&pp, "correct-pass").unwrap();
    std::fs::write(&pp_wrong, "wrong-pass").unwrap();

    let bin = archive_bin();
    let out = Command::new(bin)
        .args([
            "archive",
            "--input",
            &input,
            "--output",
            &enc,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    let out_wrong = format!("{dir}/wrong_out.txt");
    let out = Command::new(bin)
        .args([
            "unarchive",
            "--input",
            &enc,
            "--output",
            &out_wrong,
            "--passphrase-file",
            &pp_wrong,
            "--tier",
            "nano",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "wrong passphrase should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unarchive failed"),
        "expected auth failure, got: {stderr}"
    );
}

#[test]
fn test_tampered_ciphertext_fails() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();

    let input = format!("{dir}/input.txt");
    let enc = format!("{dir}/archive.enc");
    let pp = format!("{dir}/pass.txt");

    std::fs::write(&input, b"tamper test data").unwrap();
    std::fs::write(&pp, "tamper-pass").unwrap();

    let bin = archive_bin();
    let out = Command::new(bin)
        .args([
            "archive",
            "--input",
            &input,
            "--output",
            &enc,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Flip a byte in the ciphertext body (past the header).
    let mut data = std::fs::read(&enc).unwrap();
    if data.len() > 100 {
        data[100] ^= 0xFF;
    }
    std::fs::write(&enc, &data).unwrap();

    let out_tampered = format!("{dir}/tampered_out.txt");
    let out = Command::new(bin)
        .args([
            "unarchive",
            "--input",
            &enc,
            "--output",
            &out_tampered,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "tampered ciphertext should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unarchive failed"),
        "expected auth failure on tampered data, got: {stderr}"
    );
}

#[test]
fn test_cross_compressor_roundtrip() {
    // zstd and DEFLATE must produce valid containers, each decryptable
    // independently (the compressor is read from the header, not the CLI).
    let data = b"cross compressor test data with enough content to compress";
    let passphrase = "cross-comp-pass";

    for compressor in ["zstd", "deflate"] {
        let dir = tmp_dir();
        std::fs::create_dir_all(&dir).unwrap();

        let input = format!("{dir}/input.txt");
        let enc = format!("{dir}/archive.enc");
        let output = format!("{dir}/output.txt");
        let pp = format!("{dir}/pass.txt");

        std::fs::write(&input, data).unwrap();
        std::fs::write(&pp, passphrase).unwrap();

        let bin = archive_bin();
        let out = Command::new(bin)
            .args([
                "archive",
                "--input",
                &input,
                "--output",
                &enc,
                "--passphrase-file",
                &pp,
                "--tier",
                "nano",
                "--compressor",
                compressor,
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "archive with {compressor} failed");

        // Unarchive WITHOUT specifying --compressor (it's read from header).
        let out = Command::new(bin)
            .args([
                "unarchive",
                "--input",
                &enc,
                "--output",
                &output,
                "--passphrase-file",
                &pp,
                "--tier",
                "nano",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "unarchive with {compressor} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let recovered = std::fs::read(&output).unwrap();
        assert_eq!(data, &recovered[..], "roundtrip mismatch for {compressor}");
    }
}

#[test]
fn test_tampered_compressor_byte_fails() {
    // Archive with zstd, then flip the compressor byte in the header.
    // This changes the AAD, so decryption should fail.
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();

    let input = format!("{dir}/input.txt");
    let enc = format!("{dir}/archive.enc");
    let pp = format!("{dir}/pass.txt");

    std::fs::write(&input, b"compressor tamper test").unwrap();
    std::fs::write(&pp, "tamper-pp").unwrap();

    let bin = archive_bin();
    let out = Command::new(bin)
        .args([
            "archive",
            "--input",
            &input,
            "--output",
            &enc,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
            "--compressor",
            "zstd",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Flip the compressor byte (offset 6).
    let mut data = std::fs::read(&enc).unwrap();
    data[6] ^= 0xFF;
    std::fs::write(&enc, &data).unwrap();

    let out_tampered = format!("{dir}/tampered_out.txt");
    let out = Command::new(bin)
        .args([
            "unarchive",
            "--input",
            &enc,
            "--output",
            &out_tampered,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "tampered compressor byte should fail"
    );
}

#[test]
fn test_chunk_boundary_exact_multiple() {
    // Data that compresses to exactly N * chunk_size bytes.
    // Use random data with a small chunk size.
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();

    let data = random_data(8_192); // 8KB of random data
    let chunk_size = 4096; // 8KB / 4KB = exactly 2 chunks (if compression doesn't shrink)
    let input = format!("{dir}/input.bin");
    let enc = format!("{dir}/archive.enc");
    let output = format!("{dir}/output.bin");
    let pp = format!("{dir}/pass.txt");

    std::fs::write(&input, &data).unwrap();
    std::fs::write(&pp, "boundary-pass").unwrap();

    let bin = archive_bin();
    let out = Command::new(bin)
        .args([
            "archive",
            "--input",
            &input,
            "--output",
            &enc,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
            "--compressor",
            "zstd",
            "--chunk-size",
            &chunk_size.to_string(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    let out = Command::new(bin)
        .args([
            "unarchive",
            "--input",
            &enc,
            "--output",
            &output,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "unarchive failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let recovered = std::fs::read(&output).unwrap();
    assert_eq!(data, recovered, "roundtrip mismatch at chunk boundary");
}

#[test]
fn test_chunk_boundary_plus_one() {
    // Data that produces N chunks + 1 byte more → N+1 chunks with last chunk
    // being a single byte.
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();

    let data = random_data(8_193); // 8KB + 1 byte
    let chunk_size = 4096;
    let input = format!("{dir}/input.bin");
    let enc = format!("{dir}/archive.enc");
    let output = format!("{dir}/output.bin");
    let pp = format!("{dir}/pass.txt");

    std::fs::write(&input, &data).unwrap();
    std::fs::write(&pp, "boundary-pass").unwrap();

    let bin = archive_bin();
    let out = Command::new(bin)
        .args([
            "archive",
            "--input",
            &input,
            "--output",
            &enc,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
            "--chunk-size",
            &chunk_size.to_string(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    let out = Command::new(bin)
        .args([
            "unarchive",
            "--input",
            &enc,
            "--output",
            &output,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "unarchive failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let recovered = std::fs::read(&output).unwrap();
    assert_eq!(data, recovered);
}

#[test]
fn test_chunk_boundary_minus_one() {
    // Data that compresses to exactly N * chunk_size - 1 bytes → N-1 full
    // chunks + 1 chunk with (chunk_size - 1) bytes.
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();

    let data = random_data(4_095); // 4KB - 1 byte
    let chunk_size = 4096;
    let input = format!("{dir}/input.bin");
    let enc = format!("{dir}/archive.enc");
    let output = format!("{dir}/output.bin");
    let pp = format!("{dir}/pass.txt");

    std::fs::write(&input, &data).unwrap();
    std::fs::write(&pp, "boundary-pass").unwrap();

    let bin = archive_bin();
    let out = Command::new(bin)
        .args([
            "archive",
            "--input",
            &input,
            "--output",
            &enc,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
            "--chunk-size",
            &chunk_size.to_string(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    let out = Command::new(bin)
        .args([
            "unarchive",
            "--input",
            &enc,
            "--output",
            &output,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "unarchive failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let recovered = std::fs::read(&output).unwrap();
    assert_eq!(data, recovered);
}

#[test]
fn test_tiny_chunk_size() {
    // 8-byte chunks force many tiny chunks, exercising the STREAM nonce
    // construction with high chunk indices.
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();

    let data = random_data(500); // 500 bytes with 8-byte chunks = ~63 chunks
    let chunk_size = 8;
    let input = format!("{dir}/input.bin");
    let enc = format!("{dir}/archive.enc");
    let output = format!("{dir}/output.bin");
    let pp = format!("{dir}/pass.txt");

    std::fs::write(&input, &data).unwrap();
    std::fs::write(&pp, "tiny-chunk").unwrap();

    let bin = archive_bin();
    let out = Command::new(bin)
        .args([
            "archive",
            "--input",
            &input,
            "--output",
            &enc,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
            "--chunk-size",
            &chunk_size.to_string(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    let out = Command::new(bin)
        .args([
            "unarchive",
            "--input",
            &enc,
            "--output",
            &output,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "unarchive failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let recovered = std::fs::read(&output).unwrap();
    assert_eq!(data, recovered);
}

#[test]
fn test_stdin_stdout_pipeline() {
    // Pipe data through archive → unarchive via stdin/stdout.
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();

    let data = random_data(10_000);
    let pp = format!("{dir}/pass.txt");
    std::fs::write(&pp, "pipe-pass").unwrap();

    let bin = archive_bin();

    // Step 1: archive from stdin, output to file.
    let enc_path = format!("{dir}/archive.enc");
    let mut child = Command::new(bin)
        .args([
            "archive",
            "--input",
            "-",
            "--output",
            &enc_path,
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&data).unwrap();
    let status = child.wait().unwrap();
    assert!(status.success(), "archive via stdin failed");

    // Step 2: unarchive from file, output to stdout.
    let status = Command::new(bin)
        .args([
            "unarchive",
            "--input",
            &enc_path,
            "--output",
            "-",
            "--passphrase-file",
            &pp,
            "--tier",
            "nano",
        ])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "unarchive via stdout failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );

    assert_eq!(
        data, status.stdout,
        "stdin/stdout pipeline roundtrip mismatch"
    );
}
