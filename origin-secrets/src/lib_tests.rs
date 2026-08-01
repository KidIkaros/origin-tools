//! Unit tests for lib.rs resolve_passphrase

use super::*;
use std::path::Path;

#[test]
fn test_resolve_passphrase_none_returns_required() {
    let r = resolve_passphrase(None);
    assert!(matches!(r, Err(Error::PassphraseRequired)));
}

#[test]
fn test_resolve_passphrase_file_trims_newline() {
    let dir = tempfile::tempdir().unwrap();
    let pw = dir.path().join("pw.txt");
    std::fs::write(&pw, "secret\n").unwrap();
    let r = resolve_passphrase(Some(&pw)).unwrap();
    assert_eq!(r, "secret");
}

#[test]
fn test_resolve_passphrase_file_trims_carriage_return_newline() {
    let dir = tempfile::tempdir().unwrap();
    let pw = dir.path().join("pw.txt");
    std::fs::write(&pw, "secret\r\n").unwrap();
    let r = resolve_passphrase(Some(&pw)).unwrap();
    assert_eq!(r, "secret");
}

#[test]
fn test_resolve_passphrase_file_missing_returns_io_error() {
    let r = resolve_passphrase(Some(Path::new("/nonexistent/file.txt")));
    assert!(matches!(r, Err(Error::IoError(_))));
}

#[test]
fn test_resolve_passphrase_dash_reads_from_stdin() {
    // In a real test, we'd swap stdin, but for now we can only test the path
    // resolution — we can't mock stdin in this harness. The binary-level
    // integration test exercises stdin.
    // This test documents the expectation; the real verification is in the
    // integration dogfood (echo "$PW" | origin-secrets -p - verify).
    // We do ensure the `-` path doesn't hit PassphraseRequired:
    let r = resolve_passphrase(Some(Path::new("-")));
    assert!(!matches!(r, Err(Error::PassphraseRequired)));
}
