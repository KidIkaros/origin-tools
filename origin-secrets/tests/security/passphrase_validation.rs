//! Security test: passphrase handling.
//!
//! Verifies that the wrong/empty passphrase cannot decrypt a vault and that
//! decryption failure is reported (not a silent wrong result). A passphrase
//! source (-p) is mandatory for every command; there is no built-in default.

use clap::Parser;
use origin_secrets::cli::Cli;
use origin_secrets::dispatch;
use std::io::Write;
use std::path::Path;

fn cli(vault: &Path, passfile: Option<&Path>, args: &[&str]) -> Cli {
    let mut full = vec!["origin-secrets", "-V"];
    full.push(vault.to_str().unwrap());
    if let Some(pf) = passfile {
        full.push("-p");
        full.push(pf.to_str().unwrap());
    }
    full.extend_from_slice(args);
    Cli::parse_from(full)
}

fn write_pw(path: &Path, pw: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    writeln!(f, "{pw}").unwrap();
}

#[test]
fn wrong_passphrase_cannot_decrypt_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");

    // init with a known passphrase
    let correct = dir.path().join("correct.pw");
    write_pw(&correct, "correct horse battery staple");
    dispatch(cli(&vault, Some(&correct), &["init", "--tier", "standard"])).unwrap();

    // write a WRONG passphrase to a file and try to shard (needs vault decrypt)
    let wrong = dir.path().join("wrong.pw");
    write_pw(&wrong, "definitely-the-wrong-passphrase");

    let r = dispatch(cli(
        &vault,
        Some(&wrong),
        &[
            "shard",
            "--label",
            "master",
            "--threshold",
            "2",
            "--shares",
            "3",
        ],
    ));
    assert!(r.is_err(), "wrong passphrase must not decrypt the vault");
}

#[test]
fn empty_passphrase_file_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");

    // init with a known passphrase
    let correct = dir.path().join("correct.pw");
    write_pw(&correct, "correct horse battery staple");
    dispatch(cli(&vault, Some(&correct), &["init", "--tier", "standard"])).unwrap();

    // an empty passphrase file must not decrypt the vault
    let empty = dir.path().join("empty.pw");
    std::fs::File::create(&empty).unwrap(); // 0-byte file -> empty passphrase

    let r = dispatch(cli(
        &vault,
        Some(&empty),
        &["verify", "--vault-path", vault.to_str().unwrap()],
    ));
    assert!(r.is_err(), "empty passphrase must not decrypt the vault");
}

#[test]
fn missing_passphrase_is_rejected() {
    // No -p at all must be refused (no silent weak default fallback).
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    let r = dispatch(cli(&vault, None, &["init", "--tier", "standard"]));
    assert!(
        matches!(r, Err(origin_secrets::Error::PassphraseRequired)),
        "init without -p must return PassphraseRequired, got: {:?}",
        r
    );
}
