//! Security test: passphrase handling.
//!
//! Verifies that the wrong passphrase cannot decrypt a vault and that
//! decryption failure is reported (not a silent wrong result).

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

#[test]
fn wrong_passphrase_cannot_decrypt_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");

    // init with default passphrase (dispatch default)
    dispatch(cli(
        &vault,
        None,
        &["init", "--tier", "standard", "--no-prompt"],
    ))
    .unwrap();

    // write a WRONG passphrase to a file and try to shard (needs vault decrypt)
    let wrong = dir.path().join("wrong.pw");
    let mut f = std::fs::File::create(&wrong).unwrap();
    writeln!(f, "definitely-the-wrong-passphrase").unwrap();
    drop(f);

    let r = dispatch(cli(
        &vault,
        Some(&wrong),
        &[
            "shard",
            "--key",
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

    dispatch(cli(
        &vault,
        None,
        &["init", "--tier", "standard", "--no-prompt"],
    ))
    .unwrap();

    let empty = dir.path().join("empty.pw");
    std::fs::File::create(&empty).unwrap(); // 0-byte file -> empty passphrase

    let r = dispatch(cli(
        &vault,
        Some(&empty),
        &["verify", "--vault-path", vault.to_str().unwrap()],
    ));
    assert!(r.is_err(), "empty passphrase must not decrypt the vault");
}
