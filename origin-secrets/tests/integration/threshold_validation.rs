//! Integration test: threshold validation (K-of-N correctness).

use clap::Parser;
use origin_secrets::cli::Cli;
use origin_secrets::dispatch;
use std::path::Path;

fn cli(vault: &Path, args: &[&str]) -> Cli {
    // Every command requires a passphrase source (-p); attach a temp file.
    let pw = vault.parent().unwrap().join("pw.txt");
    std::fs::write(&pw, "correct horse battery staple\n").unwrap();
    let mut full = vec!["origin-secrets", "-V"];
    full.push(vault.to_str().unwrap());
    full.push("-p");
    full.push(pw.to_str().unwrap());
    full.extend_from_slice(args);
    Cli::parse_from(full)
}

fn setup(vault: &Path, shares_dir: &Path) {
    dispatch(cli(vault, &["init", "--tier", "standard"])).unwrap();
    dispatch(cli(
        vault,
        &[
            "shard",
            "--label",
            "master",
            "--threshold",
            "3",
            "--shares",
            "5",
        ],
    ))
    .unwrap();
    // ensure shares_dir points at the vault's sibling `shares` dir
    let _ = shares_dir;
}

#[test]
fn insufficient_shares_fails_at_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    setup(&vault, &dir.path().join("shares"));

    let shares = dir.path().join("shares");
    let s1 = shares.join("share_001.json");
    let s2 = shares.join("share_002.json");
    // Only 2 of 3 threshold -> must fail.
    let r = dispatch(cli(
        &vault,
        &["recover", s1.to_str().unwrap(), s2.to_str().unwrap()],
    ));
    assert!(r.is_err(), "recover with <threshold shares should fail");
}

#[test]
fn exact_threshold_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    setup(&vault, &dir.path().join("shares"));

    let shares = dir.path().join("shares");
    let s1 = shares.join("share_001.json");
    let s2 = shares.join("share_002.json");
    let s3 = shares.join("share_003.json");
    let out = dir.path().join("seed.out");
    let r = dispatch(cli(
        &vault,
        &[
            "recover",
            s1.to_str().unwrap(),
            s2.to_str().unwrap(),
            s3.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ],
    ));
    assert!(
        r.is_ok(),
        "recover with exactly K shares should succeed: {:?}",
        r
    );
    assert_eq!(std::fs::read_to_string(&out).unwrap().len(), 64);
}

#[test]
fn invalid_threshold_rejected_by_shard() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    setup(&vault, &dir.path().join("shares"));

    // threshold (5) > shares (3) is invalid
    let r = dispatch(cli(
        &vault,
        &[
            "shard",
            "--label",
            "master",
            "--threshold",
            "5",
            "--shares",
            "3",
        ],
    ));
    assert!(r.is_err(), "shard with threshold>shares should fail");
}
