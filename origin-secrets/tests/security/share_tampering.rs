//! Security test: share tampering detection.
//!
//! A share's hybrid signature (Ed25519 + Falcon-1024) binds the share data.
//! Modifying the share data, the signature, or the recipient must cause
//! recovery/verification to reject it.

use origin_secrets::cli::Cli;
use origin_secrets::dispatch;
use clap::Parser;
use std::path::Path;

fn cli(vault: &Path, args: &[&str]) -> Cli {
    let mut full = vec!["origin-secrets", "-V"];
    full.push(vault.to_str().unwrap());
    full.extend_from_slice(args);
    Cli::parse_from(full)
}

fn init_and_shard(vault: &Path) {
    dispatch(cli(vault, &["init", "--tier", "standard", "--no-prompt"])).unwrap();
    dispatch(cli(
        vault,
        &["shard", "--key", "master", "--threshold", "2", "--shares", "3"],
    ))
    .unwrap();
}

#[test]
fn tampered_share_data_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init_and_shard(&vault);

    let share = dir.path().join("shares").join("share_001.json");
    let mut s: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&share).unwrap()).unwrap();
    let mut data: Vec<u8> = serde_json::from_value(s["share_data"].clone()).unwrap();
    data[0] ^= 0x55;
    s["share_data"] = serde_json::to_value(&data).unwrap();
    std::fs::write(&share, serde_json::to_string_pretty(&s).unwrap()).unwrap();

    let r = dispatch(cli(&vault, &["verify", "--share", share.to_str().unwrap()]));
    assert!(r.is_err(), "tampered share data must be rejected");
}

#[test]
fn tampered_share_signature_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init_and_shard(&vault);

    let share = dir.path().join("shares").join("share_001.json");
    let mut s: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&share).unwrap()).unwrap();
    let mut sig: Vec<u8> = serde_json::from_value(s["signature"]["falcon1024"].clone()).unwrap();
    sig[0] ^= 0x55;
    s["signature"]["falcon1024"] = serde_json::to_value(&sig).unwrap();
    std::fs::write(&share, serde_json::to_string_pretty(&s).unwrap()).unwrap();

    let r = dispatch(cli(&vault, &["verify", "--share", share.to_str().unwrap()]));
    assert!(r.is_err(), "tampered Falcon signature must be rejected");
}

#[test]
fn recover_with_tampered_share_fails() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init_and_shard(&vault);

    // Tamper share 2, then attempt recovery with shares 1,2,3.
    let s2 = dir.path().join("shares").join("share_002.json");
    let mut s: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&s2).unwrap()).unwrap();
    let mut data: Vec<u8> = serde_json::from_value(s["share_data"].clone()).unwrap();
    data[0] ^= 0x01;
    s["share_data"] = serde_json::to_value(&data).unwrap();
    std::fs::write(&s2, serde_json::to_string_pretty(&s).unwrap()).unwrap();

    let s1 = dir.path().join("shares").join("share_001.json");
    let s3 = dir.path().join("shares").join("share_003.json");
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
    assert!(r.is_err(), "recovery with a tampered share must fail");
}
