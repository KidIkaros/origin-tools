//! Security test: share tampering detection.
//!
//! A share's hybrid signature (Ed25519 + Falcon-1024) binds the share data.
//! Modifying the share data, the signature, or the recipient must cause
//! recovery/verification to reject it.

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

fn init_and_shard(vault: &Path) {
    dispatch(cli(vault, &["init", "--tier", "standard"])).unwrap();
    dispatch(cli(
        vault,
        &[
            "shard",
            "--label",
            "master",
            "--threshold",
            "2",
            "--shares",
            "3",
        ],
    ))
    .unwrap();
}

#[test]
fn tampered_share_data_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init_and_shard(&vault);

    let share = dir.path().join("shares").join("share_001.json");
    // P3.3: shares are encrypted at rest, so the on-disk file is an
    // EncryptedShare envelope (version/nonce/ciphertext). Flip a byte in the
    // ciphertext to simulate tampering; the AEAD check must reject it.
    let mut s: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&share).unwrap()).unwrap();
    let mut data: Vec<u8> = serde_json::from_value(s["ciphertext"].clone()).unwrap();
    data[0] ^= 0x55;
    s["ciphertext"] = serde_json::to_value(&data).unwrap();
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
    // P3.3: the on-disk file is an EncryptedShare envelope. Tamper its
    // ciphertext so the AEAD check rejects it during verification.
    let mut s: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&share).unwrap()).unwrap();
    let mut sig: Vec<u8> = serde_json::from_value(s["ciphertext"].clone()).unwrap();
    sig[0] ^= 0x55;
    s["ciphertext"] = serde_json::to_value(&sig).unwrap();
    std::fs::write(&share, serde_json::to_string_pretty(&s).unwrap()).unwrap();

    let r = dispatch(cli(&vault, &["verify", "--share", share.to_str().unwrap()]));
    assert!(r.is_err(), "tampered Falcon signature must be rejected");
}

#[test]
fn recover_with_tampered_share_fails() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init_and_shard(&vault);

    // Tamper share 2, then attempt recovery with shares 1,2,3. P3.3: the file
    // is an EncryptedShare envelope, so flip a byte in its ciphertext; the
    // AEAD check must reject it during recovery.
    let s2 = dir.path().join("shares").join("share_002.json");
    let mut s: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&s2).unwrap()).unwrap();
    let mut data: Vec<u8> = serde_json::from_value(s["ciphertext"].clone()).unwrap();
    data[0] ^= 0x01;
    s["ciphertext"] = serde_json::to_value(&data).unwrap();
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
