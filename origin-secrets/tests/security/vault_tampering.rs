//! Security test: vault tampering detection.
//!
//! Any modification to the encrypted vault (ciphertext, salt, or nonce) must
//! cause decryption/verification to fail — no silent accept.

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

fn init(vault: &Path) {
    dispatch(cli(vault, &["init", "--tier", "standard", "--no-prompt"])).unwrap();
}

#[test]
fn tampered_ciphertext_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init(&vault);

    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vault).unwrap()).unwrap();
    let mut ct: Vec<u8> = serde_json::from_value(v["ciphertext"].clone()).unwrap();
    ct[0] ^= 0x01;
    v["ciphertext"] = serde_json::to_value(&ct).unwrap();
    std::fs::write(&vault, serde_json::to_string_pretty(&v).unwrap()).unwrap();

    let r = dispatch(cli(&vault, &["verify", "--vault-path", vault.to_str().unwrap()]));
    assert!(r.is_err(), "tampered ciphertext must be rejected");
}

#[test]
fn tampered_salt_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init(&vault);

    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vault).unwrap()).unwrap();
    let mut salt: Vec<u8> = serde_json::from_value(v["salt"].clone()).unwrap();
    salt[0] ^= 0x42;
    v["salt"] = serde_json::to_value(&salt).unwrap();
    std::fs::write(&vault, serde_json::to_string_pretty(&v).unwrap()).unwrap();

    let r = dispatch(cli(&vault, &["verify", "--vault-path", vault.to_str().unwrap()]));
    assert!(r.is_err(), "tampered salt must be rejected");
}

#[test]
fn tampered_nonce_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init(&vault);

    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vault).unwrap()).unwrap();
    let mut nonce: Vec<u8> = serde_json::from_value(v["nonce"].clone()).unwrap();
    nonce[0] ^= 0x99;
    v["nonce"] = serde_json::to_value(&nonce).unwrap();
    std::fs::write(&vault, serde_json::to_string_pretty(&v).unwrap()).unwrap();

    let r = dispatch(cli(&vault, &["verify", "--vault-path", vault.to_str().unwrap()]));
    assert!(r.is_err(), "tampered nonce must be rejected");
}
