//! Integration test: hybrid signature verification (Ed25519 + Falcon-1024).
//!
//! Confirms that (a) legitimate shares verify, and (b) a tampered share is
//! rejected because its hybrid signature no longer validates.

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

fn init_and_shard(vault: &Path, threshold: u8, shares: u8) {
    // cli() injects the -p passphrase file, so init/shard get a real key.
    dispatch(cli(vault, &["init", "--tier", "standard"])).unwrap();
    dispatch(cli(
        vault,
        &[
            "shard",
            "--key",
            "master",
            "--threshold",
            &threshold.to_string(),
            "--shares",
            &shares.to_string(),
        ],
    ))
    .unwrap();
}

#[test]
fn valid_share_passes_verify() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init_and_shard(&vault, 2, 3);

    let share = dir.path().join("shares").join("share_001.json");
    let r = dispatch(cli(&vault, &["verify", "--share", share.to_str().unwrap()]));
    assert!(r.is_ok(), "valid share should verify: {:?}", r);
}

#[test]
fn tampered_share_fails_verify() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init_and_shard(&vault, 2, 3);

    let share_path = dir.path().join("shares").join("share_001.json");
    // Flip a byte in the share data to simulate tampering.
    let mut share: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&share_path).unwrap()).unwrap();
    let data = share["share_data"].clone();
    let mut bytes: Vec<u8> = serde_json::from_value(data).unwrap();
    bytes[0] ^= 0xFF;
    share["share_data"] = serde_json::to_value(&bytes).unwrap();
    std::fs::write(&share_path, serde_json::to_string_pretty(&share).unwrap()).unwrap();

    let r = dispatch(cli(
        &vault,
        &["verify", "--share", share_path.to_str().unwrap()],
    ));
    assert!(r.is_err(), "tampered share must fail verification");
}

#[test]
fn vault_integrity_tamper_detected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init_and_shard(&vault, 2, 3);

    // Corrupt the ciphertext in the vault file.
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vault).unwrap()).unwrap();
    let ct = v["ciphertext"].clone();
    let mut cbytes: Vec<u8> = serde_json::from_value(ct).unwrap();
    cbytes[0] ^= 0xFF;
    v["ciphertext"] = serde_json::to_value(&cbytes).unwrap();
    std::fs::write(&vault, serde_json::to_string_pretty(&v).unwrap()).unwrap();

    let r = dispatch(cli(
        &vault,
        &["verify", "--vault-path", vault.to_str().unwrap()],
    ));
    assert!(r.is_err(), "tampered vault must fail verification");
}

#[test]
fn verify_share_binds_to_source_vault_not_default() {
    // Regression: `verify --share` must verify against the share's OWN source
    // vault (its grandparent dir), not the resolved default vault path. A share
    // from vault A must not be checked against vault B's signing key.
    let dir = tempfile::tempdir().unwrap();
    let vault_a = dir.path().join("vaultA").join("secrets.vault");
    std::fs::create_dir_all(vault_a.parent().unwrap()).unwrap();
    let vault_b = dir.path().join("vaultB").join("secrets.vault");
    std::fs::create_dir_all(vault_b.parent().unwrap()).unwrap();

    init_and_shard(&vault_a, 2, 3);
    init_and_shard(&vault_b, 2, 3);

    let share_a = vault_a
        .parent()
        .unwrap()
        .join("shares")
        .join("share_001.json");
    // Verify share A using vault B as the resolved default path. The fix routes
    // verification to share A's own source vault (vaultA), so it must pass.
    let r = dispatch(cli(
        &vault_b,
        &["verify", "--share", share_a.to_str().unwrap()],
    ));
    assert!(
        r.is_ok(),
        "share must verify against its source vault even when default points elsewhere: {:?}",
        r
    );
}
