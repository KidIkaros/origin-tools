// SPDX-License-Identifier: Apache-2.0

//! P7: admin operations through the real `origin-payments` binary —
//! the audit hash chain (origin-attest shape), the TOTP 2FA gate on
//! admin commands, and K-of-N custody (origin-secrets) with
//! threshold recovery.

use std::path::Path;
use std::process::Command;

use origin_crypto_sdk::drbg::otp::{format_code, totp, HashAlgorithm};
use origin_payments::audit;
use origin_payments::store::PaymentStore;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_origin-payments"))
}

fn run(bin: &mut Command) -> std::process::Output {
    let out = bin.output().unwrap();
    assert!(
        out.status.success(),
        "command failed: {}\nstderr: {}",
        format!("{:?}", bin),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// Read the 2FA secret the binary wrote and compute the current code,
/// exactly as an authenticator app would (RFC 6238, SHA-256, ±0 window).
fn current_totp(root: &Path) -> String {
    let raw = std::fs::read_to_string(root.join("admin_2fa.secret")).unwrap();
    let secret = hex::decode(raw.trim()).unwrap();
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    format_code(totp(&secret, now, 30, 6, HashAlgorithm::Sha256), 6)
}

#[test]
fn audit_chain_records_and_detects_tamper() {
    let dir = tempfile::tempdir().unwrap();
    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();

    audit::record(
        &store,
        audit::AT_ORDER_CREATED,
        serde_json::json!({ "order": "o1" }),
        None,
    )
    .unwrap();
    audit::record(
        &store,
        audit::AT_ORDER_SETTLED,
        serde_json::json!({ "order": "o1", "amount": "3.15" }),
        None,
    )
    .unwrap();
    audit::record(
        &store,
        audit::AT_RECONCILE,
        serde_json::json!({ "date": "2026-08-23" }),
        None,
    )
    .unwrap();
    assert!(audit::verify(&store).unwrap());

    // Tamper with a payload in the persisted log — the chain must break.
    let path = store.audit_path();
    let raw = std::fs::read_to_string(&path).unwrap();
    let mut recs: Vec<audit::AuditRecord> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    recs[1].payload = serde_json::json!({ "order": "o1", "amount": "9999.99" });
    let rewritten: Vec<String> = recs
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect();
    std::fs::write(&path, rewritten.join("\n") + "\n").unwrap();
    assert_eq!(audit::verify(&store).unwrap(), false);

    // The binary agrees: `audit verify` exits non-zero on a broken chain.
    let out = bin()
        .args(["--home", store.root().to_str().unwrap(), "audit-verify"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn totp_gate_accepts_current_code_rejects_wrong() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payments");
    let home = root.to_str().unwrap().to_string();

    run(bin().args(["--home", &home, "admin2fa-init"]));
    let code = current_totp(&root);
    let pw = dir.path().join("pw.txt");
    std::fs::write(&pw, "vault-pass-strong-1").unwrap();

    // Correct code → keys-backup proceeds (2-of-3 vault created).
    let out = bin()
        .args([
            "--home",
            &home,
            "--passphrase-file",
            pw.to_str().unwrap(),
            "keys-backup",
            "--shards",
            "3",
            "--threshold",
            "2",
            "--totp",
            &code,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(root.join("keys/secrets.vault").exists());
    assert_eq!(
        std::fs::read_dir(root.join("keys/shares")).unwrap().count(),
        3
    );

    // Wrong code → refused before anything touches the vault.
    let out = bin()
        .args([
            "--home",
            &home,
            "--passphrase-file",
            pw.to_str().unwrap(),
            "keys-backup",
            "--shards",
            "3",
            "--threshold",
            "2",
            "--totp",
            "000000",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "wrong TOTP must be refused");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("totp") || stderr.contains("2FA") || stderr.contains("TOTP"),
        "stderr: {stderr}"
    );
}

#[test]
fn custody_backup_then_recover_from_k_of_n_shares() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payments");
    let home = root.to_str().unwrap().to_string();
    let pw = dir.path().join("pw.txt");
    std::fs::write(&pw, "vault-pass-strong-1").unwrap();

    // 2-of-3 backup.
    run(bin().args(["--home", &home, "admin2fa-init"]));
    let code = current_totp(&root);
    run(bin().args([
        "--home",
        &home,
        "--passphrase-file",
        pw.to_str().unwrap(),
        "keys-backup",
        "--shards",
        "3",
        "--threshold",
        "2",
        "--totp",
        &code,
    ]));

    let mut shares: Vec<_> = std::fs::read_dir(root.join("keys/shares"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    shares.sort();
    assert_eq!(shares.len(), 3);

    // Recover with K=2 of 3 → seed written.
    let recovered = dir.path().join("recovered.seed");
    run(bin().args([
        "--home",
        &home,
        "--passphrase-file",
        pw.to_str().unwrap(),
        "keys-recover",
        "--out",
        recovered.to_str().unwrap(),
        shares[0].to_str().unwrap(),
        shares[1].to_str().unwrap(),
    ]));
    let seed = std::fs::read_to_string(&recovered).unwrap();
    assert!(!seed.trim().is_empty(), "recovered seed written");
    assert_eq!(seed.trim().len() % 2, 0, "hex-encoded seed");

    // K-1 = 1 share is below threshold → refused.
    let out = bin()
        .args([
            "--home",
            &home,
            "--passphrase-file",
            pw.to_str().unwrap(),
            "keys-recover",
            "--out",
            dir.path().join("x.seed").to_str().unwrap(),
            shares[0].to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "K-1 shares must not recover the seed"
    );
}
