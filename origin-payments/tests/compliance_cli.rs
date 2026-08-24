// SPDX-License-Identifier: Apache-2.0

//! CLI integration test for `--compliance-rule`: proves the executor
//! respects compliance thresholds through the real binary, not just the
//! library API.

use std::process::Command;

use origin_payments::store::PaymentStore;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_origin-payments"))
}

fn run_ok(bin: &mut Command) -> std::process::Output {
    let out = bin.output().unwrap();
    assert!(
        out.status.success(),
        "command failed: {:?}\nstderr: {}",
        bin,
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn run_err(bin: &mut Command) -> std::process::Output {
    let out = bin.output().unwrap();
    assert!(
        !out.status.success(),
        "command should have failed: {:?}\nstdout: {}",
        bin,
        String::from_utf8_lossy(&out.stdout)
    );
    out
}

/// A valid 64-hex MeshId for native rail testing.
const PEER_MESH: &str = "e2ad0a8b3395fdc9dc84c845e058ee5be59634a51253d997e8ecd61daa6491b5";

/// Create a wallet via the library and return (wallet_path, passphrase_path).
fn make_wallet(dir: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let wallet = dir.path().join("payer.wallet");
    let pass = dir.path().join("payer.pass");
    std::fs::write(&pass, "cli-test-passphrase-123456").unwrap();
    let mut w = origin_wallet::Wallet::create("cli-test-passphrase-123456").unwrap();
    w.derive_account(0).unwrap();
    w.save(&wallet, "cli-test-passphrase-123456").unwrap();
    (wallet, pass)
}

#[test]
fn compliance_reject_above_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("payments");
    let home_s = home.to_str().unwrap().to_string();
    let (wallet, pass) = make_wallet(&dir);

    run_ok(bin().args(["--home", &home_s, "init", "--per-tx-cap", "500.00"]));

    // Create an order for $15.00 — above our reject threshold of $10.00.
    run_ok(bin().args([
        "--home",
        &home_s,
        "order-create",
        "--checkout",
        "c-above",
        "--to",
        PEER_MESH,
        "--amount",
        "15.00",
        "--currency",
        "USD",
    ]));

    // Run executor with a compliance rule: reject above 10.00 (1000 minor).
    let out = run_ok(bin().args([
        "--home",
        &home_s,
        "executor-run",
        "--once",
        "--wallet",
        wallet.to_str().unwrap(),
        "-p",
        pass.to_str().unwrap(),
        "--compliance-rule",
        r#"{"reject_threshold_minor":1000,"flag_threshold_minor":500}"#,
    ]));
    let stdout = String::from_utf8_lossy(&out.stdout);

    // The order should be compliance-rejected (NOT just retried).
    assert!(
        stdout.contains("compliance rejected"),
        "expected compliance rejection in output: {stdout}"
    );

    // Verify it's in the DLQ with the compliance reason.
    let store = PaymentStore::open(&home).unwrap();
    let dlq = store.dlq_records().unwrap();
    let found = dlq.iter().any(|r| r.reason.contains("compliance rejected"));
    assert!(found, "order should be in DLQ with compliance reason");
}

#[test]
fn compliance_below_threshold_proceeds() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("payments");
    let home_s = home.to_str().unwrap().to_string();
    let (wallet, pass) = make_wallet(&dir);

    run_ok(bin().args(["--home", &home_s, "init", "--per-tx-cap", "500.00"]));

    // Create an order for $1.00 — below the $10.00 reject threshold.
    run_ok(bin().args([
        "--home",
        &home_s,
        "order-create",
        "--checkout",
        "c-below",
        "--to",
        PEER_MESH,
        "--amount",
        "1.00",
        "--currency",
        "USD",
    ]));

    // Run with same compliance rule — should NOT be rejected.
    let _ = run_ok(bin().args([
        "--home",
        &home_s,
        "executor-run",
        "--once",
        "--wallet",
        wallet.to_str().unwrap(),
        "-p",
        pass.to_str().unwrap(),
        "--compliance-rule",
        r#"{"reject_threshold_minor":1000,"flag_threshold_minor":500}"#,
    ]));

    // Should NOT be compliance-rejected (may retry for other reasons, e.g.
    // peer unreachable, but not compliance).
    let store = PaymentStore::open(&home).unwrap();
    let dlq = store.dlq_records().unwrap();
    for record in &dlq {
        assert!(
            !record.reason.contains("compliance rejected"),
            "below-threshold order should NOT be compliance-rejected: {}",
            record.reason
        );
    }
}

#[test]
fn compliance_flag_flag_in_audit() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("payments");
    let home_s = home.to_str().unwrap().to_string();
    let (wallet, pass) = make_wallet(&dir);

    run_ok(bin().args(["--home", &home_s, "init", "--per-tx-cap", "500.00"]));

    // Create an order for $7.00 — above the $5.00 flag but below the $10.00 reject.
    run_ok(bin().args([
        "--home",
        &home_s,
        "order-create",
        "--checkout",
        "c-flag",
        "--to",
        PEER_MESH,
        "--amount",
        "7.00",
        "--currency",
        "USD",
    ]));

    // Run with the same rule — should flag (audit entry) but not reject.
    let _ = run_ok(bin().args([
        "--home",
        &home_s,
        "executor-run",
        "--once",
        "--wallet",
        wallet.to_str().unwrap(),
        "-p",
        pass.to_str().unwrap(),
        "--compliance-rule",
        r#"{"reject_threshold_minor":1000,"flag_threshold_minor":500}"#,
    ]));

    // The audit trail should contain an AT_ORDER_FLAGGED entry.
    let store = PaymentStore::open(&home).unwrap();
    let audits = store.audit_records().unwrap();
    let flagged = audits
        .iter()
        .any(|r| r.entry_type == origin_payments::audit::AT_ORDER_FLAGGED);
    assert!(
        flagged,
        "flagged order should produce an AT_ORDER_FLAGGED audit entry"
    );
}

#[test]
fn compliance_bad_json_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("payments");
    let home_s = home.to_str().unwrap().to_string();
    let (wallet, pass) = make_wallet(&dir);

    run_ok(bin().args(["--home", &home_s, "init", "--per-tx-cap", "500.00"]));

    // Create a valid order.
    run_ok(bin().args([
        "--home",
        &home_s,
        "order-create",
        "--checkout",
        "c-badjson",
        "--to",
        PEER_MESH,
        "--amount",
        "5.00",
        "--currency",
        "USD",
    ]));

    // Run with invalid compliance-rule JSON — should fail.
    let out = run_err(bin().args([
        "--home",
        &home_s,
        "executor-run",
        "--once",
        "--wallet",
        wallet.to_str().unwrap(),
        "-p",
        pass.to_str().unwrap(),
        "--compliance-rule",
        "not-json",
    ]));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid") || stderr.contains("JSON") || stderr.contains("parse"),
        "bad compliance JSON should produce a parse error: {stderr}"
    );
}

#[test]
fn amount_validation_at_cli() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("payments");
    let home_s = home.to_str().unwrap().to_string();

    run_ok(bin().args(["--home", &home_s, "init"]));

    // Zero amount should be rejected.
    let out = run_err(bin().args([
        "--home",
        &home_s,
        "order-create",
        "--checkout",
        "c-zero",
        "--to",
        PEER_MESH,
        "--amount",
        "0.00",
        "--currency",
        "USD",
    ]));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("positive") || stderr.contains("zero") || stderr.contains("must be"),
        "zero amount should be rejected: {stderr}"
    );

    // Negative amount — clap rejects `-5.00` as a flag before our code runs.
    // Use `--amount=-5.00` to force it through as a value.
    let out = run_err(bin().args([
        "--home",
        &home_s,
        "order-create",
        "--checkout",
        "c-neg",
        "--to",
        PEER_MESH,
        "--amount=-5.00",
        "--currency",
        "USD",
    ]));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("positive") || stderr.contains("negative") || stderr.contains("must be"),
        "negative amount should be rejected: {stderr}"
    );

    // Non-numeric amount should be rejected.
    let out = run_err(bin().args([
        "--home",
        &home_s,
        "order-create",
        "--checkout",
        "c-nan",
        "--to",
        PEER_MESH,
        "--amount",
        "abc",
        "--currency",
        "USD",
    ]));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("invalid")
            || stderr.to_lowercase().contains("parse")
            || stderr.to_lowercase().contains("number"),
        "non-numeric amount should be rejected: {stderr}"
    );
}
