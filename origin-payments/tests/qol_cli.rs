// SPDX-License-Identifier: Apache-2.0

//! QoL surface of the CLI: global flags accepted before OR after the
//! subcommand, the `status` dashboard, and shell completions.

use std::process::Command;

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

/// Regression: `--json` / `--home` used to be rejected after the
/// subcommand (non-global parent args). They must work in either position.
#[test]
fn global_flags_work_after_subcommand() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payments");
    let home = root.to_str().unwrap().to_string();

    run(bin().args(["--home", &home, "init"]));

    // Flags AFTER the subcommand:
    let out = run(bin().args([
        "order-create",
        "--checkout",
        "c1",
        "--to",
        "deadbeef",
        "--amount",
        "1.00",
        "--currency",
        "USD",
        "--json",
        "--home",
        &home,
    ]));
    let order: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(order["command"], "order_create");
    assert!(order["payment_order_id"].as_str().is_some());

    // And the short `-p` passphrase alias is accepted after the subcommand
    // (global-arg parsing; dlq-list never resolves the passphrase).
    let pw = dir.path().join("pw.txt");
    std::fs::write(&pw, "x").unwrap();
    let out = run(bin().args([
        "--home",
        &home,
        "dlq-list",
        "-p",
        pw.to_str().unwrap(),
        "--json",
    ]));
    let list: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(list.is_array(), "dlq-list --json emits the records array");
}

#[test]
fn status_dashboard_via_binary() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payments");
    let home = root.to_str().unwrap().to_string();

    // Uninitialized root → dashboard says so, human + JSON.
    let out = run(bin().args(["--home", &home, "status"]));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("NOT INITIALIZED"), "{text}");

    run(bin().args(["--home", &home, "init"]));
    run(bin().args([
        "--home",
        &home,
        "order-create",
        "--checkout",
        "c1",
        "--to",
        "deadbeef",
        "--amount",
        "3.15",
        "--currency",
        "USD",
    ]));

    let out = run(bin().args(["--home", &home, "--json", "status"]));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["initialized"], true);
    assert_eq!(report["orders"]["not_started"], 1);
    assert_eq!(report["config"]["currency"], "USD");
    assert_eq!(
        report["audit_entries"], 1,
        "order-create records an audit entry"
    );

    let out = run(bin().args(["--home", &home, "status"]));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("orders") && text.contains("1 NOT_STARTED"),
        "{text}"
    );
    assert!(text.contains("audit"), "{text}");
}

#[test]
fn completions_generate_scripts() {
    for shell in ["bash", "zsh", "fish"] {
        let out = run(bin().args(["completions", shell]));
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("order-create") && text.contains("origin-payments"),
            "{shell} completions mention the subcommand and binary:\n{}",
            &text[..text.len().min(400)]
        );
    }
}
