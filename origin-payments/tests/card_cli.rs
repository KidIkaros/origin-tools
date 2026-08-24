// SPDX-License-Identifier: Apache-2.0

//! Card rail CLI surface: `order-create --card-*` tokenization — all three
//! args or none, implies the card rail, and refuses an explicit non-card
//! rail.

use std::process::Command;

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

#[test]
fn card_order_create_sets_token_and_rail() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payments");
    let home = root.to_str().unwrap().to_string();
    run(bin().args(["--home", &home, "init"]));

    let out = run(bin().args([
        "--home",
        &home,
        "--json",
        "order-create",
        "--checkout",
        "c-card",
        "--to",
        "merchant-acct",
        "--amount",
        "19.99",
        "--currency",
        "USD",
        "--card-token",
        "tok_visa_4242",
        "--card-network",
        "VISA",
        "--card-last4",
        "4242",
    ]));
    let order: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(order["command"], "order_create");

    // The order persisted with the tokenization + the card rail implied.
    let store = PaymentStore::open(&root).unwrap();
    let id = order["payment_order_id"].as_str().unwrap();
    let saved = store.get_order(id).unwrap();
    assert_eq!(saved.card_token.as_deref(), Some("tok_visa_4242"));
    assert_eq!(saved.card_network.as_deref(), Some("VISA"));
    assert_eq!(saved.card_last4.as_deref(), Some("4242"));
    assert_eq!(saved.rail, Some(origin_payments::RailHint::Card));
}

#[test]
fn partial_card_args_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payments");
    let home = root.to_str().unwrap().to_string();
    run(bin().args(["--home", &home, "init"]));

    // Only the token — the other two must be refused.
    let partial = bin()
        .args([
            "--home",
            &home,
            "order-create",
            "--checkout",
            "c-card",
            "--to",
            "merchant-acct",
            "--amount",
            "5.00",
            "--currency",
            "USD",
            "--card-token",
            "tok_visa_4242",
        ])
        .output()
        .unwrap();
    assert!(!partial.status.success(), "partial --card-* args must fail");

    // Card args with an explicit non-card rail — refused.
    let wrong_rail = bin()
        .args([
            "--home",
            &home,
            "order-create",
            "--checkout",
            "c-card",
            "--to",
            "merchant-acct",
            "--amount",
            "5.00",
            "--currency",
            "USD",
            "--rail",
            "native",
            "--card-token",
            "tok_visa_4242",
            "--card-network",
            "VISA",
            "--card-last4",
            "4242",
        ])
        .output()
        .unwrap();
    assert!(
        !wrong_rail.status.success(),
        "--card-* with --rail native must fail"
    );
    let stderr = String::from_utf8_lossy(&wrong_rail.stderr);
    assert!(stderr.contains("--rail card"), "stderr: {stderr}");
}
