// SPDX-License-Identifier: Apache-2.0

//! P9 + P10 CLI surface: FX order creation (`order-create --fx-*`),
//! per-currency settlement export (`settlement-export`), and `order-resume`
//! returning a REQUIRES_ACTION order to the ready queue (so the next
//! executor pass settles it).

use std::process::Command;

use origin_payments::event::{OrderStatus, PaymentOrder};
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
fn fx_order_create_then_per_currency_settlement_export() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payments");
    let home = root.to_str().unwrap().to_string();
    run(bin().args(["--home", &home, "init"]));

    // An FX order: 10.00 USD settles in EUR @ 0.9.
    let out = run(bin().args([
        "--home",
        &home,
        "--json",
        "order-create",
        "--checkout",
        "c-fx",
        "--to",
        "deadbeef",
        "--amount",
        "10.00",
        "--currency",
        "USD",
        "--fx-from",
        "USD",
        "--fx-to",
        "EUR",
        "--fx-rate",
        "0.9",
    ]));
    let order: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(order["command"], "order_create");
    let order_id = order["payment_order_id"].as_str().unwrap();

    // A plain USD order for comparison.
    run(bin().args([
        "--home",
        &home,
        "order-create",
        "--checkout",
        "c-plain",
        "--to",
        "deadbeef",
        "--amount",
        "5.00",
        "--currency",
        "USD",
    ]));

    // Mark both orders settled (library-side; the executor would do this).
    let store = PaymentStore::open(&root).unwrap();
    let mut o = store.get_order(order_id).unwrap();
    o.transition(OrderStatus::Executing).unwrap();
    o.transition(OrderStatus::Success).unwrap();
    store.update_order(&o).unwrap();
    let plain = store
        .orders()
        .unwrap()
        .into_iter()
        .find(|ord| ord.checkout_id == "c-plain")
        .unwrap();
    let mut po = plain.clone();
    po.transition(OrderStatus::Executing).unwrap();
    po.transition(OrderStatus::Success).unwrap();
    store.update_order(&po).unwrap();
    drop(store);

    // Per-currency settlement export: the FX order attributes to EUR, the
    // plain order to USD.
    let out = run(bin().args([
        "--home",
        &home,
        "--json",
        "settlement-export",
        "--rail",
        "native",
        "--date",
        "2026-08-23",
    ]));
    let res: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(res["command"], "settlement_export");
    let files = res["files"].as_array().unwrap();
    let usd = files.iter().find(|f| f["currency"] == "USD").unwrap();
    let eur = files.iter().find(|f| f["currency"] == "EUR").unwrap();
    assert_eq!(usd["rows"], 1);
    assert_eq!(eur["rows"], 1);
    assert!(!eur["content_hash"].as_str().unwrap().is_empty());
}

#[test]
fn fx_order_requires_all_together_and_valid_rate() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payments");
    let home = root.to_str().unwrap().to_string();
    run(bin().args(["--home", &home, "init"]));

    // Partial FX flags → rejected.
    let out = bin()
        .args([
            "--home",
            &home,
            "--json",
            "order-create",
            "--checkout",
            "c-bad",
            "--to",
            "deadbeef",
            "--amount",
            "1.00",
            "--currency",
            "USD",
            "--fx-from",
            "USD",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "partial FX args must fail");

    // Same from/to → rejected.
    let same = bin()
        .args([
            "--home",
            &home,
            "order-create",
            "--checkout",
            "c-same",
            "--to",
            "deadbeef",
            "--amount",
            "1.00",
            "--currency",
            "USD",
            "--fx-from",
            "USD",
            "--fx-to",
            "USD",
            "--fx-rate",
            "1",
        ])
        .output()
        .unwrap();
    assert!(!same.status.success(), "from == to must fail");

    // Invalid rate → rejected.
    let bad_rate = bin()
        .args([
            "--home",
            &home,
            "order-create",
            "--checkout",
            "c-rate",
            "--to",
            "deadbeef",
            "--amount",
            "1.00",
            "--currency",
            "USD",
            "--fx-from",
            "USD",
            "--fx-to",
            "EUR",
            "--fx-rate",
            "0.1234567",
        ])
        .output()
        .unwrap();
    assert!(!bad_rate.status.success(), "rate > 6 decimals must fail");
}

#[test]
fn order_resume_returns_requires_action_to_ready_queue() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("payments");
    let home = root.to_str().unwrap().to_string();
    let store = PaymentStore::open(&root).unwrap();
    run(bin().args(["--home", &home, "init"]));

    // A REQUIRES_ACTION order (e.g. an x402 `settlement_pending` resolved).
    let mut order = PaymentOrder::new("c1", "http://127.0.0.1:1/x", "1.00", "USD");
    order.transition(OrderStatus::Executing).unwrap();
    order.transition(OrderStatus::RequiresAction).unwrap();
    store.insert_order(&order).unwrap();
    drop(store);

    // Resume → NOT_STARTED (ready queue), so the next executor pass settles.
    let out = run(bin().args([
        "--home",
        &home,
        "--json",
        "order-resume",
        &order.payment_order_id,
    ]));
    let res: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(res["command"], "order_resume");
    assert_eq!(res["status"], "NOT_STARTED");

    let store = PaymentStore::open(&root).unwrap();
    assert_eq!(
        store.get_order(&order.payment_order_id).unwrap().status,
        OrderStatus::NotStarted
    );
}
