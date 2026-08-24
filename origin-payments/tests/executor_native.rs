// SPDX-License-Identifier: Apache-2.0

//! P3: the executor settles NOT_STARTED orders over the native rail —
//! real loopback Stoa meshes via `origin-wallet::network::pay_native`
//! (mirrors the wallet's own integration tests).

use std::time::Duration;

use origin_payments::event::{OrderStatus, PaymentOrder};
use origin_payments::executor;
use origin_payments::journal;
use origin_payments::store::PaymentStore;
use origin_wallet::Wallet;

/// A payer wallet file + a payee node bound on loopback.
fn payer_and_payee(
    dir: &tempfile::TempDir,
) -> (
    std::path::PathBuf,
    origin_wallet::MeshId,
    origin_wallet::Mesh,
    std::net::SocketAddr,
) {
    let payer = Wallet::create("payer-pass").unwrap();
    let wallet_path = dir.path().join("payer.wallet");
    payer.save(&wallet_path, "payer-pass").unwrap();

    let payee = Wallet::create("payee-pass").unwrap();
    let payee_keys = payee.stoa_node_keys().unwrap();
    let payee_id = *payee_keys.mesh_id();
    let (payee_mesh, payee_addr) =
        origin_wallet::Mesh::bind(payee_keys, "127.0.0.1:0".parse().unwrap()).unwrap();
    (wallet_path, payee_id, payee_mesh, payee_addr)
}

#[tokio::test]
async fn executor_settles_order_over_native_rail() {
    let dir = tempfile::tempdir().unwrap();
    let (wallet_path, payee_id, payee_mesh, payee_addr) = payer_and_payee(&dir);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    let order = PaymentOrder::new("checkout-1", &payee_id.to_string(), "7.77", "USD");
    store.insert_order(&order).unwrap();

    let summary = executor::run_once(
        &store,
        &wallet_path,
        "payer-pass",
        Some(payee_addr),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(summary.ready, 1);
    assert_eq!(summary.executed, 1);

    let settled = store.get_order(&order.payment_order_id).unwrap();
    assert_eq!(settled.status, OrderStatus::Success);
    assert!(settled.ledger_updated, "journal batch posted");
    assert!(settled.wallet_updated, "wallet balance updated");
    assert!(settled.receipt.is_some(), "native rail receipt recorded");
    assert_eq!(settled.attempts, 1);
    assert!(
        settled.executing_since.is_some(),
        "executing_since set before the rail call"
    );

    // Double-entry journal posted and balanced.
    let nets = journal::balance(&store, None).unwrap();
    assert_eq!(nets, vec![("USD".to_string(), 0)]);

    // The payee's node ingests the signed receipt via gossip.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if !payee_mesh.ledger_snapshot().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("payee never ingested the receipt");
    assert_eq!(payee_mesh.ledger_snapshot().await[0].amount, 777);
}

#[tokio::test]
async fn executor_dlqs_terminal_failures() {
    let dir = tempfile::tempdir().unwrap();
    let (wallet_path, payee_id, _payee_mesh, _payee_addr) = payer_and_payee(&dir);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    // A terminal (non-retryable) failure: an unparseable amount is refused
    // before any rail call → FAILED + DLQ directly.
    let mut order = PaymentOrder::new("checkout-2", &payee_id.to_string(), "not-an-amount", "USD");
    store.insert_order(&order).unwrap();

    let summary = executor::run_once(
        &store,
        &wallet_path,
        "payer-pass",
        Some("127.0.0.1:1".parse().unwrap()),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(summary.executed, 0);
    assert_eq!(summary.retried, 0, "terminal failures are not retried");

    let failed = store.get_order(&order.payment_order_id).unwrap();
    assert_eq!(failed.status, OrderStatus::Failed);
    let dlq = store.dlq_records().unwrap();
    assert_eq!(dlq.len(), 1);
    assert_eq!(dlq[0].payment_order_id, order.payment_order_id);
    assert!(!dlq[0].reason.is_empty());
}

#[tokio::test]
async fn executor_requeues_and_settles_after_retry() {
    let dir = tempfile::tempdir().unwrap();
    let (wallet_path, payee_id, _payee_mesh, payee_addr) = payer_and_payee(&dir);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    let order = PaymentOrder::new("checkout-3", &payee_id.to_string(), "2.50", "USD");
    store.insert_order(&order).unwrap();

    // First pass fails (unreachable) → FAILED + DLQ.
    let summary = executor::run_once(
        &store,
        &wallet_path,
        "payer-pass",
        Some("127.0.0.1:1".parse().unwrap()),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(summary.executed, 0);
    assert_eq!(
        summary.retried, 1,
        "transient failure schedules a backoff retry"
    );
    assert_eq!(store.retry_jobs().unwrap().len(), 1);
    assert_eq!(
        store.get_order(&order.payment_order_id).unwrap().status,
        OrderStatus::Failed
    );

    // Requeue (FAILED -> NOT_STARTED) and settle for real.
    let mut requeued = store.get_order(&order.payment_order_id).unwrap();
    requeued.transition(OrderStatus::NotStarted).unwrap();
    store.update_order(&requeued).unwrap();

    let summary = executor::run_once(
        &store,
        &wallet_path,
        "payer-pass",
        Some(payee_addr),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(summary.executed, 1);
    assert_eq!(
        store.get_order(&order.payment_order_id).unwrap().status,
        OrderStatus::Success
    );
    // Exactly-once: still exactly one journal batch.
    assert_eq!(store.postings().unwrap().len(), 2);
}

/// The dogfood credit finding: the mesh credit is cumulative (`remaining =
/// limit − sent`), so without a standing line the *second* order in a pass
/// re-opens a fresh channel whose limit is already exhausted → "payment
/// exceeds credit limit".
#[tokio::test]
async fn executor_second_order_exceeds_per_order_credit() {
    let dir = tempfile::tempdir().unwrap();
    let (wallet_path, payee_id, _payee_mesh, payee_addr) = payer_and_payee(&dir);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    let a = PaymentOrder::new("credit-a", &payee_id.to_string(), "7.77", "USD");
    let b = PaymentOrder::new("credit-b", &payee_id.to_string(), "10.00", "USD");
    store.insert_order(&a).unwrap();
    store.insert_order(&b).unwrap();

    // No standing credit: exactly one order settles, the other is refused
    // on the cumulative credit line and scheduled for a backoff retry.
    let summary = executor::run_once(
        &store,
        &wallet_path,
        "payer-pass",
        Some(payee_addr),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        summary.executed, 1,
        "only one order fits the per-order credit"
    );
    assert_eq!(summary.retried, 1, "credit refusal schedules a retry");

    let statuses: Vec<OrderStatus> = [&a, &b]
        .iter()
        .map(|o| store.get_order(&o.payment_order_id).unwrap().status)
        .collect();
    assert!(statuses.contains(&OrderStatus::Success));
    assert!(statuses.contains(&OrderStatus::Failed));
}

/// The fix: a standing credit line (`--peer-credit`) pre-funds one channel
/// so both orders settle against a single `ENTRY_OPEN` limit.
#[tokio::test]
async fn executor_standing_credit_settles_multiple_orders() {
    let dir = tempfile::tempdir().unwrap();
    let (wallet_path, payee_id, payee_mesh, payee_addr) = payer_and_payee(&dir);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    let a = PaymentOrder::new("credit-c", &payee_id.to_string(), "7.77", "USD");
    let b = PaymentOrder::new("credit-d", &payee_id.to_string(), "10.00", "USD");
    let a_id = a.payment_order_id.clone();
    let b_id = b.payment_order_id.clone();
    store.insert_order(&a).unwrap();
    store.insert_order(&b).unwrap();

    // Standing credit of 20.00 covers 17.77 of payments.
    let summary = executor::run_once(
        &store,
        &wallet_path,
        "payer-pass",
        Some(payee_addr),
        Some(2000),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        summary.executed, 2,
        "both orders settle against the standing credit line"
    );
    assert_eq!(summary.retried, 0);
    assert_eq!(store.get_order(&a_id).unwrap().status, OrderStatus::Success);
    assert_eq!(store.get_order(&b_id).unwrap().status, OrderStatus::Success);

    // Double-entry journal balanced across both batches.
    let nets = journal::balance(&store, None).unwrap();
    assert_eq!(nets, vec![("USD".to_string(), 0)]);

    // The payee ingests both signed receipts via gossip.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if payee_mesh.ledger_snapshot().await.len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("payee never ingested both receipts");
}
