// SPDX-License-Identifier: Apache-2.0

//! P3: the executor settles NOT_STARTED orders over the native rail via
//! the wallet's **rail seam** ([`origin_wallet::NativeRail`]). The seam is
//! backed today by the offline [`origin_wallet::LocalNativeRail`] (the
//! external **stoa** project is expected to implement the trait for the
//! real mesh rail later), so these tests exercise settlement without a
//! peer address or a live node.

use origin_payments::event::{OrderStatus, PaymentOrder};
use origin_payments::executor;
use origin_payments::journal;
use origin_payments::store::PaymentStore;
use origin_wallet::{LocalNativeRail, Wallet};

/// A funded payer wallet on disk + a deterministic payee node id. The
/// payee id is the "to" on a native order (a `MeshId`-shaped hex string);
/// no counterparty node is required to settle offline.
fn payer_and_payee(dir: &tempfile::TempDir, funding: u64) -> (std::path::PathBuf, String) {
    let payer = Wallet::create("payer-pass").unwrap();
    let wallet_path = dir.path().join("payer.wallet");
    payer.save(&wallet_path, "payer-pass").unwrap();

    // Open and pre-fund account 0 so the offline rail can debit it.
    let mut payer = Wallet::open(&wallet_path, "payer-pass").unwrap();
    payer.derive_account(0).unwrap();
    payer.update_balance(0, funding).unwrap();
    payer.save(&wallet_path, "payer-pass").unwrap();

    (wallet_path, hex::encode([0x5A; 32]))
}

#[tokio::test]
async fn executor_settles_order_over_native_rail() {
    let dir = tempfile::tempdir().unwrap();
    let (wallet_path, payee_id) = payer_and_payee(&dir, 10_000_000);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    let order = PaymentOrder::new("checkout-1", &payee_id, "7.77", "USD");
    store.insert_order(&order).unwrap();

    let summary = executor::run_once(&store, &wallet_path, "payer-pass", &LocalNativeRail, None)
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

    // The payer wallet was debited by the offline rail.
    let wallet = Wallet::open(&wallet_path, "payer-pass").unwrap();
    assert_eq!(wallet.get_balance(0).unwrap(), 10_000_000 - 777);
    assert_eq!(wallet.transaction_count(), 1, "one MMR leaf recorded");

    // Double-entry journal posted and balanced.
    let nets = journal::balance(&store, None).unwrap();
    assert_eq!(nets, vec![("USD".to_string(), 0)]);
}

#[tokio::test]
async fn executor_dlqs_terminal_failures() {
    let dir = tempfile::tempdir().unwrap();
    let (wallet_path, payee_id) = payer_and_payee(&dir, 10_000_000);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    // A terminal (non-retryable) failure: an unparseable amount is refused
    // before any rail call → FAILED + DLQ directly.
    let order = PaymentOrder::new("checkout-2", &payee_id, "not-an-amount", "USD");
    store.insert_order(&order).unwrap();

    let summary = executor::run_once(&store, &wallet_path, "payer-pass", &LocalNativeRail, None)
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
    // Start UNFUNDED so the first pass hits insufficient funds (retryable),
    // then fund and reconcile on the second pass.
    let (wallet_path, payee_id) = payer_and_payee(&dir, 0);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    let order = PaymentOrder::new("checkout-3", &payee_id, "2.50", "USD");
    store.insert_order(&order).unwrap();

    // First pass fails (insufficient funds → retryable) → FAILED + backoff.
    let summary = executor::run_once(&store, &wallet_path, "payer-pass", &LocalNativeRail, None)
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

    // Fund the wallet, requeue (FAILED -> NOT_STARTED) and settle for real.
    let mut wallet = Wallet::open(&wallet_path, "payer-pass").unwrap();
    wallet.update_balance(0, 10_000_000).unwrap();
    wallet.save(&wallet_path, "payer-pass").unwrap();
    let mut requeued = store.get_order(&order.payment_order_id).unwrap();
    requeued.transition(OrderStatus::NotStarted).unwrap();
    store.update_order(&requeued).unwrap();

    let summary = executor::run_once(&store, &wallet_path, "payer-pass", &LocalNativeRail, None)
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

/// With the offline rail there is no cumulative mesh credit line (each
/// payment debits the wallet independently), so multiple orders in one
/// pass all settle — the mesh credit-cap finding no longer applies.
#[tokio::test]
async fn executor_settles_multiple_orders_offline() {
    let dir = tempfile::tempdir().unwrap();
    let (wallet_path, payee_id) = payer_and_payee(&dir, 10_000_000);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    let a = PaymentOrder::new("credit-a", &payee_id, "7.77", "USD");
    let b = PaymentOrder::new("credit-b", &payee_id, "10.00", "USD");
    let a_id = a.payment_order_id.clone();
    let b_id = b.payment_order_id.clone();
    store.insert_order(&a).unwrap();
    store.insert_order(&b).unwrap();

    let summary = executor::run_once(&store, &wallet_path, "payer-pass", &LocalNativeRail, None)
        .await
        .unwrap();
    assert_eq!(summary.executed, 2, "both orders settle offline");
    assert_eq!(summary.retried, 0);
    assert_eq!(store.get_order(&a_id).unwrap().status, OrderStatus::Success);
    assert_eq!(store.get_order(&b_id).unwrap().status, OrderStatus::Success);

    // Double-entry journal balanced across both batches.
    let nets = journal::balance(&store, None).unwrap();
    assert_eq!(nets, vec![("USD".to_string(), 0)]);

    // The payer wallet was debited for both.
    let wallet = Wallet::open(&wallet_path, "payer-pass").unwrap();
    assert_eq!(wallet.get_balance(0).unwrap(), 10_000_000 - 777 - 1000);
}
