// SPDX-License-Identifier: Apache-2.0

//! End-to-end store flow: init → order (idempotent) → journal → DLQ →
//! requeue. (Executor-on-native-rail coverage lives in `executor_native.rs`.)

use origin_payments::event::{OrderStatus, PaymentOrder};
use origin_payments::journal::{append_batch, Account};
use origin_payments::store::{DlqRecord, InsertOutcome, PaymentStore, PaymentsConfig};

#[test]
fn full_flow_init_order_journal_retry() {
    let dir = tempfile::tempdir().unwrap();
    let store = PaymentStore::open(dir.path()).unwrap();

    // init: config written exactly once
    store.write_config(&PaymentsConfig::default()).unwrap();
    assert!(store.config_path().exists());
    assert_eq!(store.load_config().unwrap().currency, "USD");

    // order create — idempotent on payment_order_id
    let order = PaymentOrder::new("checkout-1", "seller-mesh", "3.15", "USD");
    assert_eq!(store.insert_order(&order).unwrap(), InsertOutcome::Inserted);
    assert!(matches!(
        store.insert_order(&order).unwrap(),
        InsertOutcome::Replay(_)
    ));

    // journal: balanced batch + net-zero balance
    let batch = append_batch(
        &store,
        &order.payment_order_id,
        "USD",
        &[(Account::Debit, "3.15"), (Account::Credit, "3.15")],
        None,
    )
    .unwrap();
    assert!(!batch.is_empty());
    assert_eq!(store.postings().unwrap().len(), 2);
    let nets = origin_payments::journal::balance(&store, None).unwrap();
    assert_eq!(nets, vec![("USD".to_string(), 0)]);

    // terminal failure -> DLQ -> requeue (FAILED -> NOT_STARTED)
    store
        .append_dlq(&DlqRecord {
            payment_order_id: order.payment_order_id.clone(),
            reason: "rail decline".to_string(),
            evidence: serde_json::json!({ "rail": "native" }),
            created_at: "now".to_string(),
        })
        .unwrap();

    let mut failed = store.get_order(&order.payment_order_id).unwrap();
    failed.transition(OrderStatus::Failed).unwrap();
    store.update_order(&failed).unwrap();

    let mut requeued = store.get_order(&order.payment_order_id).unwrap();
    requeued.transition(OrderStatus::NotStarted).unwrap();
    store.update_order(&requeued).unwrap();

    assert_eq!(
        store.get_order(&order.payment_order_id).unwrap().status,
        OrderStatus::NotStarted
    );
    assert_eq!(store.dlq_records().unwrap().len(), 1);
    assert_eq!(
        store.dlq_record(&order.payment_order_id).unwrap().reason,
        "rail decline"
    );
}

#[test]
fn store_layout_matches_design() {
    let dir = tempfile::tempdir().unwrap();
    let store = PaymentStore::open(dir.path()).unwrap();
    // The design's file names (empty logs are created lazily on first write).
    assert!(store.config_path().ends_with("config.toml"));
    assert!(store.events_path().ends_with("payment_events.jsonl"));
    assert!(store.orders_path().ends_with("payment_orders.jsonl"));
    assert!(store.journal_path().ends_with("journal.jsonl"));
    assert!(store.retry_path().ends_with("retry_queue.jsonl"));
    assert!(store.dlq_path().ends_with("dlq.jsonl"));
}
