//! Compliance scoring integration tests: prove the executor respects
//! ComplianceScorer verdicts — Reject → DLQ, Flag → audit note + proceed.

use origin_payments::compliance::RuleBasedScorer;
use origin_payments::event::PaymentOrder;
use origin_payments::{audit, executor, store::PaymentStore};
use origin_wallet::Wallet;

/// A valid 64-hex MeshId (the native rail validates this format).
const PEER_MESH_ID: &str = "e2ad0a8b3395fdc9dc84c845e058ee5be59634a51253d997e8ecd61daa6491b5";

fn tmp_store_and_wallet(dir: &tempfile::TempDir) -> (PaymentStore, std::path::PathBuf) {
    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    let mut config = store.load_config().unwrap();
    config.enabled_rails = vec!["native".to_string()];
    let _ = std::fs::remove_file(store.config_path());
    store.write_config(&config).unwrap();

    let mut wallet = Wallet::create("payer-pass").unwrap();
    wallet.derive_account(0).unwrap();
    let wallet_path = dir.path().join("payer.wallet");
    wallet.save(&wallet_path, "payer-pass").unwrap();
    (store, wallet_path)
}

/// A scorer that rejects everything >= 1.00.
fn reject_above_1() -> RuleBasedScorer {
    RuleBasedScorer {
        flag_threshold_minor: 100,
        reject_threshold_minor: 100,
        allowed_counterparties: None,
    }
}

/// A scorer that flags everything >= 5.00 but doesn't reject.
fn flag_above_5() -> RuleBasedScorer {
    RuleBasedScorer {
        flag_threshold_minor: 500,
        reject_threshold_minor: i128::MAX,
        allowed_counterparties: None,
    }
}

#[tokio::test]
async fn compliance_below_threshold_proceeds() {
    let dir = tempfile::tempdir().unwrap();
    let (store, wallet_path) = tmp_store_and_wallet(&dir);

    // Order at 0.50 — below the 1.00 reject threshold → should proceed.
    let order = PaymentOrder::new("compliance-ok", PEER_MESH_ID, "0.50", "USD");
    store.insert_order(&order).unwrap();

    let scorer = reject_above_1();
    let summary = executor::run_once(
        &store,
        &wallet_path,
        "payer-pass",
        Some("127.0.0.1:1".parse().unwrap()),
        None,
        Some(&scorer),
    )
    .await
    .unwrap();

    // Order should be retried (peer unreachable) but NOT DLQ'd by compliance.
    assert_eq!(
        summary.retried + summary.executed,
        summary.ready,
        "compliance should not reject below-threshold: {}",
        summary.note
    );
    let dlq = store.dlq_records().unwrap();
    for record in &dlq {
        assert!(
            !record.reason.contains("compliance rejected"),
            "compliance should not reject below-threshold order: {}",
            record.reason
        );
    }
}

#[tokio::test]
async fn compliance_flag_proceeds_with_audit_entry() {
    let dir = tempfile::tempdir().unwrap();
    let (store, wallet_path) = tmp_store_and_wallet(&dir);

    // Order at 6.00 — above flag threshold (5.00), below reject → proceeds.
    let order = PaymentOrder::new("compliance-flag", PEER_MESH_ID, "6.00", "USD");
    store.insert_order(&order).unwrap();

    let scorer = flag_above_5();
    let summary = executor::run_once(
        &store,
        &wallet_path,
        "payer-pass",
        Some("127.0.0.1:1".parse().unwrap()),
        None,
        Some(&scorer),
    )
    .await
    .unwrap();

    // Not DLQ'd by compliance.
    assert_eq!(
        summary.retried + summary.executed,
        summary.ready,
        "flag should not block settlement: {}",
        summary.note
    );
    // AT_ORDER_FLAGGED audit entry recorded.
    let audits = store.audit_records().unwrap();
    let flagged = audits.iter().any(|r| {
        r.entry_type == audit::AT_ORDER_FLAGGED
            && r.payload
                .get("order")
                .and_then(|v| v.as_str())
                .map(|s| s == order.payment_order_id)
                .unwrap_or(false)
    });
    assert!(
        flagged,
        "flagged order should have AT_ORDER_FLAGGED audit entry"
    );
}

#[tokio::test]
async fn compliance_no_scorer_proceeds_unrestricted() {
    let dir = tempfile::tempdir().unwrap();
    let (store, wallet_path) = tmp_store_and_wallet(&dir);

    // A large order — no scorer → proceeds without restriction.
    let order = PaymentOrder::new("compliance-none", PEER_MESH_ID, "999.00", "USD");
    store.insert_order(&order).unwrap();

    let _summary = executor::run_once(
        &store,
        &wallet_path,
        "payer-pass",
        Some("127.0.0.1:1".parse().unwrap()),
        None,
        None, // no compliance scorer
    )
    .await
    .unwrap();

    // No compliance rejection.
    let dlq = store.dlq_records().unwrap();
    for record in &dlq {
        assert!(
            !record.reason.contains("compliance rejected"),
            "no scorer means no compliance rejection"
        );
    }
}

#[tokio::test]
async fn compliance_reject_sends_to_dlq() {
    let dir = tempfile::tempdir().unwrap();
    let (store, wallet_path) = tmp_store_and_wallet(&dir);

    // Order at 5.00 — above the 1.00 reject threshold → should be DLQ'd.
    let order = PaymentOrder::new("compliance-reject", PEER_MESH_ID, "5.00", "USD");
    store.insert_order(&order).unwrap();

    let scorer = reject_above_1();
    let summary = executor::run_once(
        &store,
        &wallet_path,
        "payer-pass",
        Some("127.0.0.1:1".parse().unwrap()),
        None,
        Some(&scorer),
    )
    .await
    .unwrap();

    // Order should be DLQ'd by compliance (terminal failure).
    assert_eq!(summary.executed, 0, "rejected order should not execute");
    assert_eq!(summary.retried, 0, "rejected order should not retry");
    let dlq = store.dlq_records().unwrap();
    let compliance_dlq = dlq.iter().any(|r| {
        r.payment_order_id == order.payment_order_id && r.reason.contains("compliance rejected")
    });
    assert!(
        compliance_dlq,
        "rejected order should be in DLQ with compliance reason; note: {}",
        summary.note
    );
    // Order status is Failed.
    let failed = store.get_order(&order.payment_order_id).unwrap();
    assert_eq!(failed.status, origin_payments::event::OrderStatus::Failed);
}
