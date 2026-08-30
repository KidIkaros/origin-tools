// SPDX-License-Identifier: Apache-2.0

//! Cross-tool workflow: payments → wallet native rail (seam) → journal →
//! reconciliation checkpoint (MMR) → membership proof.
//!
//! Links `origin-payments` (orders, executor, double-entry journal),
//! `origin-wallet` (the native rail seam + offline default), and
//! `origin-proof` (MMR as the tamper-evident reconcile checkpoint).
//! The mesh is owned by the external **stoa** project (which *uses* these
//! foundational crates), so this chain settles offline through the seam.

use origin_payments::event::{OrderStatus, PaymentOrder};
use origin_payments::executor;
use origin_payments::journal;
use origin_payments::store::PaymentStore;
use origin_proof::mmr::MmrState;
use origin_wallet::{LocalNativeRail, Wallet};

#[tokio::test]
async fn payments_wallet_proof_chain() {
    let dir = tempfile::tempdir().unwrap();

    // Wallet layer: payer (merchant) wallet; pre-fund account 0 so the
    // offline native rail can debit it. The payee is just an id on the
    // order (no counterparty node is required offline).
    let payer = Wallet::create("payer-pass").unwrap();
    let wallet_path = dir.path().join("payer.wallet");
    payer.save(&wallet_path, "payer-pass").unwrap();
    let mut payer = Wallet::open(&wallet_path, "payer-pass").unwrap();
    payer.derive_account(0).unwrap();
    payer.update_balance(0, 10_000_000).unwrap();
    payer.save(&wallet_path, "payer-pass").unwrap();

    let payee_id = hex::encode([0x5A; 32]);

    // Payments layer: an order to the payee, settled by the executor over
    // the native rail seam (offline default).
    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    let order = PaymentOrder::new("x-checkout", &payee_id, "4.20", "USD");
    store.insert_order(&order).unwrap();

    let summary = executor::run_once(&store, &wallet_path, "payer-pass", &LocalNativeRail, None)
        .await
        .expect("executor run");
    assert_eq!(summary.executed, 1);
    assert_eq!(
        store.get_order(&order.payment_order_id).unwrap().status,
        OrderStatus::Success
    );

    // The double-entry journal is balanced...
    let nets = journal::balance(&store, None).unwrap();
    assert_eq!(nets, vec![("USD".to_string(), 0)]);
    assert_eq!(store.postings().unwrap().len(), 2, "exactly one batch");

    // ...and the payer wallet was debited + recorded an MMR leaf.
    let payer = Wallet::open(&wallet_path, "payer-pass").unwrap();
    assert_eq!(payer.get_balance(0).unwrap(), 10_000_000 - 420);
    assert_eq!(payer.transaction_count(), 1);

    // Proof layer: the reconcile checkpoint = journal head hashed into an
    // MMR; the membership proof verifies against the root.
    let mut mmr = MmrState::new();
    let journal_head = store.journal_head().unwrap();
    mmr.append_hash(journal_head);
    let root = mmr.root();
    let proof = mmr.prove(0).expect("proof for the only leaf");
    assert!(
        mmr.verify_proof(&proof, &root),
        "reconcile checkpoint must be provable in the MMR"
    );

    // A wrong root fails verification.
    let wrong_root = [0x42u8; 32];
    assert!(!mmr.verify_proof(&proof, &wrong_root));
}
