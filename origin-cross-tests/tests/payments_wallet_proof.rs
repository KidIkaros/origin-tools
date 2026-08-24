// SPDX-License-Identifier: Apache-2.0

//! Cross-tool workflow: payments → wallet native rail → journal →
//! reconciliation checkpoint (MMR) → membership proof.
//!
//! Links `origin-payments` (orders, executor, double-entry journal),
//! `origin-wallet` + Stoa (the native pay rail), and `origin-proof` (MMR
//! as the tamper-evident reconcile checkpoint).

use std::time::Duration;

use origin_payments::event::{OrderStatus, PaymentOrder};
use origin_payments::executor;
use origin_payments::journal;
use origin_payments::store::PaymentStore;
use origin_proof::mmr::MmrState;
use origin_wallet::Wallet;

#[tokio::test]
async fn payments_wallet_proof_chain() {
    let dir = tempfile::tempdir().unwrap();

    // Wallet layer: payer (merchant) + payee node on the mesh.
    let payer = Wallet::create("payer-pass").unwrap();
    let wallet_path = dir.path().join("payer.wallet");
    payer.save(&wallet_path, "payer-pass").unwrap();

    let payee = Wallet::create("payee-pass").unwrap();
    let payee_keys = payee.stoa_node_keys().unwrap();
    let payee_id = *payee_keys.mesh_id();
    let (payee_mesh, payee_addr) =
        stoa::Mesh::bind(payee_keys, "127.0.0.1:0".parse().unwrap()).unwrap();

    // Payments layer: an order to the payee, settled by the executor on
    // the native rail.
    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    let order = PaymentOrder::new("x-checkout", &payee_id.to_string(), "4.20", "USD");
    store.insert_order(&order).unwrap();

    let summary = executor::run_once(&store, &wallet_path, "payer-pass", Some(payee_addr), None, None)
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

    // ...and the payee's node ingested the signed receipt via gossip.
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
    assert_eq!(payee_mesh.ledger_snapshot().await[0].amount, 420);

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
