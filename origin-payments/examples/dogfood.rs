// SPDX-License-Identifier: Apache-2.0

//! Dogfood: origin-payments as a library.
//!
//! Exercises the store (init → idempotent order → journal), the MMR
//! checkpoint proof, the hash-chained audit log, deferred settlement, and
//! the compliance scorer interface — the surfaces a payments backend
//! consumer builds on.

use std::process::ExitCode;

use origin_payments::audit;
use origin_payments::compliance::{AcceptAll, ComplianceScorer, RuleBasedScorer};
use origin_payments::event::{OrderStatus, PaymentOrder};
use origin_payments::journal::{append_batch, balance, posting_hash, Account, LedgerPosting};
use origin_payments::settle::{commit_deferred_batch, DeferredBatch, DeferredItem};
use origin_payments::status;
use origin_payments::store::{DlqRecord, InsertOutcome, PaymentStore, PaymentsConfig};
use origin_payments::x402::PaymentSigner;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!(
        "origin-payments-dogfood-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn main() -> ExitCode {
    let home = tmpdir("home");
    let store = match PaymentStore::open(&home) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("open: {e}");
            return ExitCode::FAILURE;
        }
    };

    // --- init -----------------------------------------------------------
    if let Err(e) = store.write_config(&PaymentsConfig::default()) {
        eprintln!("write_config: {e}");
        return ExitCode::FAILURE;
    }
    println!(
        "init: config at {} (currency={})",
        store.config_path().display(),
        store.load_config().unwrap().currency
    );

    // --- order lifecycle (idempotent insert) ----------------------------
    let mut order = PaymentOrder::new("checkout-42", "mesh-seller", "3.15", "USD");
    match store.insert_order(&order) {
        Ok(InsertOutcome::Inserted) => println!("order: created {}", order.payment_order_id),
        Ok(InsertOutcome::Replay(_)) => {
            eprintln!("order: unexpected replay on first insert");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("insert_order: {e}");
            return ExitCode::FAILURE;
        }
    }
    match store.insert_order(&order) {
        Ok(InsertOutcome::Replay(prev)) => {
            println!(
                "order: idempotent replay detected (order {}",
                prev.payment_order_id,
            );
        }
        other => {
            eprintln!("order: expected replay, got {other:?}");
            return ExitCode::FAILURE;
        }
    }

    // status machine: NOT_STARTED → EXECUTING → SETTLED
    order.transition(OrderStatus::Executing).unwrap();
    store.update_order(&order).unwrap();
    order.transition(OrderStatus::Success).unwrap();
    store.update_order(&order).unwrap();
    println!("order: transitioned to {}", order.status);

    // --- double-entry journal (balanced batch) --------------------------
    let batch_id = append_batch(
        &store,
        &order.payment_order_id,
        "USD",
        &[(Account::Debit, "3.15"), (Account::Credit, "3.15")],
        None,
    )
    .unwrap();
    let postings: Vec<LedgerPosting> = store
        .postings()
        .unwrap()
        .into_iter()
        .filter(|p| p.batch_id == batch_id)
        .collect();
    println!(
        "journal: {} postings in batch {}; net balance {:?}",
        postings.len(),
        batch_id,
        balance(&store, None).unwrap()
    );

    // --- MMR membership proof over a checkpoint -------------------------
    let root = store.checkpoint_mmr(posting_hash(&postings[0])).unwrap();
    let mmr = store.load_mmr().unwrap();
    let proof = mmr.prove(0).unwrap();
    println!(
        "mmr: root {:02x?}…, leaf_count={}, proof valid={}",
        &root[..4],
        mmr.leaf_count(),
        mmr.verify_proof(&proof, &root)
    );

    // --- audit hash chain ------------------------------------------------
    audit::record(
        &store,
        1,
        serde_json::json!({ "event": "order_created" }),
        None,
    )
    .unwrap();
    audit::record(
        &store,
        2,
        serde_json::json!({ "event": "journal_posted" }),
        None,
    )
    .unwrap();
    println!(
        "audit: {} records, chain verified={}",
        store.audit_records().unwrap().len(),
        audit::verify(&store).unwrap()
    );

    // --- DLQ + requeue ---------------------------------------------------
    // The settled order is terminal, so the DLQ/requeue walk uses a fresh
    // order (a declined rail attempt: NOT_STARTED → FAILED → DLQ, then
    // requeued back to NOT_STARTED for a later pass).
    let dlq_order = PaymentOrder::new("checkout-dlq", "mesh-seller", "1.00", "USD");
    store.insert_order(&dlq_order).unwrap();
    let dlq_id = dlq_order.payment_order_id.clone();
    store
        .append_dlq(&DlqRecord {
            payment_order_id: dlq_id.clone(),
            reason: "simulated rail decline".to_string(),
            evidence: serde_json::json!({ "rail": "native" }),
            created_at: "now".to_string(),
        })
        .unwrap();
    let mut failed = store.get_order(&dlq_id).unwrap();
    failed.transition(OrderStatus::Failed).unwrap();
    store.update_order(&failed).unwrap();
    let mut requeued = store.get_order(&dlq_id).unwrap();
    requeued.transition(OrderStatus::NotStarted).unwrap();
    store.update_order(&requeued).unwrap();
    println!(
        "dlq: {} record(s), requeued order to {}",
        store.dlq_records().unwrap().len(),
        store.get_order(&dlq_id).unwrap().status
    );

    // --- deferred settlement batch --------------------------------------
    // A deferred commitment is a signed x402 authorization bound to a
    // resource URL; `push` refuses anything that does not verify, so we
    // build a real hybrid-signed payload from an operator identity.
    let op_home = origin_common::OriginHome::with_root(home.join("operator")).unwrap();
    let _store = origin_common::IdentityStore::create(
        &op_home,
        "dogfood-pass",
        origin_common::MemoryTier::Nano,
    )
    .unwrap();
    let keys =
        origin_payments::identity::load_operator_keys_from(&op_home, "dogfood-pass").unwrap();
    let signer = origin_payments::x402::HybridSigner::new(&keys);
    let url = "stoa://merchant/checkout-42";
    let req = origin_payments::x402::PaymentRequirements {
        accepts: vec![origin_payments::x402::PaymentOption {
            scheme: "exact".to_string(),
            network: "eip155:8453".to_string(),
            pay_to: "0xMerchant".to_string(),
            amount: "3.15".to_string(),
            max_timeout_secs: Some(300),
            payment_details: serde_json::json!({}),
        }],
    };
    let signed = signer.sign(&req, url).unwrap();
    let mut batch = DeferredBatch::new("2026-08-28").unwrap();
    let item = DeferredItem {
        payment_order_id: order.payment_order_id.clone(),
        amount: "3.15".to_string(),
        currency: "USD".to_string(),
        signed_payload: signed.clone(),
        resource_url: url.to_string(),
    };
    // Admission check: the forged/replayed-for-another-URL variant is refused.
    batch.push(item.clone()).unwrap();
    let forged = DeferredItem {
        signed_payload: signed,
        resource_url: "stoa://elsewhere/evil".to_string(),
        ..item.clone()
    };
    assert!(batch.push(forged).is_err(), "replayed commitment refused");
    assert_eq!(batch.items.len(), 1);
    // Pending queue → committed daily batch (tamper-evident manifest + MMR).
    store.append_deferred_commitment(&item).unwrap();
    let committed = commit_deferred_batch(&store, "2026-08-28").unwrap();
    println!(
        "deferred: committed batch {} with {} item(s), total {}",
        committed.batch_id,
        committed.items.len(),
        committed.total_minor
    );

    // --- compliance scoring plugin ---------------------------------------
    let accept = AcceptAll.score(&order).unwrap();
    println!("compliance: accept-all verdict {accept:?}");
    // 3.15 USD = 315 minor units; flag above 100, reject above 10000.
    let scorer = RuleBasedScorer {
        flag_threshold_minor: 100,
        reject_threshold_minor: 10_000,
        allowed_counterparties: None,
    };
    println!(
        "compliance: rule-based verdict for 3.15 USD is {:?}",
        scorer.score(&order).unwrap()
    );

    // --- status dashboard -------------------------------------------------
    let report = status::build(&store);
    println!(
        "status: {} postings, {} dlq, audit chain valid={:?}",
        report.journal_postings, report.dlq, report.audit_chain_valid
    );

    println!("payments: OK");
    ExitCode::SUCCESS
}
