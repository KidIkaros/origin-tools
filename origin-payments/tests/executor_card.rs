// SPDX-License-Identifier: Apache-2.0

//! Card rail (CardAcp) through the real executor: an order with card
//! tokenization settles via a mock ACP facilitator's `POST /authorize` —
//! journal posted, CardAcp receipt recorded, no stoa wallet movement, no
//! PAN anywhere (only the token reference + last4). `settlement_pending`
//! parks in REQUIRES_ACTION; a decline goes terminal to the DLQ; an
//! unconfigured facilitator or a missing token refuses before any HTTP
//! call.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::thread;

use base64::Engine as _;
use origin_payments::event::{OrderStatus, PaymentOrder};
use origin_payments::executor::{self, ExecutorSummary};
use origin_payments::store::{PaymentStore, PaymentsConfig};
use origin_payments::RailHint;
use origin_wallet::Wallet;

/// A wallet file the executor can open (required by `run_once` even when
/// the rail doesn't touch the wallet).
fn wallet_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let wallet = Wallet::create("payer-pass").unwrap();
    let path = dir.path().join("payer.wallet");
    wallet.save(&path, "payer-pass").unwrap();
    path
}

/// Mock ACP facilitator: answers `POST /authorize` with `response` for
/// exactly `connections` requests (so `join` returns), capturing the
/// request bodies for the PAN-absence check.
fn mock_acp(
    connections: usize,
    response: impl Fn() -> Vec<u8> + Send + 'static,
) -> (
    String,
    thread::JoinHandle<()>,
    std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let cap = captured.clone();
    let handle = thread::spawn(move || {
        for _ in 0..connections {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            cap.lock().unwrap().extend_from_slice(&buf);
            let body = response();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), handle, captured)
}

fn enable_card(store: &PaymentStore) {
    let mut config = PaymentsConfig::default();
    config.enabled_rails = vec!["native".to_string(), "card".to_string()];
    store.write_config(&config).unwrap();
}

fn configure_card_facilitator(store: &PaymentStore, url: &str) {
    origin_payments::vault::store_secret(store.root(), "card", b"sk_test_card").unwrap();
    origin_payments::vault::store_facilitator_url(store.root(), "card", url).unwrap();
}

fn success_response() -> Vec<u8> {
    let auth = base64::engine::general_purpose::STANDARD.encode(b"acp-auth-evidence");
    format!(r#"{{"status":"success","auth":"{auth}"}}"#).into_bytes()
}

fn pending_response() -> Vec<u8> {
    br#"{"status":"settlement_pending","transaction":"tx-acp-1"}"#.to_vec()
}

fn declined_response() -> Vec<u8> {
    br#"{"status":"declined","error":"insufficient funds"}"#.to_vec()
}

fn card_order() -> PaymentOrder {
    let mut order = PaymentOrder::new("checkout-card", "merchant-acct", "19.99", "USD");
    order.rail = Some(RailHint::Card);
    order.card_token = Some("tok_visa_4242".to_string());
    order.card_network = Some("VISA".to_string());
    order.card_last4 = Some("4242".to_string());
    order
}

async fn run_pass(store: &PaymentStore, wallet_path: &Path) -> ExecutorSummary {
    executor::run_once(
        store,
        wallet_path,
        "payer-pass",
        Some("127.0.0.1:1".parse().unwrap()),
        None,
        None,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn executor_settles_order_over_card_rail() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = wallet_file(&dir);
    let (url, handle, captured) = mock_acp(1, success_response);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    enable_card(&store);
    configure_card_facilitator(&store, &url);
    let order = card_order();
    store.insert_order(&order).unwrap();

    let summary = run_pass(&store, &wallet_path).await;
    assert_eq!(summary.executed, 1);

    let settled = store.get_order(&order.payment_order_id).unwrap();
    assert_eq!(settled.status, OrderStatus::Success);
    assert!(settled.ledger_updated, "journal batch posted");
    assert!(!settled.wallet_updated, "no stoa wallet movement on card");
    match &settled.receipt {
        Some(origin_payments::rails::RailReceipt::CardAcp {
            network,
            last4,
            auth,
        }) => {
            assert_eq!(network, "VISA");
            assert_eq!(last4, "4242");
            assert_eq!(auth, b"acp-auth-evidence");
        }
        other => panic!("expected CardAcp receipt, got {other:?}"),
    }
    // Double-entry journal balanced.
    let nets = origin_payments::journal::balance(&store, None).unwrap();
    assert_eq!(nets, vec![("USD".to_string(), 0)]);

    // The wire request carried the token reference + last4 — and never
    // a PAN (no 16-digit sequence, no card data beyond the display hint).
    let sent = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(sent.contains("tok_visa_4242"), "token reference sent");
    assert!(sent.contains("\"last4\":\"4242\""));
    assert!(
        sent.contains("x-api-key: sk_test_card"),
        "API-key authenticated"
    );

    handle.join().unwrap();
}

#[tokio::test]
async fn executor_parks_card_settlement_pending_in_requires_action() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = wallet_file(&dir);
    let (url, handle, _) = mock_acp(1, pending_response);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    enable_card(&store);
    configure_card_facilitator(&store, &url);
    let order = card_order();
    store.insert_order(&order).unwrap();

    let summary = run_pass(&store, &wallet_path).await;
    assert_eq!(summary.executed, 0, "nothing settles while pending");

    let order = store.get_order(&order.payment_order_id).unwrap();
    assert_eq!(order.status, OrderStatus::RequiresAction);
    // Nothing journaled yet (exactly-once holds).
    assert_eq!(store.postings().unwrap().len(), 0);
    // The tx reference is the reconciliation evidence in the notification.
    let notes = store.notifications().unwrap();
    assert!(notes.iter().any(|n| n.event.contains("settlement_pending")));

    handle.join().unwrap();
}

#[tokio::test]
async fn executor_dlqs_declined_card_authorization() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = wallet_file(&dir);
    let (url, handle, _) = mock_acp(1, declined_response);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    enable_card(&store);
    configure_card_facilitator(&store, &url);
    let order = card_order();
    store.insert_order(&order).unwrap();

    let summary = run_pass(&store, &wallet_path).await;
    assert_eq!(summary.executed, 0);
    assert_eq!(summary.retried, 0, "a PSP decline is terminal, not retried");

    let failed = store.get_order(&order.payment_order_id).unwrap();
    assert_eq!(failed.status, OrderStatus::Failed);
    let dlq = store.dlq_records().unwrap();
    assert_eq!(dlq.len(), 1);
    assert!(dlq[0].reason.contains("declined"));

    handle.join().unwrap();
}

#[tokio::test]
async fn executor_refuses_card_without_facilitator_config() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = wallet_file(&dir);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    enable_card(&store);
    // No vault config for the card rail.
    let order = card_order();
    store.insert_order(&order).unwrap();

    let summary = run_pass(&store, &wallet_path).await;
    assert_eq!(summary.executed, 0);

    let failed = store.get_order(&order.payment_order_id).unwrap();
    assert_eq!(failed.status, OrderStatus::Failed);
    let dlq = store.dlq_records().unwrap();
    assert!(
        dlq[0].reason.contains("psp-configure card"),
        "actionable hint"
    );
}

#[tokio::test]
async fn executor_refuses_card_order_without_token() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = wallet_file(&dir);
    let (url, handle, _) = mock_acp(0, success_response);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    enable_card(&store);
    configure_card_facilitator(&store, &url);
    // Card rail hint but no tokenization — refused before any HTTP call.
    let mut order = PaymentOrder::new("checkout-notoken", "merchant-acct", "5.00", "USD");
    order.rail = Some(RailHint::Card);
    store.insert_order(&order).unwrap();

    let summary = run_pass(&store, &wallet_path).await;
    assert_eq!(summary.executed, 0);
    let failed = store.get_order(&order.payment_order_id).unwrap();
    assert_eq!(failed.status, OrderStatus::Failed);
    let dlq = store.dlq_records().unwrap();
    assert!(dlq[0].reason.contains("--card-token"), "actionable hint");

    handle.join().unwrap();
}
