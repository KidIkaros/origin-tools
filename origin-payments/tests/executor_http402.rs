// SPDX-License-Identifier: Apache-2.0

//! x402 rail through the real executor: an order with `rail: http402`
//! runs the x402 handshake against a mock HTTP server, posts the journal
//! batch, and settles — or parks in REQUIRES_ACTION on
//! `settlement_pending` (the spec's non-terminal state).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;

use base64::Engine as _;
use origin_common::{IdentityStore, MemoryTier, OriginHome};
use origin_payments::event::{OrderStatus, PaymentOrder};
use origin_payments::executor::{self, ExecutorSummary};
use origin_payments::store::{PaymentStore, PaymentsConfig};
use origin_payments::RailHint;
use origin_wallet::Wallet;

/// The shared test identity: the executor's `run_once` loads operator
/// keys from `$ORIGIN_HOME` (via `OriginHome::load`), so the tests point
/// `ORIGIN_HOME` at one temp home created here, once. Created once per
/// test binary; every test sets the same value, so parallel tests never
/// race the env var.
fn test_identity_home() -> &'static std::path::Path {
    static HOME: OnceLock<std::path::PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = OriginHome::with_root(dir.path().join("home")).expect("origin home");
        IdentityStore::create(&home, "payer-pass", MemoryTier::Nano).expect("identity");
        // `tempdir` deletes on drop — leak it so the path stays live.
        std::mem::forget(dir);
        home.root().to_path_buf()
    })
}

/// A wallet file the executor can open (required by `run_once` even when
/// the rail doesn't touch the wallet).
fn wallet_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let wallet = Wallet::create("payer-pass").unwrap();
    let path = dir.path().join("payer.wallet");
    wallet.save(&path, "payer-pass").unwrap();
    path
}

/// Mock x402 endpoint: `settle` decides the PAYMENT-RESPONSE (or a 402
/// re-rejection) for the signed retry. When `verify_sig` is set, the
/// endpoint **verifies the PAYMENT-SIGNATURE payload against the resource
/// URL** before settling — an invalid hybrid signature is rejected with a
/// re-402 (exactly what a real facilitator does). Serves exactly
/// `connections` requests so `join` returns.
fn mock_x402_endpoint(
    connections: usize,
    verify_sig: bool,
    settle: impl Fn() -> Vec<u8> + Send + 'static,
) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let resource_url = format!("http://{addr}");
    let handle = thread::spawn(move || {
        for stream in listener.incoming().take(connections) {
            let Ok(mut stream) = stream else { break };
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
            let head = String::from_utf8_lossy(&buf);
            let mut headers = HashMap::new();
            let mut request_path = "/";
            for (i, line) in head.lines().enumerate() {
                if i == 0 {
                    // Request line: "GET /paid HTTP/1.1" — the resource
                    // URL the client signed is host + this path.
                    if let Some(path) = line.split_whitespace().nth(1) {
                        request_path = path;
                    }
                } else if let Some((k, v)) = line.split_once(':') {
                    headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                }
            }
            // Reconstruct the exact resource URL the client signed
            // (Host header, or the bound address as a fallback).
            let host = headers
                .get("host")
                .cloned()
                .unwrap_or_else(|| resource_url.trim_start_matches("http://").to_string());
            let signed_url = format!("http://{host}{request_path}");
            let response = if headers.contains_key("payment-signature") {
                if verify_sig {
                    // Real facilitator behavior: verify the signed
                    // payload (offline, against the embedded keys).
                    let raw = headers.get("payment-signature").unwrap();
                    let payload = base64::engine::general_purpose::STANDARD
                        .decode(raw.trim())
                        .unwrap();
                    match origin_payments::x402::verify_payment_payload(&payload, &signed_url) {
                        Ok(true) => settle(),
                        _ => reject_response(),
                    }
                } else {
                    settle()
                }
            } else {
                let requirements = base64::engine::general_purpose::STANDARD.encode(
                    br#"{"accepts":[{"scheme":"exact","network":"base","payTo":"0xMerchant","amount":"100","maxTimeoutSeconds":300}]}"#,
                );
                format!(
                    "HTTP/1.1 402 Payment Required\r\nContent-Length: 0\r\npayment-required: {requirements}\r\n\r\n"
                )
                .into_bytes()
            };
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        }
    });
    (addr, handle)
}

fn enable_http402(store: &PaymentStore) {
    let mut config = PaymentsConfig::default();
    config.enabled_rails = vec!["native".to_string(), "http402".to_string()];
    store.write_config(&config).unwrap();
}

fn success_response() -> Vec<u8> {
    let receipt = base64::engine::general_purpose::STANDARD.encode(br#"{"status":"success"}"#);
    format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\npayment-response: {receipt}\r\n\r\n")
        .into_bytes()
}

fn pending_response(tx: &str) -> Vec<u8> {
    let body = format!(r#"{{"status":"settlement_pending","transaction":"{tx}"}}"#);
    let receipt = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());
    format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\npayment-response: {receipt}\r\n\r\n")
        .into_bytes()
}

fn reject_response() -> Vec<u8> {
    b"HTTP/1.1 402 Payment Required\r\nContent-Length: 0\r\n\r\n".to_vec()
}

async fn run_pass(store: &PaymentStore, wallet_path: &Path) -> ExecutorSummary {
    // Point the executor at the shared test identity so the x402 rail
    // hybrid-signs its payment authorizations.
    std::env::set_var("ORIGIN_HOME", test_identity_home());
    executor::run_once(
        store,
        wallet_path,
        "payer-pass",
        &origin_wallet::LocalNativeRail,
        None,
    )
    .await
    .unwrap()
}

/// A mock x402 **facilitator**: answers `POST /verify` with `{ok:true}`
/// and `POST /settle` with a success settlement body — the verify/settle
/// split the executor switches to whenever a facilitator is configured.
/// Serves exactly `connections` POSTs so `join` returns.
fn mock_facilitator(
    connections: usize,
) -> (
    SocketAddr,
    Arc<std::sync::Mutex<Vec<String>>>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(std::sync::Mutex::new(Vec::new()));
    let hits_clone = hits.clone();
    let handle = thread::spawn(move || {
        for stream in listener.incoming().take(connections) {
            let Ok(mut stream) = stream else { break };
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
            let head = String::from_utf8_lossy(&buf);
            let path = head
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();
            let key = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("x-api-key:"))
                .map(|l| {
                    l.split_once(':')
                        .map(|(_, v)| v.trim())
                        .unwrap_or("")
                        .to_string()
                });
            hits_clone
                .lock()
                .unwrap()
                .push(format!("{path} key={}", key.as_deref().unwrap_or("none")));
            let body = if path.ends_with("/settle") {
                br#"{"status":"success"}"#.to_vec()
            } else {
                br#"{"ok":true}"#.to_vec()
            };
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            let mut out = resp.into_bytes();
            out.extend_from_slice(&body);
            let _ = stream.write_all(&out);
            let _ = stream.flush();
        }
    });
    (addr, hits, handle)
}

#[tokio::test]
async fn executor_settles_via_facilitator_verify_settle_split() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = wallet_file(&dir);

    // The resource endpoint answers one 402 with payment requirements
    // (the facilitator handles the signed settle — the direct path never
    // runs). A facilitator with 2 expected POSTs: /verify then /settle.
    let (paid_addr, paid_handle) = mock_x402_endpoint(1, false, success_response);
    let (fac_addr, hits, fac_handle) = mock_facilitator(2);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    enable_http402(&store);
    // Wire the facilitator into the vault (http402.rails = url, secret = key).
    origin_payments::vault::store_facilitator_url(
        store.root(),
        "http402",
        &format!("http://{fac_addr}"),
    )
    .unwrap();
    origin_payments::vault::store_secret(store.root(), "http402", b"fac-key-42").unwrap();

    // The mock resource's PAYMENT-REQUIRED declares amount 100 (minor
    // units); verify_signed_payload enforces that the signed authorization
    // equals the order's amount, so the order amount must match 100.
    let mut order = PaymentOrder::new("co-fac", &format!("http://{paid_addr}/paid"), "100", "USD");
    order.rail = Some(RailHint::Http402);
    store.insert_order(&order).unwrap();

    let summary = run_pass(&store, &wallet_path).await;
    assert_eq!(summary.executed, 1, "settled through the facilitator");
    assert_eq!(
        store.get_order(&order.payment_order_id).unwrap().status,
        OrderStatus::Success
    );
    // Exactly one journal batch (exactly-once holds).
    assert_eq!(store.postings().unwrap().len(), 2);

    // The split really happened: /verify then /settle, both authenticated.
    let hits = hits.lock().unwrap();
    assert_eq!(hits.len(), 2, "verify + settle");
    assert!(hits[0].starts_with("/verify") && hits[0].contains("key=fac-key-42"));
    assert!(hits[1].starts_with("/settle") && hits[1].contains("key=fac-key-42"));
    drop(hits);

    fac_handle.join().unwrap();
    paid_handle.join().unwrap();
}

#[tokio::test]
async fn executor_requeues_when_facilitator_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = wallet_file(&dir);
    let (paid_addr, paid_handle) = mock_x402_endpoint(1, false, success_response);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    enable_http402(&store);
    // Configure a facilitator URL nobody is listening on.
    origin_payments::vault::store_facilitator_url(store.root(), "http402", "http://127.0.0.1:1")
        .unwrap();
    origin_payments::vault::store_secret(store.root(), "http402", b"k").unwrap();

    let mut order = PaymentOrder::new("co-fac2", &format!("http://{paid_addr}/paid"), "100", "USD");
    order.rail = Some(RailHint::Http402);
    store.insert_order(&order).unwrap();

    // verify/get happens before the facilitator call, so the order is
    // retried (Retryable) — not DLQ'd — on an unreachable facilitator.
    let summary = run_pass(&store, &wallet_path).await;
    assert_eq!(summary.executed, 0);
    assert_eq!(summary.retried, 1, "unreachable facilitator is retryable");
    assert_eq!(
        store.get_order(&order.payment_order_id).unwrap().status,
        OrderStatus::Failed
    );
    assert!(
        store.dlq_records().unwrap().is_empty(),
        "not a terminal DLQ"
    );

    paid_handle.join().unwrap();
}

#[tokio::test]
async fn executor_settles_order_over_x402_rail() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = wallet_file(&dir);
    let (addr, handle) = mock_x402_endpoint(2, true, success_response);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    enable_http402(&store);
    let mut order = PaymentOrder::new("checkout-1", &format!("http://{addr}/paid"), "1.00", "USD");
    order.rail = Some(RailHint::Http402);
    store.insert_order(&order).unwrap();

    let summary = run_pass(&store, &wallet_path).await;
    assert_eq!(summary.executed, 1);

    let settled = store.get_order(&order.payment_order_id).unwrap();
    assert_eq!(settled.status, OrderStatus::Success);
    assert!(settled.ledger_updated, "journal batch posted");
    assert!(!settled.wallet_updated, "no stoa wallet movement on x402");
    match &settled.receipt {
        Some(origin_payments::rails::RailReceipt::Http402 { receipt }) => {
            assert_eq!(receipt, br#"{"status":"success"}"#)
        }
        other => panic!("expected Http402 receipt, got {other:?}"),
    }
    // Double-entry journal balanced.
    let nets = origin_payments::journal::balance(&store, None).unwrap();
    assert_eq!(nets, vec![("USD".to_string(), 0)]);

    handle.join().unwrap();
}

#[tokio::test]
async fn executor_parks_settlement_pending_in_requires_action() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = wallet_file(&dir);
    let (addr, handle) = mock_x402_endpoint(2, true, || pending_response("0xdeadbeef"));

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    enable_http402(&store);
    let mut order = PaymentOrder::new("checkout-2", &format!("http://{addr}/slow"), "2.50", "USD");
    order.rail = Some(RailHint::Http402);
    store.insert_order(&order).unwrap();

    let summary = run_pass(&store, &wallet_path).await;
    assert_eq!(summary.executed, 0, "nothing settles while pending");

    let order = store.get_order(&order.payment_order_id).unwrap();
    assert_eq!(order.status, OrderStatus::RequiresAction);
    // Nothing journaled yet (exactly-once holds).
    assert_eq!(store.postings().unwrap().len(), 0);
    // The tx hash is the reconciliation evidence in the notification.
    let notes = store.notifications().unwrap();
    assert!(notes.iter().any(|n| n.event.contains("settlement_pending")));

    handle.join().unwrap();
}

#[tokio::test]
async fn executor_payment_with_unverifiable_signature_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = wallet_file(&dir);
    // The endpoint verifies the PAYMENT-SIGNATURE and always rejects — a
    // forged/tampered authorization never settles. The executor sees the
    // re-402 (no receipt) as a terminal failure, so only the first
    // unsigned GET happens: one connection.
    let (addr, handle) = mock_x402_endpoint(1, true, reject_response);

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    enable_http402(&store);
    let mut order = PaymentOrder::new("checkout-4", &format!("http://{addr}/no"), "1.00", "USD");
    order.rail = Some(RailHint::Http402);
    store.insert_order(&order).unwrap();

    let summary = run_pass(&store, &wallet_path).await;
    assert_eq!(
        summary.executed, 0,
        "nothing settles on a rejected signature"
    );
    assert_eq!(
        store.get_order(&order.payment_order_id).unwrap().status,
        OrderStatus::Failed
    );
    // Exactly-once: nothing journaled.
    assert_eq!(store.postings().unwrap().len(), 0);

    handle.join().unwrap();
}

#[tokio::test]
async fn executor_rejects_to_dlq_then_requeues_and_settles() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_path = wallet_file(&dir);
    // First signed retry is re-rejected (terminal), the next settles.
    let rejected = Arc::new(AtomicBool::new(true));
    let rejected_clone = rejected.clone();
    let (addr, handle) = mock_x402_endpoint(4, true, move || {
        if rejected_clone.swap(false, Ordering::SeqCst) {
            reject_response()
        } else {
            success_response()
        }
    });

    let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
    enable_http402(&store);
    let mut order = PaymentOrder::new("checkout-3", &format!("http://{addr}/retry"), "4.00", "USD");
    order.rail = Some(RailHint::Http402);
    store.insert_order(&order).unwrap();

    // Pass 1: rejected -> FAILED + DLQ.
    let summary = run_pass(&store, &wallet_path).await;
    assert_eq!(summary.executed, 0);
    assert_eq!(
        store.get_order(&order.payment_order_id).unwrap().status,
        OrderStatus::Failed
    );
    assert_eq!(store.dlq_records().unwrap().len(), 1);

    // Requeue (FAILED -> NOT_STARTED) and settle on the second pass.
    let mut requeued = store.get_order(&order.payment_order_id).unwrap();
    requeued.transition(OrderStatus::NotStarted).unwrap();
    store.update_order(&requeued).unwrap();

    let summary = run_pass(&store, &wallet_path).await;
    assert_eq!(summary.executed, 1);
    assert_eq!(
        store.get_order(&order.payment_order_id).unwrap().status,
        OrderStatus::Success
    );
    // Exactly-once: exactly one journal batch.
    assert_eq!(store.postings().unwrap().len(), 2);

    handle.join().unwrap();
}
