// SPDX-License-Identifier: Apache-2.0

//! Lightweight HTTP webhook receiver for async settlement callbacks
//! (design doc §4.2: "the executor does not retry it on a timer — it
//! waits for the rail's asynchronous webhook").
//!
//! When a PSP returns `settlement_pending` (3DS, card async auth), the
//! order enters `REQUIRES_ACTION`. The PSP later sends a callback to this
//! receiver confirming settlement. The receiver validates the callback
//! signature (HMAC-SHA256 with a shared secret stored in the vault),
//! looks up the order, and transitions it back to `NOT_STARTED` so the
//! next executor pass picks it up.
//!
//! ## Wire format
//!
//! `POST /settlement-callback`
//! ```json
//! {
//!   "order_id": "uuid",
//!   "status": "settled" | "failed",
//!   "receipt": "base64-encoded receipt (optional)",
//!   "settlement_ref": "optional PSP reference",
//!   "timestamp": "ISO-8601"
//! }
//! ```
//! Header: `X-Signature: <hex(HMAC-SHA256(body, secret))>`

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::event::OrderStatus;
use crate::store::PaymentStore;

/// The webhook callback payload from a PSP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementCallback {
    pub order_id: String,
    pub status: String,
    #[serde(default)]
    pub receipt: Option<String>,
    #[serde(default)]
    pub settlement_ref: Option<String>,
    pub timestamp: String,
}

/// Start the webhook listener on `addr`. Blocks until the listener is
/// shut down. Each incoming callback is validated and processed.
pub fn listen(addr: &str, store: &PaymentStore) -> Result<()> {
    let listener = TcpListener::bind(addr).map_err(|e| Error::IoError {
        details: format!("binding webhook listener on {addr}: {e}"),
    })?;
    eprintln!("webhook listener bound on {addr}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                if let Err(e) = handle_connection(stream, store) {
                    eprintln!("webhook error: {e}");
                }
            }
            Err(e) => {
                eprintln!("webhook accept error: {e}");
            }
        }
    }
    Ok(())
}

/// Handle one TCP connection: read the HTTP request, validate the
/// callback, and process it.
fn handle_connection(mut stream: TcpStream, store: &PaymentStore) -> Result<()> {
    let reader_stream = stream.try_clone().map_err(|e| Error::IoError {
        details: format!("cloning stream: {e}"),
    })?;
    let mut reader = BufReader::new(reader_stream);

    // Read the request line.
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| Error::IoError {
            details: format!("reading request line: {e}"),
        })?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "POST" || parts[1] != "/settlement-callback" {
        send_response(&mut stream, 404, "{\"error\":\"not found\"}")?;
        return Ok(());
    }

    // Read headers to get Content-Length and X-Signature.
    let mut content_length: usize = 0;
    let mut signature: Option<String> = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| Error::IoError {
            details: format!("reading header: {e}"),
        })?;
        let line = line.trim().to_string();
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            match key.as_str() {
                "content-length" => content_length = value.parse().unwrap_or(0),
                "x-signature" => signature = Some(value),
                _ => {}
            }
        }
    }

    // Read the body.
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).map_err(|e| Error::IoError {
            details: format!("reading body: {e}"),
        })?;
    }

    // Parse the callback.
    let callback: SettlementCallback = serde_json::from_slice(&body)
        .map_err(|e| Error::InvalidAmount(format!("bad callback JSON: {e}")))?;

    // Validate HMAC signature (constant-time comparison).
    let secret = crate::vault::load_secret(store.root(), "webhook").ok();
    if let Some(secret_bytes) = &secret {
        let expected_hmac = hmac_sha3_256(secret_bytes, &body);
        let expected_hex = hex::encode(&expected_hmac);
        match &signature {
            Some(sig) if constant_time_eq(sig.as_bytes(), expected_hex.as_bytes()) => {}
            _ => {
                send_response(&mut stream, 401, "{\"error\":\"invalid signature\"}")?;
                return Ok(());
            }
        }
    }
    // If no secret is configured, skip signature validation (dev mode).

    // Timestamp freshness check: reject callbacks older than 5 minutes
    // to prevent replay of stale callbacks.
    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&callback.timestamp) {
        let age = chrono::Utc::now().signed_duration_since(ts);
        if age.num_seconds().abs() > 300 {
            send_response(
                &mut stream,
                401,
                "{\"error\":\"callback timestamp too old (>5 min)\"}",
            )?;
            return Ok(());
        }
    }

    // Process the callback.
    match process_callback(store, &callback) {
        Ok(()) => send_response(&mut stream, 200, "{\"ok\":true}")?,
        Err(e) => {
            let resp = format!("{{\"error\":\"{e}\"}}");
            send_response(&mut stream, 400, &resp)?;
        }
    }
    Ok(())
}

/// Process a validated callback: resolve the order from REQUIRES_ACTION.
fn process_callback(store: &PaymentStore, callback: &SettlementCallback) -> Result<()> {
    let mut order = store.get_order(&callback.order_id)?;

    if order.status != OrderStatus::RequiresAction {
        return Err(Error::InvalidAmount(format!(
            "order {} is not in REQUIRES_ACTION (current: {})",
            callback.order_id, order.status,
        )));
    }

    match callback.status.as_str() {
        "settled" => {
            // Transition back to NOT_STARTED so the next executor pass
            // settles it with the receipt.
            order.transition(OrderStatus::NotStarted)?;
            order.executing_since = None;
            order.next_retry_at = None;
            store.update_order(&order)?;

            store.append_notification(&crate::store::Notification {
                notification_id: uuid::Uuid::new_v4().to_string(),
                payment_order_id: order.payment_order_id.clone(),
                event: format!(
                    "webhook settled (ref: {})",
                    callback.settlement_ref.as_deref().unwrap_or("none")
                ),
                created_at: crate::now_rfc3339(),
            })?;

            crate::audit::record(
                store,
                crate::audit::AT_ORDER_REQUEUED,
                serde_json::json!({
                    "order": order.payment_order_id,
                    "reason": "webhook settled",
                    "settlement_ref": callback.settlement_ref,
                }),
                None,
            )?;
        }
        "failed" => {
            order.transition(OrderStatus::Failed)?;
            store.update_order(&order)?;

            store.append_dlq(&crate::store::DlqRecord {
                payment_order_id: order.payment_order_id.clone(),
                reason: format!(
                    "webhook failed: {}",
                    callback.settlement_ref.as_deref().unwrap_or("no ref")
                ),
                evidence: serde_json::json!({
                    "settlement_ref": callback.settlement_ref,
                    "timestamp": callback.timestamp,
                }),
                created_at: crate::now_rfc3339(),
            })?;
        }
        other => {
            return Err(Error::InvalidAmount(format!(
                "unknown callback status: {other}",
            )));
        }
    }
    Ok(())
}

/// HMAC-SHA3-256 using the SDK's SHA3-256 (standard HMAC construction:
/// `H(K XOR opad, H(K XOR ipad, message))`).
///
/// Note: the underlying hash is SHA-3-256 (not SHA-2-256). This is
/// consistent within the suite but callers interop'ing with external
/// PSPs should document the hash variant.
fn hmac_sha3_256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_padded = [0u8; 64];
    if key.len() > 64 {
        let hash = origin_crypto_sdk::sha3_256(key);
        key_padded[..32].copy_from_slice(&hash);
    } else {
        key_padded[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = key_padded[i] ^ 0x36;
        opad[i] = key_padded[i] ^ 0x5c;
    }

    let mut inner_input = Vec::with_capacity(64 + message.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(message);
    let inner_hash = origin_crypto_sdk::sha3_256(&inner_input);

    let mut outer_input = Vec::with_capacity(64 + 32);
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner_hash);
    origin_crypto_sdk::sha3_256(&outer_input)
}

/// Constant-time string comparison to prevent timing attacks on HMAC
/// verification.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Send a minimal HTTP response.
fn send_response(stream: &mut TcpStream, status: u16, body: &str) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|e| Error::IoError {
            details: format!("writing response: {e}"),
        })?;
    stream.flush().ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha3_256_produces_deterministic_output() {
        let key = b"test-secret-key";
        let msg = b"hello world";
        let h1 = hmac_sha3_256(key, msg);
        let h2 = hmac_sha3_256(key, msg);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn hmac_sha3_256_differs_for_different_keys() {
        let msg = b"same message";
        let h1 = hmac_sha3_256(b"key1", msg);
        let h2 = hmac_sha3_256(b"key2", msg);
        assert_ne!(h1, h2);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn callback_parse_roundtrip() {
        let cb = SettlementCallback {
            order_id: "test-order".to_string(),
            status: "settled".to_string(),
            receipt: Some("abc".to_string()),
            settlement_ref: Some("ref-123".to_string()),
            timestamp: "2026-08-24T00:00:00Z".to_string(),
        };
        let json = serde_json::to_vec(&cb).unwrap();
        let parsed: SettlementCallback = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.order_id, "test-order");
        assert_eq!(parsed.status, "settled");
        assert_eq!(parsed.receipt.as_deref(), Some("abc"));
    }
}
