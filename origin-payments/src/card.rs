// SPDX-License-Identifier: Apache-2.0

//! Card rail — ACP-style **tokenized** authorization (design §3/§4.1).
//!
//! PCI out of scope by design: the rail consumes a card *token* plus the
//! network and last4 display hint — never the PAN, expiry, or CVC. The
//! token is produced by an out-of-scope PCI environment (PSP hosted
//! fields / token vault) and referenced by id.
//!
//! The rail mirrors the x402 facilitator split: a configured ACP
//! facilitator (URL + API key in the PSP vault via `psp-configure card`)
//! is asked to authorize the token for the order amount. `success` →
//! journal + settle; `settlement_pending` → `REQUIRES_ACTION` (3DS /
//! async auth callback); `declined` → terminal.

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::x402::FacilitatorConfig;

/// The tokenized authorization request the executor sends to the ACP
/// facilitator. Contains only the token reference + display fields —
/// no cardholder data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardAuthRequest {
    /// The PSP-issued card token (the rail's idempotent spend key).
    pub token: String,
    /// Card network for display/audit: VISA | MASTERCARD | AMEX | ...
    pub network: String,
    /// Last 4 digits, display/audit only — never derived from the PAN.
    pub last4: String,
    /// Decimal amount string (minor units resolved PSP-side).
    pub amount: String,
    pub currency: String,
    /// The order idempotency key — the PSP dedupes on it.
    pub payment_order_id: String,
    pub checkout_id: String,
}

/// The ACP facilitator's authorization outcome, mapped onto the
/// executor's settle semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardAuthOutcome {
    /// Authorized — the receipt bytes are reconciliation evidence.
    Settled { auth: Vec<u8> },
    /// 3DS / async auth — the tx reference is the reconcile key.
    Pending { transaction: Option<String> },
    /// The PSP refused the token (insufficient funds, fraud block, ...).
    Declined { error: String },
}

/// Ask the configured ACP facilitator to authorize `req` against its
/// `POST /authorize` endpoint (authenticated with the vault's API key).
///
/// - `Ok(Settled)` / `Ok(Pending)` / `Ok(Declined)` — the facilitator
///   answered authoritatively;
/// - `Err(RailUnavailable)` — the endpoint is unreachable (retryable);
/// - `Err(...)` — misconfigured / malformed reply (terminal).
pub fn authorize(cfg: &FacilitatorConfig, req: &CardAuthRequest) -> crate::Result<CardAuthOutcome> {
    let body = serde_json::to_vec(req).map_err(|e| Error::CryptoError {
        details: format!("serializing card authorization: {e}"),
    })?;
    let extra: Vec<(&'static str, String)> = if cfg.api_key.is_empty() {
        Vec::new()
    } else {
        vec![("x-api-key", cfg.api_key.clone())]
    };

    let (status, _headers, resp) = crate::x402::http_post_json(
        &format!("{}/authorize", cfg.url.trim_end_matches('/')),
        &body,
        extra,
        "card",
    )?;
    if status >= 500 {
        return Err(Error::RailUnavailable {
            rail: "card".to_string(),
            details: format!("ACP facilitator returned HTTP {status}"),
        });
    }

    let json: serde_json::Value =
        serde_json::from_slice(&resp).map_err(|e| Error::CryptoError {
            details: format!("ACP facilitator /authorize reply not JSON: {e}"),
        })?;
    let status_str = json
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("declined");
    Ok(match status_str {
        "success" => {
            let auth = json
                .get("auth")
                .and_then(|v| v.as_str())
                .map(decode_auth)
                .transpose()
                .map_err(|e| Error::CryptoError {
                    details: format!("bad auth receipt: {e}"),
                })?
                .unwrap_or_default();
            CardAuthOutcome::Settled { auth }
        }
        "settlement_pending" => CardAuthOutcome::Pending {
            transaction: json
                .get("transaction")
                .and_then(|v| v.as_str())
                .map(String::from),
        },
        other => CardAuthOutcome::Declined {
            error: json
                .get("error")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| format!("authorization {other}")),
        },
    })
}

/// Decode the `auth` receipt: base64 first, then hex, else raw UTF-8
/// bytes (a plain string receipt).
fn decode_auth(s: &str) -> Result<Vec<u8>, String> {
    if let Ok(v) = crate::x402::b64_decode(s) {
        return Ok(v);
    }
    if let Ok(v) = hex::decode(s.trim()) {
        return Ok(v);
    }
    Ok(s.as_bytes().to_vec())
}

// ── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A tiny ACP facilitator: serves exactly `responses` replies to
    /// `POST /authorize` and captures the last request body.
    fn mock_facilitator(
        responses: Vec<Vec<u8>>,
    ) -> (
        std::thread::JoinHandle<()>,
        String,
        std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let cap = captured.clone();
        let handle = std::thread::spawn(move || {
            for resp in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap();
                cap.lock().unwrap().extend_from_slice(&buf[..n]);
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                            resp.len()
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                stream.write_all(&resp).unwrap();
            }
        });
        (handle, format!("http://{addr}"), captured)
    }

    fn cfg(url: &str) -> FacilitatorConfig {
        FacilitatorConfig {
            url: url.to_string(),
            api_key: "sk_test_card".to_string(),
        }
    }

    fn req() -> CardAuthRequest {
        CardAuthRequest {
            token: "tok_visa_1234".to_string(),
            network: "VISA".to_string(),
            last4: "4242".to_string(),
            amount: "19.99".to_string(),
            currency: "USD".to_string(),
            payment_order_id: "order-1".to_string(),
            checkout_id: "c-1".to_string(),
        }
    }

    #[test]
    fn authorize_success_decodes_auth_receipt() {
        let auth = b"acp-auth-evidence";
        let body = format!(
            "{{\"status\":\"success\",\"auth\":\"{}\"}}",
            base64_enc(auth)
        )
        .into_bytes();
        let (h, url, captured) = mock_facilitator(vec![body]);
        let outcome = authorize(&cfg(&url), &req()).unwrap();
        h.join().unwrap();
        assert_eq!(
            outcome,
            CardAuthOutcome::Settled {
                auth: auth.to_vec()
            }
        );
        // The token reference (never the PAN) is what leaves the client.
        let sent = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(sent.contains("tok_visa_1234"), "token reference sent");
        assert!(
            sent.contains("\"last4\":\"4242\""),
            "last4 display hint sent"
        );
        assert!(
            sent.contains("x-api-key: sk_test_card"),
            "API-key authenticated"
        );
    }

    #[test]
    fn authorize_pending_and_declined() {
        let body = br#"{"status":"settlement_pending","transaction":"tx-abc"}"#.to_vec();
        let (h, url, _) = mock_facilitator(vec![body]);
        let outcome = authorize(&cfg(&url), &req()).unwrap();
        h.join().unwrap();
        assert_eq!(
            outcome,
            CardAuthOutcome::Pending {
                transaction: Some("tx-abc".to_string())
            }
        );

        let body = br#"{"status":"declined","error":"insufficient funds"}"#.to_vec();
        let (h, url, _) = mock_facilitator(vec![body]);
        let outcome = authorize(&cfg(&url), &req()).unwrap();
        h.join().unwrap();
        assert_eq!(
            outcome,
            CardAuthOutcome::Declined {
                error: "insufficient funds".to_string()
            }
        );
    }

    #[test]
    fn authorize_unreachable_is_retryable_rail_error() {
        let cfg = cfg("http://127.0.0.1:1");
        let err = authorize(&cfg, &req()).unwrap_err();
        assert!(matches!(err, Error::RailUnavailable { .. }));
    }

    fn base64_enc(b: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(b)
    }
}
