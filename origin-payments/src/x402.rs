// SPDX-License-Identifier: Apache-2.0

//! x402 rail client (research: `PAYMENTS_RESEARCH.md` §2).
//!
//! Implements the x402 V2 HTTP handshake with a minimal std-based
//! HTTP/1.1 client — no new HTTP dependencies, matching the suite's
//! dependency-light ethos:
//!
//! 1. Request the gated resource → server replies `402 Payment Required`
//!    with a `PAYMENT-REQUIRED` header (base64 payment requirements).
//! 2. The client picks an acceptable option and signs a payment payload.
//! 3. Retry the request with the `PAYMENT-SIGNATURE` header.
//! 4. The server (or its facilitator) verifies + settles; the response
//!    carries a `PAYMENT-RESPONSE` header with the settlement receipt.
//!
//! Key semantics (spec): `settlement_pending` is a **non-terminal** state —
//! the tx was broadcast but confirmation is unestablished, so callers
//! reconcile on-chain before retrying. The executor maps it to
//! `REQUIRES_ACTION`.
//!
//! ## Signing (V2 payload)
//!
//! `PAYMENT-SIGNATURE` is a base64 JSON payload with the protocol version,
//! the resource being paid, the accepted payment option, and a **signed
//! authorization** ([AEON](https://aeon-xyz.readme.io/docs/x402-qr-code-payment),
//! [Radius](https://docs.radiustech.xyz/developer-resources/x402-integration/)).
//! [`HybridSigner`] produces that authorization with the operator's
//! **origin-crypto-sdk hybrid bundle** (Ed25519 + Falcon-1024, same
//! `OperatorKeys` that sign orders, events, and journal postings). The
//! signature covers a canonical form of the authorization *plus the
//! resource URL* — so a signed payment can never be replayed against a
//! different endpoint. The signer's public keys ride in the payload so
//! verification works offline ([`verify_payment_payload`]).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// x402 V2 header names.
pub const PAYMENT_REQUIRED: &str = "payment-required";
pub const PAYMENT_SIGNATURE: &str = "payment-signature";
pub const PAYMENT_RESPONSE: &str = "payment-response";

/// Request timeout for the std HTTP client.
const HTTP_TIMEOUT_SECS: u64 = 10;

/// Facilitator configuration for the x402 rail: the facilitator API
/// endpoint whose `verify` / `settle` split settles signed payment
/// authorizations, plus the API key used to authenticate those calls
/// (stored in the PSP vault via `psp-configure`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacilitatorConfig {
    /// Facilitator base URL, e.g. `http://facilitator.example` (the std
    /// client only speaks `http://`; TLS is a documented follow-up).
    pub url: String,
    /// Authenticating API key (stored in the vault; sent as `x-api-key`).
    pub api_key: String,
}

/// Verdict from the chain of `verify`-time checks (cheap checks before
/// any settlement spend).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyVerdict {
    /// Authorization signatures/intents check out — safe to settle.
    Accept,
    /// A check failed and the payment must not proceed.
    Reject(String),
}

/// Outcome of a facilitator settle attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FacilitatorSettleOutcome {
    Settled {
        receipt: Vec<u8>,
    },
    Pending {
        transaction: Option<String>,
        /// Retry-After hint from the facilitator (seconds). The executor
        /// passes this to `schedule_retry` so the backoff respects the
        /// facilitator's timing.
        retry_after: Option<u64>,
    },
    Rejected {
        error: String,
        retry_after: Option<u64>,
    },
}

/// Payment requirements from a `PAYMENT-REQUIRED` header: the acceptable
/// payment options (scheme + network + details).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequirements {
    pub accepts: Vec<PaymentOption>,
}

/// One acceptable way to pay for the resource (V2 field shape). The
/// wire format is camelCase (`payTo`, `maxTimeoutSeconds`) per the spec;
/// the Rust fields are snake_case.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentOption {
    pub scheme: String,
    /// CAIP-2 network id (e.g. "eip155:8453").
    pub network: String,
    /// Payee address — the signed authorization's `to` must match this
    /// (spec validation rule).
    pub pay_to: String,
    /// Payment amount (minor units, as declared by the facilitator).
    pub amount: String,
    /// Authorization validity window (seconds); defaults to 300.
    #[serde(default)]
    pub max_timeout_secs: Option<u64>,
    /// Facilitator-specific extras (asset, token decimals, …).
    #[serde(default)]
    pub payment_details: serde_json::Value,
}

/// The settlement outcome parsed from the `PAYMENT-RESPONSE` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X402Status {
    /// Settled and confirmed.
    Success,
    /// Broadcast but not confirmed — non-terminal; the tx hash is
    /// reconciliation evidence ("reconcile on chain before deciding
    /// whether to retry").
    Pending { transaction: Option<String> },
    /// Terminally rejected (invalid payload, server refusal).
    Failed { error: Option<String> },
}

/// One x402 handshake: the outcome plus the raw receipt bytes.
#[derive(Debug, Clone)]
pub struct X402Outcome {
    pub status: X402Status,
    /// The `PAYMENT-RESPONSE` header value (base64 JSON settlement
    /// response) — the receipt evidence for the journal.
    pub receipt: Vec<u8>,
}

/// The seam for producing a signed payment payload. The executor plugs
/// in [`HybridSigner`] (operator hybrid keys); [`StubSigner`] exists for
/// protocol-shape tests.
pub trait PaymentSigner {
    /// Produce the base64-ready JSON payment payload (the `PAYMENT-SIGNATURE`
    /// header value is `base64(json)` of this). `resource_url` is bound
    /// into the signature.
    fn sign(&self, requirements: &PaymentRequirements, resource_url: &str) -> Result<Vec<u8>>;
}

/// x402 V2 payment payload — the JSON object that is base64-encoded into
/// the `PAYMENT-SIGNATURE` header (AEON / Radius reference shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentPayload {
    pub x402_version: u8,
    pub resource: PaymentResource,
    /// The exact `accepts[]` option chosen in step 1, passed back.
    pub accepted: PaymentOption,
    pub payload: SignedAuthorization,
}

/// The gated resource being paid for — part of the signed bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResource {
    pub url: String,
    #[serde(default)]
    pub description: String,
}

/// The signed authorization (V2 `payload.authorization` + `payload.signature`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAuthorization {
    pub authorization: PaymentAuthorization,
    /// SDK `HybridSig` wire bytes, hex-encoded.
    pub signature: String,
    /// The signer's public keys, embedded for offline verification.
    pub signer: PaymentSignerKeys,
}

/// A payment authorization: payer → payee, value, validity window, nonce.
/// The signature covers these fields canonically (plus the resource URL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentAuthorization {
    /// Payer identifier — the hybrid bundle's ed25519 public key (hex),
    /// the origin-key analogue of an EVM `from` address.
    pub from: String,
    /// Payee — must match `accepted.payTo` (spec validation rule).
    pub to: String,
    /// Payment amount (minor units, as declared in `accepted.amount`).
    pub value: String,
    /// Epoch seconds; the authorization is invalid before this.
    pub valid_after: String,
    /// Epoch seconds; the authorization expires after this.
    pub valid_before: String,
    /// Single-use nonce (hex) — replay protection.
    pub nonce: String,
    /// The origin hybrid signature scheme (as opposed to EVM EIP-712).
    pub scheme: String,
}

/// The signer's public keys, embedded in the payload so verification
/// works offline (same pattern as orders / journal postings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentSignerKeys {
    /// Ed25519 verifying key, hex (32 bytes).
    pub ed25519: String,
    /// Falcon-1024 public key wire bytes, hex.
    pub falcon1024: String,
    /// The bundle domain ("payments").
    pub domain: String,
}

/// Scheme string marking an origin hybrid (Ed25519 + Falcon-1024)
/// authorization.
pub const SCHEME_ORIGIN_HYBRID: &str = "origin-hybrid-v1";

/// The canonical bytes a hybrid signature covers: the authorization
/// fields, the resource URL, and the signer's public keys — an explicit
/// field list, so nothing self-referential slips in and the order is
/// deterministic.
pub fn authorization_canonical(
    auth: &PaymentAuthorization,
    resource_url: &str,
    signer: &PaymentSignerKeys,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        auth.from,
        auth.to,
        auth.value,
        auth.valid_after,
        auth.valid_before,
        auth.nonce,
        auth.scheme,
        resource_url,
        signer.ed25519,
        signer.falcon1024,
        signer.domain,
    ]))
    .unwrap_or_default()
}

/// Sign the payment for `resource_url` with the operator's hybrid keys
/// (`OperatorKeys` — the same bundle that signs orders and journal
/// postings). The signature embeds the signer's public keys and is bound
/// to the resource URL, so a payload can't be replayed elsewhere.
pub struct HybridSigner<'a> {
    keys: &'a crate::identity::OperatorKeys,
}

impl<'a> HybridSigner<'a> {
    pub fn new(keys: &'a crate::identity::OperatorKeys) -> Self {
        Self { keys }
    }
}

impl PaymentSigner for HybridSigner<'_> {
    fn sign(&self, requirements: &PaymentRequirements, resource_url: &str) -> Result<Vec<u8>> {
        let accepted = requirements
            .accepts
            .first()
            .ok_or_else(|| Error::CryptoError {
                details: "cannot sign: no acceptable payment option".to_string(),
            })?
            .clone();
        let signer_keys = PaymentSignerKeys {
            ed25519: hex::encode(self.keys.bundle.ed25519_pk().to_bytes()),
            falcon1024: hex::encode(self.keys.bundle.falcon1024_pk().as_bytes()),
            domain: crate::identity::PAYMENTS_DOMAIN.to_string(),
        };
        let now = chrono::Utc::now().timestamp();
        let max_timeout = accepted.max_timeout_secs.unwrap_or(300).max(1) as i64;
        let auth = PaymentAuthorization {
            from: signer_keys.ed25519.clone(),
            to: accepted.pay_to.clone(),
            value: accepted.amount.clone(),
            valid_after: now.to_string(),
            valid_before: (now + max_timeout).to_string(),
            nonce: hex::encode(random_32()),
            scheme: SCHEME_ORIGIN_HYBRID.to_string(),
        };
        let canonical = authorization_canonical(&auth, resource_url, &signer_keys);

        let sig = self
            .keys
            .bundle
            .try_sign_hybrid(&canonical)
            .map_err(|e| Error::CryptoError {
                details: format!("x402 signing: {e}"),
            })?;
        let hybrid = origin_crypto_sdk::signing::wire::HybridSig::from_sig(&sig);
        let mut encoded = Vec::new();
        hybrid
            .encode(&mut encoded)
            .map_err(|e| Error::CryptoError {
                details: format!("x402 encoding signature: {e}"),
            })?;

        let payload = PaymentPayload {
            x402_version: 2,
            resource: PaymentResource {
                url: resource_url.to_string(),
                description: String::new(),
            },
            accepted,
            payload: SignedAuthorization {
                authorization: auth,
                signature: hex::encode(encoded),
                signer: signer_keys,
            },
        };
        serde_json::to_vec(&payload).map_err(|e| Error::CryptoError {
            details: format!("serializing payment payload: {e}"),
        })
    }
}

/// Deterministic dev/test signer — emits the V2 payload shape with a
/// zeroed (invalid) signature; proves the handshake, NOT a valid
/// authorization.
pub struct StubSigner;

impl PaymentSigner for StubSigner {
    fn sign(&self, requirements: &PaymentRequirements, resource_url: &str) -> Result<Vec<u8>> {
        let accepted = requirements
            .accepts
            .first()
            .cloned()
            .unwrap_or(PaymentOption {
                scheme: "exact".to_string(),
                network: String::new(),
                pay_to: String::new(),
                amount: String::new(),
                max_timeout_secs: None,
                payment_details: serde_json::Value::Null,
            });
        let payload = PaymentPayload {
            x402_version: 2,
            resource: PaymentResource {
                url: resource_url.to_string(),
                description: String::new(),
            },
            accepted,
            payload: SignedAuthorization {
                authorization: PaymentAuthorization {
                    from: String::new(),
                    to: String::new(),
                    value: String::new(),
                    valid_after: String::new(),
                    valid_before: String::new(),
                    nonce: "0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    scheme: SCHEME_ORIGIN_HYBRID.to_string(),
                },
                signature: String::new(),
                // Valid-shape dummy keys (32B / 1793B) so verification
                // fails at the signature check — not at key parsing.
                signer: PaymentSignerKeys {
                    ed25519: hex::encode([0u8; 32]),
                    falcon1024: hex::encode(vec![0u8; 1793]),
                    domain: crate::identity::PAYMENTS_DOMAIN.to_string(),
                },
            },
        };
        serde_json::to_vec(&payload).map_err(|e| Error::CryptoError {
            details: format!("serializing payment payload: {e}"),
        })
    }
}

/// 32 bytes from the SDK's CSPRNG (or a best-effort fallback).
fn random_32() -> [u8; 32] {
    let mut out = [0u8; 32];
    if origin_crypto_sdk::fill_random(&mut out).is_ok() {
        return out;
    }
    // Last-resort fallback (tests): time-seeded, non-cryptographic.
    let t = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
    out.fill(0);
    out[..8].copy_from_slice(&t.to_le_bytes());
    out
}

/// Verify a signed `PAYMENT-SIGNATURE` payload against the embedded
/// signer keys and the resource URL it claims to pay.
///
/// - `Ok(true)` — the hybrid signature verifies and binds to `resource_url`;
/// - `Ok(false)` — signature invalid (tampered, replayed elsewhere, or
///   wrong keys);
/// - `Err` — payload malformed (not JSON, wrong shape, bad hex).
pub fn verify_payment_payload(bytes: &[u8], resource_url: &str) -> Result<bool> {
    let payload: PaymentPayload =
        serde_json::from_slice(bytes).map_err(|e| Error::CryptoError {
            details: format!("parsing payment payload: {e}"),
        })?;
    if payload.x402_version != 2 {
        return Ok(false);
    }
    if payload.resource.url != resource_url {
        // The signature binds the payment to a specific endpoint — a
        // mismatch is a cross-resource replay.
        return Ok(false);
    }
    let auth = &payload.payload.authorization;
    if auth.scheme != SCHEME_ORIGIN_HYBRID {
        return Ok(false);
    }
    // Signature or key material that can't be parsed is a verification
    // failure — not a payload-shape error. Only malformed JSON above is
    // an `Err` (the caller can't even interpret the payment attempt).
    let Ok(sig_bytes) = hex::decode(&payload.payload.signature) else {
        return Ok(false);
    };
    let Ok(ed_bytes) = hex::decode(&payload.payload.signer.ed25519) else {
        return Ok(false);
    };
    let Ok(falcon_pk) = hex::decode(&payload.payload.signer.falcon1024) else {
        return Ok(false);
    };
    let Ok(ed_pk) = <[u8; 32]>::try_from(ed_bytes) else {
        return Ok(false);
    };
    let Ok(sig) = origin_crypto_sdk::signing::wire::HybridSig::decode(&sig_bytes, &mut 0) else {
        return Ok(false);
    };
    let canonical = authorization_canonical(auth, resource_url, &payload.payload.signer);
    Ok(sig.verify(&ed_pk, &falcon_pk, &canonical).is_ok())
}

/// Run the x402 handshake against `url`. The URL must be `http://` —
/// TLS is out of scope for the std client (documented follow-up).
pub fn execute(url: &str, signer: &dyn PaymentSigner) -> Result<X402Outcome> {
    // 1. Request the resource; the server answers 402 + PAYMENT-REQUIRED.
    let (status, headers, _body) = http_get(url, &[], "http402")?;
    if status != 402 {
        return Err(Error::RailNotConfigured {
            rail: "http402".to_string(),
            details: format!("expected 402 Payment Required, got HTTP {status}"),
        });
    }
    let requirements_raw =
        headers
            .get(PAYMENT_REQUIRED)
            .ok_or_else(|| Error::RailNotConfigured {
                rail: "http402".to_string(),
                details: "402 response missing PAYMENT-REQUIRED header".to_string(),
            })?;
    let requirements: PaymentRequirements = parse_base64_json(requirements_raw)?;
    if requirements.accepts.is_empty() {
        return Err(Error::RailNotConfigured {
            rail: "http402".to_string(),
            details: "PAYMENT-REQUIRED lists no acceptable payment options".to_string(),
        });
    }

    // 2–3. Sign a payload (bound to this resource URL) and retry with
    // PAYMENT-SIGNATURE.
    let payload = signer.sign(&requirements, url)?;
    let payload_b64 = b64(&payload);
    let (status, headers, _body) = http_get(url, &[(PAYMENT_SIGNATURE, &payload_b64)], "http402")?;

    // 4. The PAYMENT-RESPONSE header carries the settlement receipt.
    let receipt_raw = match headers.get(PAYMENT_RESPONSE) {
        Some(raw) => raw.clone(),
        None => {
            return Ok(X402Outcome {
                status: X402Status::Failed {
                    error: Some(format!("server rejected the payment (HTTP {status})")),
                },
                receipt: Vec::new(),
            })
        }
    };
    let receipt = b64_decode(&receipt_raw)?;
    let response: SettlementResponse =
        serde_json::from_slice(&receipt).map_err(|e| Error::CryptoError {
            details: format!("parsing PAYMENT-RESPONSE: {e}"),
        })?;
    let status = match response.status.as_str() {
        "success" => X402Status::Success,
        "settlement_pending" => X402Status::Pending {
            transaction: response.transaction,
        },
        other => X402Status::Failed {
            error: response.error.or_else(|| Some(other.to_string())),
        },
    };
    Ok(X402Outcome { status, receipt })
}

/// The settlement response body (a subset of the fields; unknown fields
/// are ignored).
#[derive(Debug, Deserialize)]
struct SettlementResponse {
    status: String,
    #[serde(default)]
    transaction: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Parse an x402 `PAYMENT-REQUIRED` header value into requirements (used
/// by both the handshake and the facilitator split).
pub fn parse_requirements(raw_header: &str) -> Result<PaymentRequirements> {
    parse_base64_json(raw_header)
}

/// Produce the signed payment payload (base64-ready JSON) for
/// `resource_url`. Delegate of [`execute`] used by the facilitator split.
pub fn build_signed_payload(
    signer: &dyn PaymentSigner,
    requirements: &PaymentRequirements,
    resource_url: &str,
) -> Result<Vec<u8>> {
    signer.sign(requirements, resource_url)
}

/// Run the cheap `verify`-time checks for a signed payload against the
/// originating endpoint. This is the executor's pre-settle gate: it
/// mirrors what a real facilitator's `/verify` does (validate signatures
/// and intents) before any money moves. `verify_payment_payload` is the
/// offline cryptographic check; `verify`-time policy lives in the
/// executor. Returns the payload when acceptable, else a `Reject`.
pub fn verify_signed_payload(
    payload: &[u8],
    resource_url: &str,
    expected_amount: Option<&str>,
) -> VerifyVerdict {
    match verify_payment_payload(payload, resource_url) {
        Ok(true) => {
            // Intents: the signed authorization's value must match the
            // option the client accepted (facilitators enforce this;
            // re-check it locally so a bad intent is refused pre-spend).
            match serde_json::from_slice::<PaymentPayload>(payload) {
                Ok(p) => {
                    if let Some(amt) = expected_amount {
                        if p.payload.authorization.value != amt {
                            return VerifyVerdict::Reject(format!(
                                "authorization value {} != declared {amt}",
                                p.payload.authorization.value
                            ));
                        }
                    }
                    VerifyVerdict::Accept
                }
                Err(e) => VerifyVerdict::Reject(format!("malformed payload: {e}")),
            }
        }
        Ok(false) => VerifyVerdict::Reject("hybrid signature invalid or resource mismatch".into()),
        Err(e) => VerifyVerdict::Reject(e.to_string()),
    }
}

/// Hit the facilitator's `POST /verify` (validate-only) endpoint with a
/// signed payload for `resource_url`.
///
/// - `Ok(true)` — accepted, safe to settle;
/// - `Ok(false)` — the facilitator rejected it;
/// - `Err` — the endpoint is unreachable / misconfigured (retryable).
pub fn facilitator_verify(
    cfg: &FacilitatorConfig,
    payload: &[u8],
    requirements: &PaymentRequirements,
    resource_url: &str,
) -> Result<bool> {
    let body = serde_json::to_vec(&serde_json::json!({
        "x402Version": 2,
        "paymentPayload": serde_json::from_slice::<serde_json::Value>(payload).map_err(|e| {
            Error::CryptoError { details: format!("payload not JSON: {e}") }
        })?,
        "paymentRequirements": requirements,
        "resourceUrl": resource_url,
    }))
    .map_err(|e| Error::CryptoError {
        details: e.to_string(),
    })?;

    let (_status, _headers, resp) = http_post(
        &format!("{}/verify", cfg.url.trim_end_matches('/')),
        &body,
        api_key_headers(cfg),
        "http402",
    )?;
    let json: serde_json::Value =
        serde_json::from_slice(&resp).map_err(|e| Error::CryptoError {
            details: format!("facilitator /verify reply not JSON: {e}"),
        })?;
    Ok(json
        .get("ok")
        .or_else(|| json.get("valid"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

/// Submit a signed payload for `resource_url` to the facilitator's
/// `POST /settle` and interpret the receipt against [`X402Status`]
/// semantics (`settlement_pending` → non-terminal).
pub fn facilitator_settle(
    cfg: &FacilitatorConfig,
    payload: &[u8],
    requirements: &PaymentRequirements,
    resource_url: &str,
) -> Result<FacilitatorSettleOutcome> {
    let body = serde_json::to_vec(&serde_json::json!({
        "x402Version": 2,
        "paymentPayload": serde_json::from_slice::<serde_json::Value>(payload).map_err(|e| {
            Error::CryptoError { details: format!("payload not JSON: {e}") }
        })?,
        "paymentRequirements": requirements,
        "resourceUrl": resource_url,
    }))
    .map_err(|e| Error::CryptoError {
        details: e.to_string(),
    })?;

    let (_status, headers, resp) = http_post(
        &format!("{}/settle", cfg.url.trim_end_matches('/')),
        &body,
        api_key_headers(cfg),
        "http402",
    )?;

    // A `PAYMENT-RESPONSE` header carrying a base64 receipt is preferred;
    // otherwise the response body itself is the receipt.
    let json_bytes = match headers.get(PAYMENT_RESPONSE) {
        Some(r) => b64_decode(r)?,
        None => resp,
    };
    let response: SettlementResponse =
        serde_json::from_slice(&json_bytes).map_err(|e| Error::CryptoError {
            details: format!("parsing settle receipt: {e}"),
        })?;
    // Parse Retry-After header (seconds) if present.
    let retry_after = headers
        .get("retry-after")
        .and_then(|v| v.trim().parse::<u64>().ok());

    Ok(match response.status.as_str() {
        "success" => FacilitatorSettleOutcome::Settled {
            receipt: json_bytes,
        },
        "settlement_pending" => FacilitatorSettleOutcome::Pending {
            transaction: response.transaction,
            retry_after,
        },
        other => FacilitatorSettleOutcome::Rejected {
            error: response.error.unwrap_or_else(|| other.to_string()),
            retry_after,
        },
    })
}

/// Extra headers authenticating facilitator calls (`x-api-key`).
fn api_key_headers(cfg: &FacilitatorConfig) -> Vec<(&'static str, String)> {
    if cfg.api_key.is_empty() {
        Vec::new()
    } else {
        vec![("x-api-key", cfg.api_key.clone())]
    }
}

// ── minimal HTTP/1.1 client (std only) ────────────────────────────────

struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
    /// True for `https://` URLs — the request is wrapped in a TLS client
    /// connection (feature `tls`) instead of a plain TCP stream.
    tls: bool,
}

fn parse_url(url: &str) -> Result<ParsedUrl> {
    let (rest, tls) = if let Some(r) = url.strip_prefix("https://") {
        (r, true)
    } else if let Some(r) = url.strip_prefix("http://") {
        (r, false)
    } else {
        return Err(Error::RailNotConfigured {
            rail: "http402".to_string(),
            details: format!(
                "unsupported scheme in {url} (the x402 client speaks http:// and https://)"
            ),
        });
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| Error::RailNotConfigured {
                rail: "http402".to_string(),
                details: format!("bad port in {url}"),
            })?,
        ),
        None => (authority.to_string(), if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(Error::RailNotConfigured {
            rail: "http402".to_string(),
            details: format!("empty host in {url}"),
        });
    }
    Ok(ParsedUrl {
        host,
        port,
        path: path.to_string(),
        tls,
    })
}

/// `GET` with optional extra headers; returns (status, lowercase-key
/// headers, body).
fn http_get(
    url: &str,
    extra_headers: &[(&str, &str)],
    rail: &str,
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    http_request("GET", url, None, extra_headers, rail)
}

/// Public `GET` for the executor's facilitator split (to fetch the
/// payment requirements from the resource endpoint).
pub fn http_get_public(
    url: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    http_get(url, extra_headers, "http402")
}

/// `POST` a JSON body with extra headers; returns (status, lowercase-key
/// headers, body).
fn http_post(
    url: &str,
    body: &[u8],
    extra_headers: Vec<(&'static str, String)>,
    rail: &str,
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    let extra: Vec<(&str, &str)> = extra_headers
        .iter()
        .map(|(k, v)| (*k, v.as_str()))
        .collect();
    http_request("POST", url, Some(body), &extra, rail)
}

/// Public `POST` wrapper for sibling rails (the card ACP rail posts its
/// token authorization through the same transport, including the optional
/// `tls` upgrade for https facilitators).
pub fn http_post_json(
    url: &str,
    body: &[u8],
    extra_headers: Vec<(&'static str, String)>,
    rail: &str,
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    http_post(url, body, extra_headers, rail)
}

/// Minimal HTTP/1.1 request over a fresh TCP stream — wrapped in a TLS
/// client connection when the URL is `https://` and the `tls` feature is
/// enabled (plain `TcpStream` otherwise, keeping the dependency-light
/// default). The Host header includes the port so a server that
/// reconstructs the resource URL (host + path) matches the URL the client
/// signed. Reads until the response is complete per Content-Length (or
/// the server closes).
fn http_request(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    extra_headers: &[(&str, &str)],
    rail: &str,
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    #[cfg(feature = "tls")]
    {
        http_request_inner(method, url, body, extra_headers, None, rail)
    }
    #[cfg(not(feature = "tls"))]
    {
        http_request_inner(method, url, body, extra_headers, rail)
    }
}

/// [`http_request`] with an injectable TLS root store — tests hand a
/// self-signed trust anchor here; production calls use the system roots.
#[cfg(all(feature = "tls", test))]
fn http_request_with_roots(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    extra_headers: &[(&str, &str)],
    roots: rustls::RootCertStore,
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    http_request_inner(method, url, body, extra_headers, Some(roots), "http402")
}

#[cfg(feature = "tls")]
fn http_request_inner(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    extra_headers: &[(&str, &str)],
    roots_override: Option<rustls::RootCertStore>,
    rail: &str,
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    let parsed = parse_url(url)?;
    let addr = format!("{}:{}", parsed.host, parsed.port);
    let tcp = TcpStream::connect(&addr).map_err(|e| Error::RailUnavailable {
        rail: rail.to_string(),
        details: format!("connecting {addr}: {e}"),
    })?;
    tcp.set_read_timeout(Some(Duration::from_secs(HTTP_TIMEOUT_SECS)))
        .map_err(|e| Error::IoError {
            details: format!("setting read timeout: {e}"),
        })?;

    // TLS upgrade for https:// (feature `tls`).
    let mut io: Box<dyn StreamIo> = if parsed.tls {
        tls_stream(tcp, &parsed.host, &addr, roots_override)?
    } else {
        Box::new(tcp)
    };
    http_core(&mut *io, method, &parsed, body, extra_headers, &addr)
}

/// Non-TLS build: identical request path for `http://` URLs; `https://`
/// URLs are refused by [`tls_stream`] with an actionable error.
#[cfg(not(feature = "tls"))]
fn http_request_inner(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    extra_headers: &[(&str, &str)],
    rail: &str,
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    let parsed = parse_url(url)?;
    let addr = format!("{}:{}", parsed.host, parsed.port);
    let tcp = TcpStream::connect(&addr).map_err(|e| Error::RailUnavailable {
        rail: rail.to_string(),
        details: format!("connecting {addr}: {e}"),
    })?;
    tcp.set_read_timeout(Some(Duration::from_secs(HTTP_TIMEOUT_SECS)))
        .map_err(|e| Error::IoError {
            details: format!("setting read timeout: {e}"),
        })?;

    let mut io: Box<dyn StreamIo> = if parsed.tls {
        tls_stream(tcp, &parsed.host, &addr)?
    } else {
        Box::new(tcp)
    };
    http_core(&mut *io, method, &parsed, body, extra_headers, &addr)
}

/// Shared HTTP/1.1 request/response core over an already-connected
/// stream (plain or TLS): writes the request, reads until the response is
/// complete per Content-Length (or the server closes), and parses it.
fn http_core(
    io: &mut dyn StreamIo,
    method: &str,
    parsed: &ParsedUrl,
    body: Option<&[u8]>,
    extra_headers: &[(&str, &str)],
    addr: &str,
) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    let host_header = format!("{}:{}", parsed.host, parsed.port);
    let mut req = format!(
        "{method} {} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: origin-payments/x402\r\nAccept: */*\r\n",
        parsed.path
    );
    if let Some(b) = body {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    let mut full: Vec<u8> = req.into_bytes();
    if let Some(b) = body {
        full.extend_from_slice(b);
    }
    io.write_all(&full).map_err(|e| Error::RailUnavailable {
        rail: "http402".to_string(),
        details: format!("sending request to {addr}: {e}"),
    })?;

    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match io.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if response_complete(&buf) {
                    break;
                }
            }
            Err(_) => break, // timeout / reset — parse what we have
        }
    }
    parse_http_response(&buf)
}

/// Unified read/write over either a plain `TcpStream` or a rustls
/// TLS-wrapped stream (`StreamOwned`), so the request/response logic is
/// identical for `http://` and `https://`.
trait StreamIo: Read + Write {}
impl StreamIo for TcpStream {}
#[cfg(feature = "tls")]
impl StreamIo for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {}

/// Wrap `tcp` in a rustls client connection for `host`, completing the
/// TLS handshake before the HTTP request is written.
#[cfg(feature = "tls")]
fn tls_stream(
    tcp: TcpStream,
    host: &str,
    addr: &str,
    roots_override: Option<rustls::RootCertStore>,
) -> Result<Box<dyn StreamIo>> {
    use std::sync::Arc;

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| {
        Error::RailUnavailable {
            rail: "http402".to_string(),
            details: format!("bad TLS server name {host}: {e}"),
        }
    })?;
    // Trust the system's root certificates so real facilitators verify;
    // a test may inject its own trust anchor (self-signed loopback).
    let roots = match roots_override {
        Some(r) => r,
        None => {
            let mut r = rustls::RootCertStore::empty();
            let result = rustls_native_certs::load_native_certs();
            for cert in result.certs {
                let _ = r.add(cert); // ignore unparsable platform certs
            }
            r
        }
    };
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let conn =
        rustls::ClientConnection::new(config, server_name).map_err(|e| Error::RailUnavailable {
            rail: "http402".to_string(),
            details: format!("building TLS client for {addr}: {e}"),
        })?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    stream
        .conn
        .complete_io(&mut stream.sock)
        .map_err(|e| Error::RailUnavailable {
            rail: "http402".to_string(),
            details: format!("TLS handshake with {addr}: {e}"),
        })?;
    Ok(Box::new(stream))
}

/// Without the `tls` feature, `https://` URLs are refused at connect time
/// with an actionable error (no silent plaintext downgrade).
#[cfg(not(feature = "tls"))]
fn tls_stream(
    _tcp: TcpStream,
    host: &str,
    _addr: &str,
    #[cfg(feature = "tls")] _roots_override: Option<rustls::RootCertStore>,
) -> Result<Box<dyn StreamIo>> {
    Err(Error::RailUnavailable {
        rail: "http402".to_string(),
        details: format!(
            "https://{host} requires the `tls` feature (origin-payments --features tls)"
        ),
    })
}

/// True once the header block is fully read and the body, if
/// Content-Length is declared, is fully present.
fn response_complete(buf: &[u8]) -> bool {
    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&buf[..header_end]);
    for line in head.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                if let Ok(len) = v.trim().parse::<usize>() {
                    return buf.len() >= header_end + 4 + len;
                }
            }
        }
    }
    true
}

fn parse_http_response(buf: &[u8]) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::RailUnavailable {
            rail: "http402".to_string(),
            details: "incomplete HTTP response (no header terminator)".to_string(),
        })?;
    let head = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = head.lines();
    let status_line = lines.next().ok_or_else(|| Error::RailUnavailable {
        rail: "http402".to_string(),
        details: "empty HTTP response".to_string(),
    })?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| Error::RailUnavailable {
            rail: "http402".to_string(),
            details: format!("malformed status line: {status_line}"),
        })?;
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let body = buf[header_end + 4..].to_vec();
    Ok((status, headers, body))
}

// ── base64 helpers (x402 headers are base64-encoded JSON) ─────────────

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| Error::CryptoError {
            details: format!("decoding base64 header: {e}"),
        })
}

fn parse_base64_json<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T> {
    let bytes = b64_decode(raw)?;
    serde_json::from_slice(&bytes).map_err(|e| Error::CryptoError {
        details: format!("parsing base64 JSON header: {e}"),
    })
}

// ── tests (mock HTTP server over TcpListener) ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// Spawn a mock x402 server. `respond` receives the request headers
    /// (lowercased) and returns the raw response bytes.
    fn mock_server(
        respond: impl Fn(&HashMap<String, String>) -> Vec<u8> + Send + 'static,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
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
                for line in head.lines().skip(1) {
                    if let Some((k, v)) = line.split_once(':') {
                        headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                    }
                }
                let response = respond(&headers);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    fn requirement_header() -> String {
        let req = PaymentRequirements {
            accepts: vec![PaymentOption {
                scheme: "exact".to_string(),
                network: "base".to_string(),
                pay_to: "0xMerchant".to_string(),
                amount: "100".to_string(),
                max_timeout_secs: Some(300),
                payment_details: serde_json::json!({ "asset": "0xUSDC" }),
            }],
        };
        b64(&serde_json::to_vec(&req).unwrap())
    }

    fn response_with(settlement: &str) -> Vec<u8> {
        let receipt = b64(settlement.as_bytes());
        format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n{PAYMENT_RESPONSE}: {receipt}\r\n\r\n")
            .into_bytes()
    }

    fn http402() -> Vec<u8> {
        format!(
            "HTTP/1.1 402 Payment Required\r\nContent-Length: 0\r\n{PAYMENT_REQUIRED}: {}\r\n\r\n",
            requirement_header()
        )
        .into_bytes()
    }

    fn test_keys() -> (tempfile::TempDir, crate::identity::OperatorKeys) {
        let dir = tempfile::tempdir().unwrap();
        let home = origin_common::OriginHome::with_root(dir.path().join("home")).unwrap();
        let _store = origin_common::IdentityStore::create(
            &home,
            "test-pass",
            origin_common::MemoryTier::Nano,
        )
        .unwrap();
        let keys = crate::identity::load_operator_keys_from(&home, "test-pass").unwrap();
        (dir, keys)
    }

    fn v2_requirements() -> PaymentRequirements {
        PaymentRequirements {
            accepts: vec![PaymentOption {
                scheme: "exact".to_string(),
                network: "eip155:8453".to_string(),
                pay_to: "0xMerchant".to_string(),
                amount: "100".to_string(),
                max_timeout_secs: Some(300),
                payment_details: serde_json::json!({ "asset": "0xUSDC" }),
            }],
        }
    }

    #[test]
    fn hybrid_signer_produces_verifiable_v2_payload() {
        let (_dir, keys) = test_keys();
        let signer = HybridSigner::new(&keys);
        let req = v2_requirements();
        let url = "http://127.0.0.1:9999/paid";

        let bytes = signer.sign(&req, url).unwrap();
        let payload: PaymentPayload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.x402_version, 2);
        assert_eq!(payload.resource.url, url);
        assert_eq!(payload.accepted.pay_to, "0xMerchant");
        assert_eq!(payload.payload.authorization.scheme, SCHEME_ORIGIN_HYBRID);
        assert_eq!(
            payload.payload.authorization.to, "0xMerchant",
            "authorization.to must match accepted.payTo (spec rule)"
        );
        assert_eq!(payload.payload.authorization.value, "100");
        // A fresh nonce and a bounded validity window.
        assert_eq!(payload.payload.authorization.nonce.len(), 64);
        assert!(
            payload
                .payload
                .authorization
                .valid_before
                .parse::<i64>()
                .unwrap()
                > payload
                    .payload
                    .authorization
                    .valid_after
                    .parse::<i64>()
                    .unwrap()
        );

        // The embedded hybrid signature verifies against the signer keys.
        assert!(verify_payment_payload(&bytes, url).unwrap());
    }

    #[test]
    fn hybrid_signer_rejects_tamper_and_cross_resource_replay() {
        let (_dir, keys) = test_keys();
        let signer = HybridSigner::new(&keys);
        let req = v2_requirements();
        let url = "http://127.0.0.1:9999/paid";

        let bytes = signer.sign(&req, url).unwrap();
        assert!(verify_payment_payload(&bytes, url).unwrap());

        // Cross-resource replay: the same payload claimed for another URL.
        assert_eq!(
            verify_payment_payload(&bytes, "http://127.0.0.1:9999/other").unwrap(),
            false
        );

        // Tampering with a signed field breaks verification.
        let mut payload: PaymentPayload = serde_json::from_slice(&bytes).unwrap();
        payload.payload.authorization.value = "999".to_string();
        let tampered = serde_json::to_vec(&payload).unwrap();
        assert_eq!(verify_payment_payload(&tampered, url).unwrap(), false);

        // Tampering with the signer keys breaks verification.
        let mut payload: PaymentPayload = serde_json::from_slice(&bytes).unwrap();
        payload.payload.signer.ed25519 = hex::encode([0xAAu8; 32]);
        let tampered = serde_json::to_vec(&payload).unwrap();
        assert_eq!(verify_payment_payload(&tampered, url).unwrap(), false);
    }

    #[test]
    fn stub_signer_emits_v2_shape_but_does_not_verify() {
        let url = "http://127.0.0.1:9999/x";
        let bytes = StubSigner.sign(&v2_requirements(), url).unwrap();
        let payload: PaymentPayload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(payload.x402_version, 2);
        assert_eq!(payload.resource.url, url);
        // The stub carries an empty signature — never a valid authorization.
        assert_eq!(verify_payment_payload(&bytes, url).unwrap(), false);
    }

    fn mock_post_server(
        respond: impl Fn(&str, &HashMap<String, String>, &[u8]) -> (u16, HashMap<String, String>, Vec<u8>)
            + Send
            + 'static,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
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
                let request_path = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let mut headers = HashMap::new();
                for line in head.lines().skip(1) {
                    if let Some((k, v)) = line.split_once(':') {
                        headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                    }
                }
                // Split off the body after the blank line.
                let body = match buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    Some(i) => buf[i + 4..].to_vec(),
                    None => Vec::new(),
                };
                let (status, resp_headers, resp_body) = respond(&request_path, &headers, &body);
                let mut resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n",
                    resp_body.len()
                );
                for (k, v) in &resp_headers {
                    resp.push_str(&format!("{k}: {v}\r\n"));
                }
                resp.push_str("\r\n");
                let mut out = resp.into_bytes();
                out.extend_from_slice(&resp_body);
                let _ = stream.write_all(&out);
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn facilitator_verify_and_settle_split_flow() {
        let (_dir, keys) = test_keys();
        let signer = HybridSigner::new(&keys);
        let req = v2_requirements();
        let resource = "http://127.0.0.1:9999/paid";
        let payload = signer.sign(&req, resource).unwrap();

        let captured_key = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let ck = captured_key.clone();
        let url = mock_post_server(move |path, headers, _body| {
            *ck.lock().unwrap() = headers.get("x-api-key").cloned();
            // /verify returns the short `ok` verdict; /settle returns a
            // settlement response (a `status` field).
            if path.ends_with("/settle") {
                (200, HashMap::new(), br#"{"status":"success"}"#.to_vec())
            } else {
                (200, HashMap::new(), br#"{"ok":true}"#.to_vec())
            }
        });
        let cfg = FacilitatorConfig {
            url: url.clone(),
            api_key: "secret-key".to_string(),
        };

        // verify: pre-settle gate returns true and the API key is sent.
        assert!(
            facilitator_verify(&cfg, &payload, &req, resource).unwrap(),
            "facilitator /verify accepts"
        );
        assert_eq!(captured_key.lock().unwrap().as_deref(), Some("secret-key"));

        // settle:
        match facilitator_settle(&cfg, &payload, &req, resource).unwrap() {
            FacilitatorSettleOutcome::Settled { receipt } => {
                assert_eq!(receipt, br#"{"status":"success"}"#)
            }
            other => panic!("expected Settled, got {other:?}"),
        }
    }

    #[test]
    fn verify_signed_payload_gates_bad_intents() {
        let (_dir, keys) = test_keys();
        let signer = HybridSigner::new(&keys);
        let mut req = v2_requirements();
        let resource = "http://127.0.0.1:9999/paid";
        // Signed for amount 100; verify against the same → accept.
        let payload = signer.sign(&req, resource).unwrap();
        assert_eq!(
            verify_signed_payload(&payload, resource, Some("100")),
            VerifyVerdict::Accept
        );
        // Signed for 100 but a call declares a different amount → reject.
        assert!(matches!(
            verify_signed_payload(&payload, resource, Some("999")),
            VerifyVerdict::Reject(_)
        ));
        // Cross-resource misuse → reject.
        assert_eq!(
            verify_signed_payload(&payload, resource, Some("100")),
            VerifyVerdict::Accept,
            "same-resource accept"
        );
        assert!(matches!(
            verify_signed_payload(&payload, "http://other/paid", Some("100")),
            VerifyVerdict::Reject(_)
        ));
        req.accepts[0].amount = "200".to_string();
    }

    #[test]
    fn handshake_success() {
        let url = mock_server(|headers| {
            if headers.contains_key(PAYMENT_SIGNATURE) {
                response_with(r#"{"status":"success"}"#)
            } else {
                http402()
            }
        });
        let outcome = execute(&url, &StubSigner).unwrap();
        assert_eq!(outcome.status, X402Status::Success);
        assert!(!outcome.receipt.is_empty());
        assert_eq!(outcome.receipt, br#"{"status":"success"}"#);
    }

    #[test]
    fn settlement_pending_carries_tx_hash() {
        let url = mock_server(|headers| {
            if headers.contains_key(PAYMENT_SIGNATURE) {
                response_with(r#"{"status":"settlement_pending","transaction":"0xabc123"}"#)
            } else {
                http402()
            }
        });
        let outcome = execute(&url, &StubSigner).unwrap();
        assert_eq!(
            outcome.status,
            X402Status::Pending {
                transaction: Some("0xabc123".to_string())
            }
        );
    }

    #[test]
    fn server_rejection_is_terminal_failed() {
        let url = mock_server(|headers| {
            if headers.contains_key(PAYMENT_SIGNATURE) {
                // Invalid payload → server re-answers 402 without a receipt.
                http402()
            } else {
                http402()
            }
        });
        let outcome = execute(&url, &StubSigner).unwrap();
        match outcome.status {
            X402Status::Failed { error } => {
                assert!(error.is_some(), "rejection carries an error")
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn non_402_first_response_is_config_error() {
        let url = mock_server(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
        let err = execute(&url, &StubSigner).unwrap_err();
        assert!(matches!(err, Error::RailNotConfigured { .. }));
    }

    #[test]
    fn connection_refused_is_retryable_rail_error() {
        // Nothing is listening on this port.
        let err = execute("http://127.0.0.1:1/x", &StubSigner).unwrap_err();
        assert!(matches!(err, Error::RailUnavailable { .. }));
    }

    #[test]
    fn https_scheme_parses_and_connects_tls_path() {
        // `https://` is a valid scheme now (TLS feature or not); the
        // failure surfaces at connect/handshake time, never at parse time.
        let parsed = parse_url("https://example.com/x").unwrap();
        assert!(parsed.tls);
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.path, "/x");

        // No server on loopback: the error is a rail-availability error
        // (connect), not a scheme rejection.
        let err = execute("https://127.0.0.1:1/x", &StubSigner).unwrap_err();
        assert!(matches!(err, Error::RailUnavailable { .. }));
    }

    #[test]
    fn parse_url_https_defaults_port_443_and_http_80() {
        assert_eq!(parse_url("https://example.com").unwrap().port, 443);
        assert_eq!(parse_url("http://example.com").unwrap().port, 80);
        assert!(parse_url("https://example.com/a/b").unwrap().tls);
        assert!(!parse_url("http://example.com/a/b").unwrap().tls);
        // Explicit port wins.
        let p = parse_url("https://example.com:8443/x").unwrap();
        assert_eq!(p.port, 8443);
        assert!(p.tls);
    }

    #[test]
    fn http_path_still_works_after_tls_split() {
        let url = mock_server(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
        let (status, _, _) = http_get(&url, &[], "http402").unwrap();
        assert_eq!(status, 200);
    }

    /// Real TLS loopback: a rustls server with a self-signed cert, and the
    /// client driving the full `https://` request through the actual
    /// `http_request` plumbing (feature `tls`) — proving the stream
    /// upgrade completes a handshake and an HTTP roundtrip end-to-end.
    #[cfg(feature = "tls")]
    #[test]
    fn tls_loopback_handshake_and_request() {
        use std::sync::Arc;

        // Self-signed cert for `localhost` via rcgen.
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = certified.cert.der().clone();
        let key_der = certified.signing_key.serialize_der();
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert_der],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
                )
                .unwrap(),
        );

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut stream = rustls::StreamOwned::new(conn, tcp);
            // Complete the handshake, then read the HTTP request and reply.
            stream.conn.complete_io(&mut stream.sock).unwrap();
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
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.flush();
        });

        // The client trusts ONLY the self-signed cert (injected roots) —
        // a real facilitator would verify against the system roots loaded
        // by default. This drives the exact `tls_stream` + `http_request`
        // path under test.
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(certified.cert.der().clone())
            .expect("self-signed cert is a valid trust anchor");
        let url = format!("https://localhost:{}/x", addr.port());
        let (status, _, _) = http_request_with_roots("GET", &url, None, &[], roots).unwrap();
        handle.join().unwrap();
        assert_eq!(status, 200, "TLS-wrapped request completed and parsed");
    }
}
