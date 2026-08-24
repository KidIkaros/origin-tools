// SPDX-License-Identifier: Apache-2.0

//! Payment executor (design §4.1–§4.3, P4/P6).
//!
//! Executes orders over enabled rails: `NOT_STARTED` orders plus retries
//! whose backoff deadline has passed. Per order:
//!
//! 1. Mark `EXECUTING` (with `executing_since`) **before** any rail call —
//!    a crash mid-flight is recoverable by re-queueing orders stuck in
//!    `EXECUTING` past a TTL (design §4.3).
//! 2. Route: the order's rail hint must be enabled in the config, and the
//!    amount must respect the payments-layer per-tx cap (policy refusal
//!    records nothing on the rail).
//! 3. Pay via the payer wallet on the native rail; encode the returned
//!    `ENTRY_RECEIPT` ledger entry as the receipt evidence.
//! 4. Post the double-entry journal batch, mark `SUCCESS` +
//!    `ledger_updated` + `wallet_updated`, and record a notification.
//! 5. On failure: **retryable** errors schedule a backoff retry
//!    (`RetryJob`); **terminal** errors or exhausted attempts go to the
//!    DLQ. `REQUIRES_ACTION` (3DS etc.) waits for `order-resume`.

use std::net::SocketAddr;
use std::path::Path;

use crate::audit::{self, AT_ORDER_FAILED, AT_ORDER_SETTLED};
use crate::error::{Error, Result};
use crate::event::{EventStatus, OrderDirection, OrderStatus, PaymentOrder};
use crate::identity::OperatorKeys;
use crate::journal;
use crate::rails::{RailHint, RailReceipt};
use crate::retry;
use crate::store::{DlqRecord, Notification, PaymentStore};

/// Result of one executor pass.
#[derive(Debug, Clone)]
pub struct ExecutorSummary {
    /// Orders picked up this pass (`NOT_STARTED` + due retries).
    pub ready: usize,
    /// Orders settled to `SUCCESS`.
    pub executed: usize,
    /// Orders scheduled for a backoff retry.
    pub retried: usize,
    /// Orders re-queued by the EXECUTING TTL sweep (crash recovery).
    pub recovered: usize,
    /// Deferred-settlement batches committed this pass (P10).
    pub deferred_batches: usize,
    /// Human-readable note (failures / no-ops).
    pub note: String,
}

/// The outcome of attempting one order on a rail: retryable (transient
/// rail/network failure) vs terminal (validation, policy, config).
#[derive(Debug)]
enum SettleOutcome {
    Retryable(String),
    Terminal(String),
    /// 3DS / risk review / async webhook rails (http402, card) construct
    /// this in P6; the handling below is already wired.
    #[allow(dead_code)]
    RequiresAction(String),
}

/// Run one executor pass: `NOT_STARTED` orders plus retries whose
/// backoff deadline has passed, paying from the wallet at `wallet_path`.
/// `peer_credit` optionally pre-funds a standing credit line toward the
/// payee on the native rail, so several orders settle against one
/// `ENTRY_OPEN` limit (the mesh credit is cumulative: `remaining =
/// limit − sent`). `None` = open per-order credit as before.
pub async fn run_once(
    store: &PaymentStore,
    wallet_path: &Path,
    passphrase: &str,
    peer_addr: Option<SocketAddr>,
    peer_credit: Option<u64>,
    compliance: Option<&dyn crate::compliance::ComplianceScorer>,
) -> Result<ExecutorSummary> {
    let mut wallet =
        origin_wallet::Wallet::open(wallet_path, passphrase).map_err(|e| Error::WalletError {
            details: format!("opening {}: {e}", wallet_path.display()),
        })?;
    let config = store.load_config()?;
    let now = crate::now_rfc3339();

    // Crash recovery: orders stuck in EXECUTING past their TTL are
    // re-queued (or DLQ'd once attempts are exhausted).
    let (recovered, ttl_dlq) = requeue_stuck_executing(store, &config)?;

    // Deferred settlement (P10): when enabled, roll any pending verified
    // x402 authorizations up into a daily batch (MMR-checkpointed) instead
    // of leaving them for next pass. Committed once per pass, idempotent —
    // an empty/no-op when nothing is pending.
    let deferred_batches = if config.deferred_settlement_enabled {
        if store.deferred_commitments()?.is_empty() {
            0
        } else {
            crate::settle::commit_deferred_batch(
                store,
                &chrono::Utc::now().format("%Y-%m-%d").to_string(),
            )?;
            1
        }
    } else {
        0
    };

    // Journal postings are hybrid-signed when the operator identity is
    // reachable with the same passphrase; otherwise they stay unsigned
    // (the hash chain is the integrity guarantee).
    let operator = identity_keys(passphrase);

    let mut ready_orders = store.orders_with_status(OrderStatus::NotStarted)?;
    // Due retries: FAILED orders whose deadline has passed.
    for order in store.orders_with_status(OrderStatus::Failed)? {
        if let Some(deadline) = &order.next_retry_at {
            if deadline <= &now {
                ready_orders.push(order);
            }
        }
    }
    let ready = ready_orders.len();
    let mut executed = 0usize;
    let mut retried = 0usize;
    let mut failures = Vec::new();

    for mut order in ready_orders {
        // EXECUTING before any rail call — crash-recoverable.
        order.transition(OrderStatus::Executing)?;
        order.executing_since = Some(crate::now_rfc3339());
        order.attempts += 1;
        store.update_order(&order)?;

        match settle(
            &mut wallet,
            store,
            &config,
            &mut order,
            peer_addr,
            peer_credit,
            operator.as_ref(),
            compliance,
        )
        .await
        {
            Ok(()) => {
                executed += 1;
                // Settlement preference: after a successful Payment, apply
                // the merchant's preference (Hold / OffRamp / Split).
                if order.direction == crate::event::OrderDirection::Payment {
                    apply_settlement_preference(store, &order, &config)?;
                }
            }
            Err(SettleOutcome::Retryable(reason)) => {
                // Extract Retry-After hint from the reason string if present.
                let retry_after_ms = extract_retry_after_ms(&reason);
                if retry::schedule_retry(store, &mut order, &reason, &config.retry, retry_after_ms)?
                {
                    retried += 1;
                    failures.push(format!(
                        "{}: {reason} (retry scheduled)",
                        order.payment_order_id
                    ));
                } else {
                    failures.push(format!("{}: {reason}", order.payment_order_id));
                    mark_failed(store, &mut order, &reason)?;
                }
            }
            Err(SettleOutcome::RequiresAction(reason)) => {
                failures.push(format!(
                    "{}: {reason} (awaiting action)",
                    order.payment_order_id
                ));
                order.transition(OrderStatus::RequiresAction)?;
                store.update_order(&order)?;
                store.append_notification(&Notification {
                    notification_id: uuid::Uuid::new_v4().to_string(),
                    payment_order_id: order.payment_order_id.clone(),
                    event: format!("requires_action: {reason}"),
                    created_at: crate::now_rfc3339(),
                })?;
                audit::record(
                    store,
                    AT_ORDER_FAILED,
                    serde_json::json!({ "order": order.payment_order_id, "requires_action": reason }),
                    None,
                )?;
            }
            Err(SettleOutcome::Terminal(reason)) => {
                failures.push(format!("{}: {reason}", order.payment_order_id));
                mark_failed(store, &mut order, &reason)?;
            }
        }
        // Coordination layer: roll the checkout's event status up from the
        // order's new state (design §4.1).
        rollup_event(store, &order.payment_order_id)?;
    }

    let mut note = if failures.is_empty() {
        match executed {
            0 => "no orders were ready".to_string(),
            n => format!("settled {n} order(s)"),
        }
    } else {
        format!(
            "settled {executed} of {ready} (retried {retried}); {}",
            failures.join("; ")
        )
    };
    if deferred_batches > 0 {
        note = format!("{note} (deferred batch committed)");
    }
    if ttl_dlq > 0 {
        note = format!("{note} (TTL sweep DLQ'd {ttl_dlq} stuck order(s))");
    }

    Ok(ExecutorSummary {
        ready,
        executed,
        retried,
        recovered,
        deferred_batches,
        note,
    })
}

/// Try to load the operator identity keys with the given passphrase.
/// A missing identity or wrong passphrase yields `None` — the executor
/// then settles unsigned rather than failing the pass.
fn identity_keys(passphrase: &str) -> Option<OperatorKeys> {
    crate::identity::load_operator_keys(passphrase).ok()
}

/// Crash-recovery TTL sweep (design §4.3): every order stuck in
/// `EXECUTING` for longer than `config.executing_ttl_secs` is re-queued
/// to `NOT_STARTED` (attempts bounded by `retry.max_attempts` — past
/// that it is DLQ'd instead). Returns `(requeued, dlqed)`.
pub fn requeue_stuck_executing(
    store: &PaymentStore,
    config: &crate::store::PaymentsConfig,
) -> Result<(usize, usize)> {
    let mut requeued = 0usize;
    let mut dlqed = 0usize;
    for mut order in store.orders_with_status(OrderStatus::Executing)? {
        let Some(since) = &order.executing_since else {
            continue;
        };
        if !executing_expired(since, config.executing_ttl_secs) {
            continue;
        }
        order.attempts += 1;
        if order.attempts >= config.retry.max_attempts {
            // Bounded: a permanently-stuck order is a terminal failure.
            mark_failed(
                store,
                &mut order,
                "stuck in EXECUTING past TTL (attempts exhausted)",
            )?;
            dlqed += 1;
        } else {
            order.transition(OrderStatus::NotStarted)?;
            order.executing_since = None;
            order.next_retry_at = None;
            store.update_order(&order)?;
            audit::record(
                store,
                audit::AT_ORDER_REQUEUED,
                serde_json::json!({ "order": order.payment_order_id, "reason": "executing ttl exceeded" }),
                None,
            )?;
            requeued += 1;
        }
        rollup_event(store, &order.payment_order_id)?;
    }
    Ok((requeued, dlqed))
}

/// True when an `executing_since` RFC3339 timestamp is older than the
/// TTL. Unparseable timestamps are left alone (never force-requeued).
fn executing_expired(since: &str, ttl_secs: u64) -> bool {
    let Ok(since) = chrono::DateTime::parse_from_rfc3339(since) else {
        return false;
    };
    let since = since.with_timezone(&chrono::Utc);
    chrono::Utc::now() - since > chrono::Duration::seconds(ttl_secs as i64)
}

/// Coordination layer: find the event containing this order, refresh its
/// order snapshots from the store, roll its status up, and append the new
/// snapshot. Rollup snapshots are unsigned coordination records — the
/// signed + envelope-encrypted creation snapshot is preserved earlier in
/// the event log; money-movement authenticity lives in the per-order
/// signatures and the audit chain.
fn rollup_event(store: &PaymentStore, order_id: &str) -> Result<()> {
    let mut event = None;
    for e in store.events()? {
        if e.payment_orders
            .iter()
            .any(|o| o.payment_order_id == order_id)
        {
            event = Some(e); // reverse iteration: last snapshot wins
        }
    }
    let Some(mut event) = event else {
        return Ok(()); // order not tied to an event (tests, ad-hoc orders)
    };
    let ids: Vec<String> = event
        .payment_orders
        .iter()
        .map(|o| o.payment_order_id.clone())
        .collect();
    let latest = store.latest_orders()?;
    event.payment_orders = ids
        .iter()
        .filter_map(|id| latest.iter().find(|o| &o.payment_order_id == id).cloned())
        .collect();
    event.status = EventStatus::rollup(&event.payment_orders);
    event.signature = None;
    event.signer = None;
    event.envelope = None;
    store.update_event(&event)
}

/// Route and settle one order. The rail is chosen from the order's hint
/// (or native) against the enabled rails in the config.
///
/// When a `compliance` scorer is provided, it is called before any rail
/// call — `Reject` sends the order to the DLQ (terminal), `Flag` adds
/// an audit note but proceeds.
#[allow(clippy::too_many_arguments)]
async fn settle(
    wallet: &mut origin_wallet::Wallet,
    store: &PaymentStore,
    config: &crate::store::PaymentsConfig,
    order: &mut PaymentOrder,
    peer_addr: Option<SocketAddr>,
    peer_credit: Option<u64>,
    signer: Option<&OperatorKeys>,
    compliance: Option<&dyn crate::compliance::ComplianceScorer>,
) -> std::result::Result<(), SettleOutcome> {
    let hint = order.rail.unwrap_or(RailHint::Native);
    if !config.enabled_rails.iter().any(|r| r == hint.as_str()) {
        return Err(SettleOutcome::Terminal(format!(
            "rail {hint} is not enabled (enabled: {})",
            config.enabled_rails.join(", ")
        )));
    }

    let amount_minor = journal::parse_amount(&order.amount)
        .map_err(|_| SettleOutcome::Terminal(format!("invalid amount: {}", order.amount)))?;
    if amount_minor < 0 {
        return Err(SettleOutcome::Terminal(format!(
            "negative amount: {}",
            order.amount
        )));
    }
    // Payments-layer spend cap: refuse before any rail call.
    if let Some(cap_str) = &config.per_tx_cap {
        let cap = journal::parse_amount(cap_str)
            .map_err(|_| SettleOutcome::Terminal(format!("bad per_tx_cap in config: {cap_str}")))?;
        if amount_minor > cap {
            return Err(SettleOutcome::Terminal(format!(
                "amount {} exceeds per-tx cap {} (policy refusal — nothing sent)",
                order.amount, cap_str
            )));
        }
    }

    // Compliance scoring: refuse before any rail call when the scorer
    // rejects the payment (risk, counterparty, policy).
    if let Some(scorer) = compliance {
        let verdict = scorer
            .score(order)
            .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
        match verdict {
            crate::compliance::ComplianceVerdict::Accept => {}
            crate::compliance::ComplianceVerdict::Flag { reason } => {
                // Proceed but record the flag in the audit trail.
                crate::audit::record(
                    store,
                    crate::audit::AT_ORDER_FLAGGED,
                    serde_json::json!({
                        "order": order.payment_order_id,
                        "flag": reason,
                    }),
                    None,
                )
                .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
            }
            crate::compliance::ComplianceVerdict::Reject {
                reason,
                evidence: _,
            } => {
                return Err(SettleOutcome::Terminal(format!(
                    "compliance rejected: {reason}"
                )));
            }
        }
    }

    match hint {
        RailHint::Native => {
            settle_native(
                wallet,
                store,
                order,
                peer_addr,
                amount_minor as u64,
                peer_credit,
                signer,
            )
            .await
        }
        RailHint::Http402 => settle_http402(store, order, signer),
        RailHint::Card => settle_card(store, order, signer),
        RailHint::Ach => settle_ach(store, order, signer),
    }
}

/// Execute one order on the x402 rail: run the HTTP handshake against the
/// endpoint (the order's `to` is the x402 URL), then settle like the
/// native rail. `settlement_pending` maps to `REQUIRES_ACTION` — the tx
/// hash is reconciliation evidence; the wallet is NOT touched (funds move
/// from the client's chain wallet, not the stoa wallet).
fn settle_http402(
    store: &PaymentStore,
    order: &mut PaymentOrder,
    journal_signer: Option<&OperatorKeys>,
) -> std::result::Result<(), SettleOutcome> {
    // The x402 endpoint is the rail contract on the order.
    if !order.to.starts_with("http://") && !order.to.starts_with("https://") {
        return Err(SettleOutcome::Terminal(format!(
            "http402 rail: order.to must be an x402 endpoint URL, got {}",
            order.to
        )));
    }
    // The payment authorization MUST be hybrid-signed with the operator's
    // origin-crypto-sdk bundle (same keys that sign orders and journal
    // postings) — an unsigned x402 payment is not a valid authorization,
    // so unlike journal postings there is no unsigned fallback here.
    let Some(keys) = journal_signer else {
        return Err(SettleOutcome::Terminal(
            "http402 rail requires the operator identity (run origin-identity keygen) — refusing to send an unsigned payment".to_string(),
        ));
    };
    let signer = crate::x402::HybridSigner::new(keys);

    // A configured facilitator drives the verify/settle split (the cheap
    // pre-settle gate, then the money move). Without one we fall back to
    // the direct resource handshake. Both paths end in the same
    // journal-and-settle step (`settle_http402_success`).
    match crate::vault::load_facilitator_config(store.root(), "http402") {
        Ok(Some(cfg)) => {
            return settle_http402_with_facilitator(store, order, journal_signer, &signer, &cfg);
        }
        Ok(None) => {}
        Err(e) => return Err(x402_err(e)),
    }

    let outcome = crate::x402::execute(&order.to, &signer).map_err(|e| match e {
        Error::RailUnavailable { .. } => SettleOutcome::Retryable(e.to_string()),
        other => SettleOutcome::Terminal(other.to_string()),
    })?;
    match outcome.status {
        crate::x402::X402Status::Success => {
            settle_http402_success(store, order, journal_signer, outcome.receipt)?;
            Ok(())
        }
        crate::x402::X402Status::Pending { transaction } => Err(SettleOutcome::RequiresAction(
            format!("settlement_pending tx={}", transaction.unwrap_or_default()),
        )),
        crate::x402::X402Status::Failed { error } => Err(SettleOutcome::Terminal(
            error.unwrap_or_else(|| "x402 payment rejected".to_string()),
        )),
    }
}

/// Run the x402 facilitator verify/settle split for one order.
///
/// 1. **verify** — the cheap pre-settle gate: offline crypto check of the
///    signed authorization plus a call to the facilitator's `/verify`
///    (validate-only). Nothing is spent if either refuses.
/// 2. **settle** — the actual money move via the facilitator's `/settle`.
///
/// `verification rejected` and `settlement_pending` come back through
/// [`SettleOutcome`] so the supervisor maps them to DLQ / `REQUIRES_ACTION`
/// exactly as the direct handshake does.
fn settle_http402_with_facilitator(
    store: &PaymentStore,
    order: &mut PaymentOrder,
    journal_signer: Option<&OperatorKeys>,
    signer: &dyn crate::x402::PaymentSigner,
    cfg: &crate::x402::FacilitatorConfig,
) -> std::result::Result<(), SettleOutcome> {
    // Fetch the payment requirements from the resource endpoint (the
    // order's `to` is the x402 URL).
    let (status, headers, _) = crate::x402::http_get_public(&order.to, &[]).map_err(x402_err)?;
    if status != 402 {
        return Err(SettleOutcome::Terminal(format!(
            "expected 402 Payment Required, got HTTP {status}"
        )));
    }
    let req_raw = headers.get(crate::x402::PAYMENT_REQUIRED).ok_or_else(|| {
        SettleOutcome::Terminal("402 response missing PAYMENT-REQUIRED header".to_string())
    })?;
    let requirements = crate::x402::parse_requirements(req_raw).map_err(x402_err)?;
    let payload =
        crate::x402::build_signed_payload(signer, &requirements, &order.to).map_err(x402_err)?;

    // 1. verify — cheap pre-settle gate.
    match crate::x402::verify_signed_payload(&payload, &order.to, Some(&order.amount)) {
        crate::x402::VerifyVerdict::Accept => {}
        crate::x402::VerifyVerdict::Reject(reason) => {
            return Err(SettleOutcome::Terminal(format!(
                "verify rejected: {reason}"
            )))
        }
    }
    let verified = crate::x402::facilitator_verify(cfg, &payload, &requirements, &order.to)
        .map_err(x402_err)?;
    if !verified {
        return Err(SettleOutcome::Terminal(
            "facilitator /verify rejected the payment".to_string(),
        ));
    }

    // 2. settle — the actual spend.
    match crate::x402::facilitator_settle(cfg, &payload, &requirements, &order.to)
        .map_err(x402_err)?
    {
        crate::x402::FacilitatorSettleOutcome::Settled { receipt } => {
            settle_http402_success(store, order, journal_signer, receipt)?;
            Ok(())
        }
        crate::x402::FacilitatorSettleOutcome::Pending {
            transaction,
            retry_after,
        } => Err(SettleOutcome::RequiresAction(format!(
            "settlement_pending tx={}{}",
            transaction.unwrap_or_default(),
            retry_after
                .map(|r| format!(" retry-after={r}s"))
                .unwrap_or_default(),
        ))),
        crate::x402::FacilitatorSettleOutcome::Rejected { error, retry_after } => {
            // Facilitator rejection with a Retry-After hint is retryable
            // (not terminal) — the facilitator is saying "try again later".
            if let Some(secs) = retry_after {
                Err(SettleOutcome::Retryable(format!(
                    "facilitator /settle rejected: {error} (retry-after={secs}s)"
                )))
            } else {
                Err(SettleOutcome::Terminal(format!(
                    "facilitator /settle rejected: {error}"
                )))
            }
        }
    }
}

/// Map an x402 error onto a [`SettleOutcome`]: network/rail failures are
/// retryable; everything else is terminal.
/// Apply the merchant's settlement preference after a successful Payment.
/// - `OffRamp`: create a Payout order for the full amount (to be settled
///   via the off-ramp facilitator on the next pass).
/// - `Split`: create a Payout order for `(100 - split_pct)%` of the
///   amount.
/// - `Hold`: do nothing (the default).
fn apply_settlement_preference(
    store: &PaymentStore,
    order: &PaymentOrder,
    config: &crate::store::PaymentsConfig,
) -> Result<()> {
    use crate::store::SettlementPreference;
    match &config.settlement_preference {
        SettlementPreference::Hold => {}
        SettlementPreference::OffRamp => {
            // Create a payout order for the full amount.
            let mut payout = PaymentOrder::new(
                &order.checkout_id,
                &order.to,
                &order.amount,
                &order.currency,
            );
            payout.direction = OrderDirection::Payout;
            store.insert_order(&payout)?;
            crate::audit::record(
                store,
                crate::audit::AT_ORDER_CREATED,
                serde_json::json!({
                    "order": payout.payment_order_id,
                    "reason": "settlement_preference off_ramp",
                    "source_order": order.payment_order_id,
                }),
                None,
            )?;
        }
        SettlementPreference::Split => {
            // Create a payout order for `(100 - split_pct)%` of the amount.
            let pct = config.split_pct.min(100) as i128;
            let off_ramp_pct = 100 - pct;
            if off_ramp_pct <= 0 {
                return Ok(());
            }
            let amount_minor = journal::parse_amount(&order.amount).unwrap_or(0);
            let payout_minor = amount_minor * off_ramp_pct / 100;
            if payout_minor <= 0 {
                return Ok(());
            }
            // Format back to decimal string.
            let payout_amount = format!("{:.2}", payout_minor as f64 / 100.0);
            let mut payout = PaymentOrder::new(
                &order.checkout_id,
                &order.to,
                &payout_amount,
                &order.currency,
            );
            payout.direction = OrderDirection::Payout;
            store.insert_order(&payout)?;
            crate::audit::record(
                store,
                crate::audit::AT_ORDER_CREATED,
                serde_json::json!({
                    "order": payout.payment_order_id,
                    "reason": "settlement_preference split",
                    "source_order": order.payment_order_id,
                    "split_pct": config.split_pct,
                    "off_ramp_pct": off_ramp_pct,
                }),
                None,
            )?;
        }
    }
    Ok(())
}

/// Extract a `retry-after=Xs` hint from a settle error reason string.
/// Returns the hint in milliseconds for `schedule_retry`, or `None`.
fn extract_retry_after_ms(reason: &str) -> Option<u64> {
    reason
        .split_whitespace()
        .find(|s| s.starts_with("retry-after="))
        .and_then(|s| s.strip_prefix("retry-after="))
        .and_then(|s| s.strip_suffix('s'))
        .and_then(|s| s.parse::<u64>().ok())
        .map(|secs| secs * 1000)
}

fn x402_err(e: Error) -> SettleOutcome {
    match e {
        Error::RailUnavailable { .. } => SettleOutcome::Retryable(e.to_string()),
        other => SettleOutcome::Terminal(other.to_string()),
    }
}

/// Journal + settle an x402 order after a confirmed settlement receipt.
/// Shared by the direct handshake and the facilitator paths.
///
/// **Rail-level dedupe (x402 spec §4.2):** the receipt hash is checked
/// against the dedupe cache before journaling; if the same receipt was
/// already settled (duplicate settlement attempt), the order is refused
/// with a terminal error. After journaling, the hash is recorded.
fn settle_http402_success(
    store: &PaymentStore,
    order: &mut PaymentOrder,
    journal_signer: Option<&OperatorKeys>,
    receipt: Vec<u8>,
) -> std::result::Result<(), SettleOutcome> {
    // Rail-level dedupe: same receipt hash = duplicate settlement.
    let receipt_hash = origin_crypto_sdk::sha3_256(&receipt);
    if store
        .is_receipt_settled(&receipt_hash)
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?
    {
        return Err(SettleOutcome::Terminal(
            "duplicate settlement: receipt already settled for another order".to_string(),
        ));
    }

    journal::append_order_batch(
        store,
        &order.payment_order_id,
        &order.amount,
        &order.currency,
        order.fx.as_ref(),
        journal_signer,
    )
    .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;

    order.receipt = Some(RailReceipt::Http402 { receipt });
    order
        .transition(OrderStatus::Success)
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    order.ledger_updated = true;
    // No stoa wallet movement on this rail.
    order.wallet_updated = false;
    store
        .update_order(order)
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    // Record the receipt hash for future dedupe checks.
    store
        .record_receipt_hash(&order.payment_order_id, &receipt_hash)
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    store
        .append_notification(&Notification {
            notification_id: uuid::Uuid::new_v4().to_string(),
            payment_order_id: order.payment_order_id.clone(),
            event: format!("order_settled ({})", order.direction),
            created_at: crate::now_rfc3339(),
        })
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    audit::record(
        store,
        AT_ORDER_SETTLED,
        serde_json::json!({
            "order": order.payment_order_id,
            "amount": order.amount,
            "currency": order.currency,
            "rail": "http402",
            "to": order.to,
        }),
        None,
    )
    .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    Ok(())
}

/// Execute one order on the card rail: ask the configured ACP
/// facilitator to authorize the order's card token (never the PAN), then
/// journal + settle like the other rails. `settlement_pending` maps to
/// `REQUIRES_ACTION` (3DS / async auth callback).
fn settle_card(
    store: &PaymentStore,
    order: &mut PaymentOrder,
    journal_signer: Option<&OperatorKeys>,
) -> std::result::Result<(), SettleOutcome> {
    // The token reference is the rail contract on the order.
    let (token, network, last4) = match (&order.card_token, &order.card_network, &order.card_last4)
    {
        (Some(t), Some(n), Some(l)) => (t.clone(), n.clone(), l.clone()),
        _ => {
            return Err(SettleOutcome::Terminal(
                "card rail requires the order's card tokenization \
                 (order-create --card-token --card-network --card-last4); \
                 PCI out of scope — a token reference, never the PAN"
                    .to_string(),
            ))
        }
    };

    // A configured ACP facilitator (URL + API key) drives the
    // authorization. Without one the rail is refused with a hint.
    let cfg = match crate::vault::load_facilitator_config(store.root(), "card") {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            return Err(SettleOutcome::Terminal(
                "card rail not configured: run `psp-configure card --secret-file <KEY> \
                 --facilitator-url <URL> --totp <code>` first"
                    .to_string(),
            ))
        }
        Err(e) => return Err(card_err(e)),
    };

    let req = crate::card::CardAuthRequest {
        token,
        network: network.clone(),
        last4: last4.clone(),
        amount: order.amount.clone(),
        currency: order.currency.clone(),
        payment_order_id: order.payment_order_id.clone(),
        checkout_id: order.checkout_id.clone(),
    };
    match crate::card::authorize(&cfg, &req).map_err(card_err)? {
        crate::card::CardAuthOutcome::Settled { auth } => {
            settle_card_success(store, order, journal_signer, network, last4, auth)
        }
        crate::card::CardAuthOutcome::Pending { transaction } => {
            Err(SettleOutcome::RequiresAction(format!(
                "settlement_pending tx={}",
                transaction.unwrap_or_default()
            )))
        }
        crate::card::CardAuthOutcome::Declined { error } => Err(SettleOutcome::Terminal(format!(
            "card authorization declined: {error}"
        ))),
    }
}

/// Journal + settle a card order after a confirmed authorization. The
/// receipt is the facilitator's `auth` bytes; the wallet is NOT touched
/// (the PSP moves the money).
///
/// **Rail-level dedupe (x402 spec §4.2):** the receipt hash is checked
/// against the dedupe cache before journaling; duplicate settlements are
/// refused. After journaling, the hash is recorded.
fn settle_card_success(
    store: &PaymentStore,
    order: &mut PaymentOrder,
    journal_signer: Option<&OperatorKeys>,
    network: String,
    last4: String,
    auth: Vec<u8>,
) -> std::result::Result<(), SettleOutcome> {
    // Rail-level dedupe: same receipt hash = duplicate settlement.
    let receipt_hash = origin_crypto_sdk::sha3_256(&auth);
    if store
        .is_receipt_settled(&receipt_hash)
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?
    {
        return Err(SettleOutcome::Terminal(
            "duplicate settlement: card receipt already settled for another order".to_string(),
        ));
    }

    journal::append_order_batch(
        store,
        &order.payment_order_id,
        &order.amount,
        &order.currency,
        order.fx.as_ref(),
        journal_signer,
    )
    .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;

    order.receipt = Some(RailReceipt::CardAcp {
        network: network.clone(),
        last4: last4.clone(),
        auth,
    });
    order
        .transition(OrderStatus::Success)
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    order.ledger_updated = true;
    // No stoa wallet movement on this rail.
    order.wallet_updated = false;
    store
        .update_order(order)
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    // Record the receipt hash for future dedupe checks.
    store
        .record_receipt_hash(&order.payment_order_id, &receipt_hash)
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    store
        .append_notification(&Notification {
            notification_id: uuid::Uuid::new_v4().to_string(),
            payment_order_id: order.payment_order_id.clone(),
            event: format!("order_settled ({})", order.direction),
            created_at: crate::now_rfc3339(),
        })
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    audit::record(
        store,
        AT_ORDER_SETTLED,
        serde_json::json!({
            "order": order.payment_order_id,
            "amount": order.amount,
            "currency": order.currency,
            "rail": "card",
            "card_network": network.clone(),
            "card_last4": last4.clone(),
        }),
        None,
    )
    .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    Ok(())
}

/// Map a card-rail error onto a [`SettleOutcome`]: network/rail failures
/// are retryable; everything else is terminal.
fn card_err(e: Error) -> SettleOutcome {
    match e {
        Error::RailUnavailable { .. } => SettleOutcome::Retryable(e.to_string()),
        other => SettleOutcome::Terminal(other.to_string()),
    }
}

/// Execute one order on the ACH/SEPA fiat rail via an x402-style
/// facilitator. The facilitator settles on a traditional payment network
/// (ACH, SEPA, wire) instead of on-chain — the same verify/settle split
/// as http402, but the "network" is a bank rail.
///
/// x402 V2 explicitly supports legacy-rail facilitators: "Facilitators
/// for ACH, SEPA, or card networks fit into the same payment model."
///
/// The facilitator config is stored under `psp-configure ach`; the
/// signed payment payload uses the same `HybridSigner` as http402.
fn settle_ach(
    store: &PaymentStore,
    order: &mut PaymentOrder,
    journal_signer: Option<&OperatorKeys>,
) -> std::result::Result<(), SettleOutcome> {
    // ACH facilitator config (URL + API key).
    let cfg = match crate::vault::load_facilitator_config(store.root(), "ach") {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            return Err(SettleOutcome::Terminal(
                "ach rail not configured: run `psp-configure ach --secret-file <KEY> \
                 --facilitator-url <URL> --totp <code>` first"
                    .to_string(),
            ))
        }
        Err(e) => return Err(SettleOutcome::Terminal(e.to_string())),
    };

    // The ACH facilitator endpoint is the order's `to` URL.
    if !order.to.starts_with("http://") && !order.to.starts_with("https://") {
        return Err(SettleOutcome::Terminal(format!(
            "ach rail: order.to must be an ACH facilitator URL, got {}",
            order.to
        )));
    }

    let Some(keys) = journal_signer else {
        return Err(SettleOutcome::Terminal(
            "ach rail requires the operator identity (run origin-identity keygen) — refusing to send an unsigned payment".to_string(),
        ));
    };
    let signer = crate::x402::HybridSigner::new(keys);

    // Fetch payment requirements from the ACH facilitator.
    let (status, headers, _) =
        crate::x402::http_get_public(&order.to, &[]).map_err(|e| match e {
            Error::RailUnavailable { .. } => SettleOutcome::Retryable(e.to_string()),
            other => SettleOutcome::Terminal(other.to_string()),
        })?;
    if status != 402 {
        return Err(SettleOutcome::Terminal(format!(
            "expected 402 Payment Required from ACH facilitator, got HTTP {status}"
        )));
    }
    let req_raw = headers.get(crate::x402::PAYMENT_REQUIRED).ok_or_else(|| {
        SettleOutcome::Terminal("402 response missing PAYMENT-REQUIRED header".to_string())
    })?;
    let requirements = crate::x402::parse_requirements(req_raw)
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    let payload = crate::x402::build_signed_payload(&signer, &requirements, &order.to)
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;

    // 1. verify — cheap pre-settle gate.
    match crate::x402::verify_signed_payload(&payload, &order.to, Some(&order.amount)) {
        crate::x402::VerifyVerdict::Accept => {}
        crate::x402::VerifyVerdict::Reject(reason) => {
            return Err(SettleOutcome::Terminal(format!(
                "ach verify rejected: {reason}"
            )))
        }
    }
    let verified = crate::x402::facilitator_verify(&cfg, &payload, &requirements, &order.to)
        .map_err(|e| SettleOutcome::Retryable(e.to_string()))?;
    if !verified {
        return Err(SettleOutcome::Terminal(
            "ACH facilitator /verify rejected the payment".to_string(),
        ));
    }

    // 2. settle — the bank-rail money move.
    match crate::x402::facilitator_settle(&cfg, &payload, &requirements, &order.to)
        .map_err(|e| SettleOutcome::Retryable(e.to_string()))?
    {
        crate::x402::FacilitatorSettleOutcome::Settled { receipt } => {
            // Rail-level dedupe.
            let receipt_hash = origin_crypto_sdk::sha3_256(&receipt);
            if store
                .is_receipt_settled(&receipt_hash)
                .map_err(|e| SettleOutcome::Terminal(e.to_string()))?
            {
                return Err(SettleOutcome::Terminal(
                    "duplicate settlement: ACH receipt already settled for another order"
                        .to_string(),
                ));
            }

            // Extract the settlement reference from the receipt JSON.
            let settlement_ref = serde_json::from_slice::<serde_json::Value>(&receipt)
                .ok()
                .and_then(|v| v.get("settlement_ref").or(v.get("transaction")).cloned())
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default();

            journal::append_order_batch(
                store,
                &order.payment_order_id,
                &order.amount,
                &order.currency,
                order.fx.as_ref(),
                journal_signer,
            )
            .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;

            order.receipt = Some(RailReceipt::Ach {
                settlement_ref,
                auth: receipt,
            });
            order
                .transition(OrderStatus::Success)
                .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
            order.ledger_updated = true;
            order.wallet_updated = false;
            store
                .update_order(order)
                .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
            store
                .record_receipt_hash(&order.payment_order_id, &receipt_hash)
                .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
            store
                .append_notification(&Notification {
                    notification_id: uuid::Uuid::new_v4().to_string(),
                    payment_order_id: order.payment_order_id.clone(),
                    event: format!("order_settled ({})", order.direction),
                    created_at: crate::now_rfc3339(),
                })
                .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
            audit::record(
                store,
                AT_ORDER_SETTLED,
                serde_json::json!({
                    "order": order.payment_order_id,
                    "amount": order.amount,
                    "currency": order.currency,
                    "rail": "ach",
                }),
                None,
            )
            .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
            Ok(())
        }
        crate::x402::FacilitatorSettleOutcome::Pending {
            transaction,
            retry_after,
        } => Err(SettleOutcome::RequiresAction(format!(
            "ACH settlement_pending tx={}{}",
            transaction.unwrap_or_default(),
            retry_after
                .map(|r| format!(" retry-after={r}s"))
                .unwrap_or_default(),
        ))),
        crate::x402::FacilitatorSettleOutcome::Rejected { error, retry_after } => {
            if let Some(secs) = retry_after {
                Err(SettleOutcome::Retryable(format!(
                    "ACH facilitator /settle rejected: {error} (retry-after={secs}s)"
                )))
            } else {
                Err(SettleOutcome::Terminal(format!(
                    "ACH facilitator /settle rejected: {error}"
                )))
            }
        }
    }
}

/// Execute one order on the native rail: pay from the wallet, encode the
/// receipt, post the journal batch, and settle the order.
async fn settle_native(
    wallet: &mut origin_wallet::Wallet,
    store: &PaymentStore,
    order: &mut PaymentOrder,
    peer_addr: Option<SocketAddr>,
    amount: u64,
    peer_credit: Option<u64>,
    signer: Option<&OperatorKeys>,
) -> std::result::Result<(), SettleOutcome> {
    // The native rail dials the payee's standing node — required for
    // native orders only (http402/card passes never need it).
    let peer_addr = peer_addr.ok_or_else(|| {
        SettleOutcome::Terminal("native rail requires --peer-addr <ADDR>".to_string())
    })?;
    let to: origin_wallet::MeshId = order
        .to
        .parse()
        .map_err(|e| SettleOutcome::Terminal(format!("order.to is not a 64-hex MeshId: {e}")))?;

    let entry = origin_wallet::network::pay_native_with_credit(
        wallet,
        to,
        peer_addr,
        amount,
        order.checkout_id.clone().into_bytes(),
        Some(amount), // per-call spend cap = the amount itself
        peer_credit,
    )
    .await
    .map_err(|e| SettleOutcome::Retryable(e.to_string()))?;

    // The receipt is the encoded ENTRY_RECEIPT — verifiable against the
    // gossiped ledger (Stoa §10.1).
    let encoded = origin_wallet::encode_ledger_entry(&entry)
        .map_err(|e| SettleOutcome::Terminal(format!("encoding ledger entry: {e}")))?;

    // Double-entry journal: every batch sums to zero. Pay-out legs mirror
    // pay-in legs (merchant balance ↔ counterparty); the direction on the
    // order labels the accounting and the notification.
    journal::append_order_batch(
        store,
        &order.payment_order_id,
        &order.amount,
        &order.currency,
        order.fx.as_ref(),
        signer,
    )
    .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;

    order.receipt = Some(RailReceipt::Native {
        ledger_entry: encoded,
    });
    order
        .transition(OrderStatus::Success)
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    order.ledger_updated = true;
    order.wallet_updated = true;
    store
        .update_order(order)
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    store
        .append_notification(&Notification {
            notification_id: uuid::Uuid::new_v4().to_string(),
            payment_order_id: order.payment_order_id.clone(),
            event: format!("order_settled ({})", order.direction),
            created_at: crate::now_rfc3339(),
        })
        .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    audit::record(
        store,
        AT_ORDER_SETTLED,
        serde_json::json!({
            "order": order.payment_order_id,
            "amount": order.amount,
            "currency": order.currency,
            "direction": order.direction.to_string(),
            "to": order.to,
        }),
        None,
    )
    .map_err(|e| SettleOutcome::Terminal(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::PaymentOrder;
    use crate::store::PaymentsConfig;

    fn tmp_store() -> PaymentStore {
        let dir = tempfile::tempdir().unwrap();
        PaymentStore::open(&dir.keep()).unwrap()
    }

    fn executing_order(id: &str, since: &str) -> PaymentOrder {
        let mut o = PaymentOrder::new("c", "mesh", "1.00", "USD");
        o.payment_order_id = id.to_string();
        o.transition(OrderStatus::Executing).unwrap();
        o.executing_since = Some(since.to_string());
        o
    }

    #[test]
    fn ttl_sweep_requeues_stale_executing_orders() {
        let s = tmp_store();
        let stale = executing_order("stale", "2000-01-01T00:00:00Z");
        s.insert_order(&stale).unwrap();
        let fresh = executing_order("fresh", &crate::now_rfc3339());
        s.insert_order(&fresh).unwrap();

        let config = PaymentsConfig::default();
        let (requeued, dlqed) = requeue_stuck_executing(&s, &config).unwrap();
        assert_eq!(requeued, 1);
        assert_eq!(dlqed, 0);

        let stale_now = s.get_order("stale").unwrap();
        assert_eq!(stale_now.status, OrderStatus::NotStarted);
        assert!(stale_now.executing_since.is_none(), "TTL anchor cleared");
        assert_eq!(stale_now.attempts, 1);

        // The fresh order is untouched.
        assert_eq!(s.get_order("fresh").unwrap().status, OrderStatus::Executing);

        // The requeue is audited.
        assert!(s
            .audit_records()
            .unwrap()
            .iter()
            .any(|r| r.entry_type == audit::AT_ORDER_REQUEUED));
    }

    #[test]
    fn ttl_sweep_dlqs_when_attempts_exhausted() {
        let s = tmp_store();
        let mut o = executing_order("stuck", "2000-01-01T00:00:00Z");
        o.attempts = 5; // == max_attempts
        s.insert_order(&o).unwrap();

        let config = PaymentsConfig::default();
        let (requeued, dlqed) = requeue_stuck_executing(&s, &config).unwrap();
        assert_eq!(requeued, 0);
        assert_eq!(dlqed, 1);
        assert_eq!(s.get_order("stuck").unwrap().status, OrderStatus::Failed);
        assert_eq!(s.dlq_records().unwrap().len(), 1);
    }

    #[test]
    fn ttl_sweep_leaves_unparseable_timestamps_alone() {
        let s = tmp_store();
        let o = executing_order("weird", "not-a-timestamp");
        s.insert_order(&o).unwrap();

        let config = PaymentsConfig::default();
        let (requeued, dlqed) = requeue_stuck_executing(&s, &config).unwrap();
        assert_eq!((requeued, dlqed), (0, 0));
        assert_eq!(s.get_order("weird").unwrap().status, OrderStatus::Executing);
    }

    #[test]
    fn rollup_progresses_event_lifecycle() {
        let s = tmp_store();
        let mut o1 = PaymentOrder::new("c", "mesh", "1.00", "USD");
        o1.payment_order_id = "o1".into();
        let mut o2 = PaymentOrder::new("c", "mesh", "2.00", "USD");
        o2.payment_order_id = "o2".into();
        s.insert_order(&o1).unwrap();
        s.insert_order(&o2).unwrap();
        let event =
            crate::event::PaymentEvent::new("c", "buyer", "merchant", vec![o1.clone(), o2.clone()]);
        s.append_event(&event).unwrap();

        // Nothing started → Received.
        rollup_event(&s, "o1").unwrap();
        assert_eq!(
            s.latest_event(&event.event_id).unwrap().status,
            EventStatus::Received
        );

        // One settles → the event is Split (other order still waiting).
        let mut o1 = s.get_order("o1").unwrap();
        o1.transition(OrderStatus::Executing).unwrap();
        o1.transition(OrderStatus::Success).unwrap();
        s.update_order(&o1).unwrap();
        rollup_event(&s, "o1").unwrap();
        assert_eq!(
            s.latest_event(&event.event_id).unwrap().status,
            EventStatus::Split
        );

        // Both settle → AllSettled.
        let mut o2 = s.get_order("o2").unwrap();
        o2.transition(OrderStatus::Executing).unwrap();
        o2.transition(OrderStatus::Success).unwrap();
        s.update_order(&o2).unwrap();
        rollup_event(&s, "o2").unwrap();
        assert_eq!(
            s.latest_event(&event.event_id).unwrap().status,
            EventStatus::AllSettled
        );
    }

    #[test]
    fn rollup_marks_partial_on_failure() {
        let s = tmp_store();
        let mut o1 = PaymentOrder::new("c", "mesh", "1.00", "USD");
        o1.payment_order_id = "o1".into();
        s.insert_order(&o1).unwrap();
        let event = crate::event::PaymentEvent::new("c", "buyer", "merchant", vec![o1.clone()]);
        s.append_event(&event).unwrap();

        let mut o1 = s.get_order("o1").unwrap();
        o1.transition(OrderStatus::Failed).unwrap();
        s.update_order(&o1).unwrap();
        rollup_event(&s, "o1").unwrap();
        assert_eq!(
            s.latest_event(&event.event_id).unwrap().status,
            EventStatus::Partial
        );
        // Rollup snapshots are unsigned coordination records.
        let e = s.latest_event(&event.event_id).unwrap();
        assert!(e.signature.is_none());
        assert!(e.envelope.is_none());
    }

    #[test]
    fn http402_rail_refuses_to_pay_without_operator_identity() {
        let s = tmp_store();
        let mut order = PaymentOrder::new("c", "http://127.0.0.1:1/x", "1.00", "USD");
        order.rail = Some(RailHint::Http402);
        let err = settle_http402(&s, &mut order, None).unwrap_err();
        match err {
            SettleOutcome::Terminal(msg) => {
                assert!(
                    msg.contains("unsigned"),
                    "refusal names the unsigned payment: {msg}"
                )
            }
            other => panic!("expected Terminal, got {other:?}"),
        }
        // Nothing journaled, nothing sent.
        assert!(s.postings().unwrap().is_empty());
    }

    #[test]
    fn rollup_is_noop_for_orders_without_events() {
        let s = tmp_store();
        let o = PaymentOrder::new("c", "mesh", "1.00", "USD");
        s.insert_order(&o).unwrap();
        rollup_event(&s, &o.payment_order_id).unwrap(); // no panic
    }

    /// Build a genuine signed x402 authorization bound to `url` (the same
    /// fixture shape `settle` uses), so the deferred-commit path can
    /// verify it.
    fn signed_payload(url: &str) -> Vec<u8> {
        use crate::x402::PaymentSigner;
        let dir = tempfile::tempdir().unwrap();
        let home = origin_common::OriginHome::with_root(dir.path().join("home")).unwrap();
        let _store = origin_common::IdentityStore::create(
            &home,
            "test-pass",
            origin_common::MemoryTier::Nano,
        )
        .unwrap();
        let keys = crate::identity::load_operator_keys_from(&home, "test-pass").unwrap();
        let signer = crate::x402::HybridSigner::new(&keys);
        let req = crate::x402::PaymentRequirements {
            accepts: vec![crate::x402::PaymentOption {
                scheme: "exact".to_string(),
                network: "eip155:8453".to_string(),
                pay_to: "0xMerchant".to_string(),
                amount: "100".to_string(),
                max_timeout_secs: Some(300),
                payment_details: serde_json::json!({}),
            }],
        };
        signer.sign(&req, url).unwrap()
    }

    #[test]
    fn deferred_commit_batches_pending_and_refuses_forged() {
        let s = tmp_store();
        let url = "http://127.0.0.1:9999/paid";
        let good = signed_payload(url);
        s.append_deferred_commitment(&crate::settle::DeferredItem {
            payment_order_id: "o1".to_string(),
            amount: "1.00".to_string(),
            currency: "USD".to_string(),
            signed_payload: good.clone(),
            resource_url: url.to_string(),
        })
        .unwrap();
        // A forged commitment for another resource is also pending; the
        // commit pass must refuse it and NOT clear the queue.
        s.append_deferred_commitment(&crate::settle::DeferredItem {
            payment_order_id: "o2".to_string(),
            amount: "1.00".to_string(),
            currency: "USD".to_string(),
            signed_payload: good,
            resource_url: "http://elsewhere/paid".to_string(),
        })
        .unwrap();

        let err = crate::settle::commit_deferred_batch(&s, "2026-08-23").unwrap_err();
        assert!(matches!(err, Error::ReceiptVerificationFailed { .. }));
        // Nothing was admitted or cleared on refusal.
        assert_eq!(s.deferred_commitments().unwrap().len(), 2);

        // Remove the forged item, then the batch commits and clears.
        let mut pending = s.deferred_commitments().unwrap();
        pending.retain(|i| i.payment_order_id == "o1");
        let only_one = pending;
        s.clear_deferred_commitments().unwrap();
        for i in &only_one {
            s.append_deferred_commitment(i).unwrap();
        }
        let batch = crate::settle::commit_deferred_batch(&s, "2026-08-23").unwrap();
        assert_eq!(batch.items.len(), 1);
        assert_eq!(batch.total_minor, 100);
        assert!(
            s.deferred_commitments().unwrap().is_empty(),
            "queue cleared"
        );
        // The committed batch is a leaf in the checkpoint MMR.
        let mmr = s.load_mmr().unwrap();
        assert_eq!(mmr.leaf_count(), 1);
        let proof = mmr.prove(0).unwrap();
        assert!(mmr.verify_proof(&proof, &mmr.root()));
    }
}

/// Terminal failure: FAILED + DLQ record with the evidence.
fn mark_failed(store: &PaymentStore, order: &mut PaymentOrder, reason: &str) -> Result<()> {
    order.transition(OrderStatus::Failed)?;
    store.update_order(order)?;
    store.append_dlq(&DlqRecord {
        payment_order_id: order.payment_order_id.clone(),
        reason: reason.to_string(),
        evidence: serde_json::json!({
            "rail": "native",
            "status": order.status.to_string(),
            "attempts": order.attempts,
        }),
        created_at: crate::now_rfc3339(),
    })?;
    store.append_notification(&Notification {
        notification_id: uuid::Uuid::new_v4().to_string(),
        payment_order_id: order.payment_order_id.clone(),
        event: format!("order_failed: {reason}"),
        created_at: crate::now_rfc3339(),
    })?;
    audit::record(
        store,
        AT_ORDER_FAILED,
        serde_json::json!({ "order": order.payment_order_id, "reason": reason }),
        None,
    )?;
    Ok(())
}
