// SPDX-License-Identifier: Apache-2.0

//! Payment events and orders — the coordination layer (design §4.1, §5).
//!
//! [`PaymentOrder::payment_order_id`] is THE idempotency key: the store
//! rejects a duplicate and returns the existing order, so a replayed
//! checkout can never double-execute.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::OrderSigner;
use crate::rails::RailHint;

/// Lifecycle of a payment event (one checkout, many orders).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventStatus {
    /// Received, not yet split into orders.
    Received,
    /// Split into payment orders; the executor is working through them.
    Split,
    /// Every order settled.
    AllSettled,
    /// Some orders settled, some failed / awaiting action.
    Partial,
}

/// Money direction: pay-in (buyer → merchant) or pay-out (merchant →
/// seller). Both settle through the same executor; the direction labels
/// the accounting (P6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderDirection {
    Payment,
    Payout,
}

impl std::fmt::Display for OrderDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OrderDirection::Payment => "payment",
            OrderDirection::Payout => "payout",
        })
    }
}

/// Status of a single payment order (design §5; wire names per Chapter 26).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrderStatus {
    /// Awaiting the executor.
    NotStarted,
    /// Marked BEFORE any rail call so a crash mid-flight is recoverable.
    Executing,
    /// Settled: journal + wallet updated.
    Success,
    /// Terminal failure — DLQ'd.
    Failed,
    /// 3DS / risk review / awaiting an async rail webhook.
    RequiresAction,
}

impl OrderStatus {
    /// The legal transition table (design §4.3).
    ///
    /// `EXECUTING → NOT_STARTED` is the crash-recovery TTL-sweep path:
    /// an order stuck in `EXECUTING` past its TTL is re-queued (bounded by
    /// `max_attempts`, after which it is DLQ'd instead).
    pub fn can_transition(from: OrderStatus, to: OrderStatus) -> bool {
        use OrderStatus::*;
        matches!(
            (from, to),
            (NotStarted, Executing | Failed | RequiresAction)
                | (Executing, Success | Failed | RequiresAction | NotStarted)
                | (RequiresAction, Executing | Failed | NotStarted)
                | (Failed, Executing | NotStarted)
        )
    }

    /// True when no further transition is legal (settled terminal state).
    pub fn is_terminal(self) -> bool {
        self == OrderStatus::Success
    }
}

impl EventStatus {
    /// Roll the event lifecycle up from its orders' current statuses:
    /// all settled, some failed/awaiting action (partial), any in flight
    /// (split), or everything still waiting (received).
    pub fn rollup(orders: &[PaymentOrder]) -> EventStatus {
        use EventStatus::*;
        if orders.is_empty() {
            return Received;
        }
        if orders.iter().all(|o| o.status == OrderStatus::Success) {
            return AllSettled;
        }
        if orders
            .iter()
            .any(|o| matches!(o.status, OrderStatus::Failed | OrderStatus::RequiresAction))
        {
            return Partial;
        }
        if orders.iter().any(|o| o.status != OrderStatus::NotStarted) {
            return Split;
        }
        Received
    }
}

impl std::fmt::Display for OrderStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OrderStatus::NotStarted => "NOT_STARTED",
            OrderStatus::Executing => "EXECUTING",
            OrderStatus::Success => "SUCCESS",
            OrderStatus::Failed => "FAILED",
            OrderStatus::RequiresAction => "REQUIRES_ACTION",
        })
    }
}

/// One money movement. `payment_order_id` is THE idempotency key (unique
/// at the store).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentOrder {
    pub version: u8,
    pub payment_order_id: String,
    pub checkout_id: String,
    /// MeshId or stealth address — part of the signed body.
    pub to: String,
    /// Decimal string, never a float (Chapter 26 rule).
    pub amount: String,
    pub currency: String,
    /// Optional FX conversion: `amount` is quoted in `currency`, but the
    /// merchant settles in `fx.to` at `fx.rate` (1 `from` = `rate` `to`).
    /// When set, the executor posts an FX batch (P9) instead of a plain
    /// single-currency batch. `None` = no conversion.
    #[serde(default)]
    pub fx: Option<crate::journal::FxRate>,
    /// Card tokenization (card rail): the PSP-issued token reference +
    /// network + last4 display hint. Never the PAN — PCI out of scope by
    /// design. All three are set together by `order-create --card-*`.
    #[serde(default)]
    pub card_token: Option<String>,
    #[serde(default)]
    pub card_network: Option<String>,
    #[serde(default)]
    pub card_last4: Option<String>,
    /// Rail hint; `None` = smart routing (cheapest-first).
    pub rail: Option<RailHint>,
    pub direction: OrderDirection,
    pub status: OrderStatus,
    pub ledger_updated: bool,
    pub wallet_updated: bool,
    pub attempts: u32,
    pub next_retry_at: Option<String>,
    /// Crash-recovery TTL anchor: set when the order enters EXECUTING.
    pub executing_since: Option<String>,
    pub receipt: Option<crate::rails::RailReceipt>,
    pub created_at: String,
    pub updated_at: String,
    /// Hybrid (Ed25519 + Falcon-1024) signature over `signed_body()`, in
    /// the SDK `HybridSig` wire format (P2). `None` = unsigned.
    pub signature: Option<Vec<u8>>,
    /// Signer public keys, embedded so verification works offline (the
    /// origin-secrets pattern).
    pub signer: Option<OrderSigner>,
}

impl PaymentOrder {
    /// A fresh order in `NOT_STARTED` with a new idempotency key.
    pub fn new(checkout_id: &str, to: &str, amount: &str, currency: &str) -> Self {
        let now = crate::now_rfc3339();
        PaymentOrder {
            version: 1,
            payment_order_id: uuid::Uuid::new_v4().to_string(),
            checkout_id: checkout_id.to_string(),
            to: to.to_string(),
            amount: amount.to_string(),
            currency: currency.to_string(),
            fx: None,
            card_token: None,
            card_network: None,
            card_last4: None,
            rail: None,
            direction: OrderDirection::Payment,
            status: OrderStatus::NotStarted,
            ledger_updated: false,
            wallet_updated: false,
            attempts: 0,
            next_retry_at: None,
            executing_since: None,
            receipt: None,
            created_at: now.clone(),
            updated_at: now,
            signature: None,
            signer: None,
        }
    }

    /// Transition with legality enforcement; bumps `updated_at`.
    pub fn transition(&mut self, to: OrderStatus) -> Result<()> {
        if !OrderStatus::can_transition(self.status, to) {
            return Err(Error::InvalidTransition {
                from: self.status.to_string(),
                to: to.to_string(),
            });
        }
        self.status = to;
        self.updated_at = crate::now_rfc3339();
        Ok(())
    }

    /// The exact bytes a hybrid signature must cover (wired in P2).
    pub fn signed_body(&self) -> Vec<u8> {
        // version ‖ order_id ‖ checkout ‖ to ‖ amount ‖ currency ‖ rail
        let mut b = Vec::new();
        b.push(self.version);
        b.extend_from_slice(self.payment_order_id.as_bytes());
        b.extend_from_slice(self.checkout_id.as_bytes());
        b.extend_from_slice(self.to.as_bytes());
        b.extend_from_slice(self.amount.as_bytes());
        b.extend_from_slice(self.currency.as_bytes());
        match &self.fx {
            Some(fx) => {
                b.push(0x01);
                b.extend_from_slice(fx.from.as_bytes());
                b.extend_from_slice(fx.to.as_bytes());
                b.extend_from_slice(fx.rate.as_bytes());
                // Markup in basis points — the merchant's signed margin.
                b.extend_from_slice(&fx.markup_bps.to_le_bytes());
            }
            None => b.push(0x00),
        }
        match self.rail {
            Some(r) => {
                b.push(0x01);
                b.extend_from_slice(r.as_str().as_bytes());
            }
            None => b.push(0x00),
        }
        b
    }
}

/// A checkout: one buyer action, many payment orders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentEvent {
    pub version: u8,
    pub event_id: String,
    pub checkout_id: String,
    pub buyer: String,
    pub seller: String,
    pub payment_orders: Vec<PaymentOrder>,
    pub status: EventStatus,
    pub created_at: String,
    /// Serialized origin-common Envelope (AEAD) of the event body —
    /// wired in P2 once an encryption key is available from the operator
    /// identity.
    pub envelope: Option<Vec<u8>>,
    /// Hybrid signature over the event body (P2).
    pub signature: Option<Vec<u8>>,
    /// Signer public keys (P2).
    pub signer: Option<OrderSigner>,
}

impl PaymentEvent {
    pub fn new(checkout_id: &str, buyer: &str, seller: &str, orders: Vec<PaymentOrder>) -> Self {
        PaymentEvent {
            version: 1,
            event_id: uuid::Uuid::new_v4().to_string(),
            checkout_id: checkout_id.to_string(),
            buyer: buyer.to_string(),
            seller: seller.to_string(),
            payment_orders: orders,
            status: EventStatus::Received,
            created_at: crate::now_rfc3339(),
            envelope: None,
            signature: None,
            signer: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_transitions() {
        use OrderStatus::*;
        assert!(OrderStatus::can_transition(NotStarted, Executing));
        assert!(OrderStatus::can_transition(NotStarted, Failed));
        assert!(OrderStatus::can_transition(NotStarted, RequiresAction));
        assert!(OrderStatus::can_transition(Executing, Success));
        assert!(OrderStatus::can_transition(Executing, Failed));
        assert!(OrderStatus::can_transition(Executing, RequiresAction));
        assert!(OrderStatus::can_transition(RequiresAction, Executing));
        assert!(OrderStatus::can_transition(RequiresAction, Failed));
        assert!(OrderStatus::can_transition(RequiresAction, NotStarted));
        assert!(OrderStatus::can_transition(Failed, Executing));
        assert!(OrderStatus::can_transition(Failed, NotStarted));
    }

    #[test]
    fn illegal_transitions_rejected() {
        use OrderStatus::*;
        // No skipping: NOT_STARTED cannot jump straight to SUCCESS.
        assert!(!OrderStatus::can_transition(NotStarted, Success));
        // SUCCESS is terminal.
        assert!(!OrderStatus::can_transition(Success, Executing));
        assert!(!OrderStatus::can_transition(Success, Failed));
        // Same-state transitions are not legal.
        assert!(!OrderStatus::can_transition(NotStarted, NotStarted));
        assert!(!OrderStatus::can_transition(Executing, Executing));
    }

    #[test]
    fn transition_updates_status_and_ts() {
        let mut o = PaymentOrder::new("c1", "mesh-1", "3.15", "USD");
        assert_eq!(o.status, OrderStatus::NotStarted);
        o.transition(OrderStatus::Executing).unwrap();
        assert_eq!(o.status, OrderStatus::Executing);
        o.transition(OrderStatus::Success).unwrap();
        assert!(o.status.is_terminal());
        let err = o.transition(OrderStatus::Executing).unwrap_err();
        assert!(matches!(err, Error::InvalidTransition { .. }));
    }

    #[test]
    fn wire_names_match_design() {
        assert_eq!(OrderStatus::NotStarted.to_string(), "NOT_STARTED");
        assert_eq!(OrderStatus::RequiresAction.to_string(), "REQUIRES_ACTION");
        assert_eq!(
            serde_json::to_string(&OrderStatus::Executing).unwrap(),
            "\"EXECUTING\""
        );
        assert_eq!(
            serde_json::to_string(&OrderStatus::RequiresAction).unwrap(),
            "\"REQUIRES_ACTION\""
        );
    }

    #[test]
    fn fresh_order_is_not_started_with_uuid() {
        let o = PaymentOrder::new("c1", "mesh-1", "1.00", "USD");
        assert_eq!(o.status, OrderStatus::NotStarted);
        assert_eq!(o.attempts, 0);
        assert!(!o.payment_order_id.is_empty());
        // uuid v4 shape: 8-4-4-4-12
        assert_eq!(o.payment_order_id.split('-').count(), 5);
    }

    #[test]
    fn signed_body_is_deterministic() {
        let o = PaymentOrder::new("c1", "mesh-1", "1.00", "USD");
        let b1 = o.signed_body();
        let b2 = o.signed_body();
        assert_eq!(b1, b2);
        // The amount bytes appear inside the signed body.
        assert!(b1.windows(o.amount.len()).any(|w| w == o.amount.as_bytes()));
    }
}
