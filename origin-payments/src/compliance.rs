// SPDX-License-Identifier: Apache-2.0

//! Compliance scoring interface (research §5 — Fireblocks PSP blueprint:
//! "inbound compliance screening before crediting").
//!
//! A plugin trait for risk-scoring inbound payments against the merchant's
//! trust graph (origin-attest) before crediting. The executor calls
//! `ComplianceScorer::score` before settling each order; a `Reject` verdict
//! sends the order to the DLQ with evidence, a `Flag` adds a note but
//! proceeds, and `Accept` proceeds normally.
//!
//! This is a **plugin interface** — no hard dependency on any specific
//! scoring backend (Chainalysis, Elliptic, etc.). The merchant configures
//! a scorer at init time; the default scorer is `AcceptAll` (no screening).

use crate::error::Result;
use crate::event::PaymentOrder;

/// A verdict from the compliance scorer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComplianceVerdict {
    /// The payment is acceptable — proceed with settlement.
    Accept,
    /// The payment is flagged but not blocked — proceed with a note in the
    /// audit trail. Useful for monitoring low-risk anomalies without
    /// disrupting the flow.
    Flag { reason: String },
    /// The payment is rejected — do not settle; record evidence and send
    /// to the DLQ.
    Reject {
        reason: String,
        evidence: serde_json::Value,
    },
}

/// A compliance scorer that evaluates inbound payments before settlement.
///
/// Implementors plug in risk-scoring logic (trust-graph scoring,
/// Chainalysis/Elliptic API calls, heuristic rules, etc.). The default
/// implementation accepts everything — the merchant enables screening
/// by providing a custom scorer.
pub trait ComplianceScorer {
    /// Score an inbound payment order. Called before the executor settles
    /// each order; the verdict determines whether settlement proceeds.
    fn score(&self, order: &PaymentOrder) -> Result<ComplianceVerdict>;
}

/// Default scorer: accepts all payments (no screening). The merchant
/// replaces this with a real scorer when compliance screening is required.
pub struct AcceptAll;

impl ComplianceScorer for AcceptAll {
    fn score(&self, _order: &PaymentOrder) -> Result<ComplianceVerdict> {
        Ok(ComplianceVerdict::Accept)
    }
}

/// A rule-based scorer that rejects payments exceeding a configurable
/// threshold amount or from untrusted counterparties. This is a minimal
/// example — real implementations would call external APIs.
pub struct RuleBasedScorer {
    /// Payments above this amount (in minor units) are flagged.
    pub flag_threshold_minor: i128,
    /// Payments above this amount (in minor units) are rejected.
    pub reject_threshold_minor: i128,
    /// If set, only payments to these counterparties are accepted.
    pub allowed_counterparties: Option<Vec<String>>,
}

impl ComplianceScorer for RuleBasedScorer {
    fn score(&self, order: &PaymentOrder) -> Result<ComplianceVerdict> {
        let amount = crate::journal::parse_amount(&order.amount).unwrap_or(0);

        // Counterparty allowlist check.
        if let Some(allowed) = &self.allowed_counterparties {
            if !allowed.contains(&order.to) {
                return Ok(ComplianceVerdict::Reject {
                    reason: format!("counterparty {} is not in the allowlist", order.to),
                    evidence: serde_json::json!({
                        "to": order.to,
                        "allowed": allowed,
                    }),
                });
            }
        }

        // Amount threshold checks.
        if amount >= self.reject_threshold_minor {
            return Ok(ComplianceVerdict::Reject {
                reason: format!(
                    "amount {} exceeds reject threshold {}",
                    order.amount, self.reject_threshold_minor
                ),
                evidence: serde_json::json!({
                    "amount": order.amount,
                    "reject_threshold_minor": self.reject_threshold_minor,
                }),
            });
        }
        if amount >= self.flag_threshold_minor {
            return Ok(ComplianceVerdict::Flag {
                reason: format!(
                    "amount {} exceeds flag threshold {}",
                    order.amount, self.flag_threshold_minor
                ),
            });
        }

        Ok(ComplianceVerdict::Accept)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::OrderStatus;

    fn test_order(amount: &str, to: &str) -> PaymentOrder {
        PaymentOrder {
            version: 1,
            payment_order_id: "test-order".to_string(),
            checkout_id: "test".to_string(),
            to: to.to_string(),
            amount: amount.to_string(),
            currency: "USD".to_string(),
            direction: crate::event::OrderDirection::Payment,
            status: OrderStatus::NotStarted,
            rail: None,
            fx: None,
            card_token: None,
            card_network: None,
            card_last4: None,
            receipt: None,
            attempts: 0,
            next_retry_at: None,
            created_at: crate::now_rfc3339(),
            updated_at: crate::now_rfc3339(),
            executing_since: None,
            ledger_updated: false,
            wallet_updated: false,
            signature: None,
            signer: None,
        }
    }

    #[test]
    fn accept_all_always_accepts() {
        let scorer = AcceptAll;
        assert_eq!(
            scorer.score(&test_order("100.00", "peer")).unwrap(),
            ComplianceVerdict::Accept
        );
    }

    #[test]
    fn rule_based_rejects_above_threshold() {
        let scorer = RuleBasedScorer {
            flag_threshold_minor: 5000,
            reject_threshold_minor: 10000,
            allowed_counterparties: None,
        };
        // Below flag threshold.
        assert_eq!(
            scorer.score(&test_order("1.00", "peer")).unwrap(),
            ComplianceVerdict::Accept
        );
        // Above flag, below reject.
        assert!(matches!(
            scorer.score(&test_order("60.00", "peer")).unwrap(),
            ComplianceVerdict::Flag { .. }
        ));
        // Above reject.
        assert!(matches!(
            scorer.score(&test_order("150.00", "peer")).unwrap(),
            ComplianceVerdict::Reject { .. }
        ));
    }

    #[test]
    fn rule_based_respects_counterparty_allowlist() {
        let scorer = RuleBasedScorer {
            flag_threshold_minor: 100_000,
            reject_threshold_minor: 200_000,
            allowed_counterparties: Some(vec!["trusted-peer".to_string()]),
        };
        // Allowed counterparty.
        assert_eq!(
            scorer.score(&test_order("1.00", "trusted-peer")).unwrap(),
            ComplianceVerdict::Accept
        );
        // Unknown counterparty.
        assert!(matches!(
            scorer.score(&test_order("1.00", "unknown")).unwrap(),
            ComplianceVerdict::Reject { .. }
        ));
    }
}
