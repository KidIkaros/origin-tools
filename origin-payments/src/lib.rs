// SPDX-License-Identifier: Apache-2.0

//! # Origin Payments
//!
//! The payment backend for the Origin economy (design:
//! [`PAYMENT_SYSTEM_DESIGN.md`](../PAYMENT_SYSTEM_DESIGN.md)) — the
//! coordinator that turns a checkout into settled money movement.
//!
//! Composes the sibling origin-tools crates and `origin-crypto-sdk`: no
//! crypto of its own, one home directory. The Stoa pay surface (native
//! channels, x402, card ACP) is reached through `origin-wallet`.
//!
//! Phases shipped: store + status machine (P1), journal (P2), native-rail
//! executor (P3), retries + rail routing + REQUIRES_ACTION (P4),
//! reconciliation + MMR checkpoints (P5), pay-out + notifications + spend
//! policy (P6), audit + compliance exports + K-of-N custody + TOTP 2FA
//! (P7), x402 V2 + card ACP rails (P8/P11), multi-currency FX (P9),
//! deferred settlement (P10), ACH/SEPA fiat rail (P13), rail-level
//! receipt dedupe cache (P12), merchant settlement preference (P14),
//! compliance scoring interface (P15/P16), deferred CLI (P17),
//! Retry-After parsing (P18), webhook receiver (P19), FX markup_bps
//! (P20), settlement preference payout (P21), CLI amount validation
//! (P22).

pub mod audit;
pub mod card;
pub mod cli;
pub mod commands;
pub mod compliance;
pub mod custody;
pub mod error;
pub mod event;
pub mod executor;
pub mod identity;
pub mod journal;
pub mod proof;
pub mod rails;
pub mod reconcile;
pub mod retry;
pub mod settle;
pub mod status;
pub mod store;
pub mod twofa;
pub mod vault;
pub mod webhook;
pub mod x402;

pub use compliance::{AcceptAll, ComplianceScorer, ComplianceVerdict, RuleBasedScorer};
pub use error::{Error, Result};
pub use event::{EventStatus, OrderDirection, OrderStatus, PaymentEvent, PaymentOrder};
pub use identity::{OperatorKeys, OrderSigner};
pub use journal::{Account, LedgerPosting};
pub use proof::{CheckpointMmr, MembershipProof};
pub use rails::{PaymentScheme, Rail, RailHint, RailReceipt};
pub use reconcile::{
    MismatchClass, ReconcileMismatch, ReconcileRun, ReconcileStatus, SettlementFile, SettlementRow,
};
pub use retry::{is_retryable, next_backoff_ms, schedule_retry};
pub use settle::{DeferredBatch, DeferredItem};
pub use store::{
    DlqRecord, InsertOutcome, Notification, PaymentStore, PaymentsConfig, RetryJob, RetryPolicy,
};

/// ISO 8601 (RFC 3339) UTC timestamp used across events, orders, and
/// postings.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// The default payments root: `~/.origin/payments` (or `$ORIGIN_HOME`).
///
/// Honors `--home` when supplied.
pub fn payments_root(cli_home: Option<&std::path::Path>) -> Result<std::path::PathBuf> {
    match cli_home {
        Some(p) => Ok(p.to_path_buf()),
        None => {
            let home = origin_common::OriginHome::load().map_err(|e| Error::IoError {
                details: format!("loading origin home: {e}"),
            })?;
            Ok(home.root().join("payments"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_rfc3339() {
        let ts = now_rfc3339();
        assert!(
            ts.ends_with('Z') || ts.contains('+'),
            "UTC offset expected in {ts}"
        );
        assert!(ts.contains('T'), "date-time separator expected in {ts}");
    }
}
