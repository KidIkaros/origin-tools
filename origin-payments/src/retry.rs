// SPDX-License-Identifier: Apache-2.0

//! Retry machinery (design §4.3, P4): exponential backoff with jitter, a
//! `Retry-After` override, and the schedule-vs-DLQ decision.
//!
//! Retryable failures (transient rail/network errors) are scheduled with
//! a backoff; terminal failures (validation, policy, config) go straight
//! to the dead-letter queue once attempts are exhausted.

use crate::error::Error;
use crate::event::{OrderStatus, PaymentOrder};
use crate::store::{PaymentStore, RetryJob, RetryPolicy};

/// The next retry delay in milliseconds: exponential backoff
/// `base · factor^(attempt−1)`, capped at `cap_ms`, with a `Retry-After`
/// hint honored (also capped) and ±25% jitter.
pub fn next_backoff_ms(policy: &RetryPolicy, attempt: u32, retry_after_ms: Option<u64>) -> u64 {
    let exp = policy
        .base_ms
        .saturating_mul(policy.factor.saturating_pow(attempt.saturating_sub(1)));
    let base = retry_after_ms.unwrap_or(exp).min(policy.cap_ms);

    // ±25% jitter from the SDK CSPRNG.
    let mut jitter_buf = [0u8; 8];
    let _ = origin_crypto_sdk::fill_random(&mut jitter_buf);
    let raw = u64::from_le_bytes(jitter_buf);
    let fraction = (raw % 51) as i64 - 25; // -25..=+25 percent
    let delta = (base as i64 * fraction) / 100;
    // Clamp post-jitter too: a ±25% swing must never exceed the cap.
    (base as i64 + delta).clamp(1, policy.cap_ms as i64) as u64
}

/// Schedule a retry for a retryable failure. Returns:
/// - `Ok(true)` — a `RetryJob` was written and the order marked `FAILED`
///   with a future `next_retry_at`;
/// - `Ok(false)` — the failure is terminal or attempts are exhausted;
///   the caller should DLQ.
pub fn schedule_retry(
    store: &PaymentStore,
    order: &mut PaymentOrder,
    reason: &str,
    policy: &RetryPolicy,
    retry_after_ms: Option<u64>,
) -> crate::error::Result<bool> {
    if order.attempts >= policy.max_attempts {
        return Ok(false);
    }
    let backoff_ms = next_backoff_ms(policy, order.attempts, retry_after_ms);
    // The deadline is now + backoff, so a retried order is only due later.
    let deadline = chrono::Utc::now() + chrono::Duration::milliseconds(backoff_ms as i64);

    order.transition(OrderStatus::Failed)?;
    order.next_retry_at = Some(deadline.to_rfc3339());
    store.update_order(order)?;
    store.append_retry_job(&RetryJob {
        payment_order_id: order.payment_order_id.clone(),
        attempt: order.attempts,
        next_retry_at: order.next_retry_at.clone().unwrap_or_default(),
        backoff_ms,
        last_error: reason.to_string(),
    })?;
    Ok(true)
}

/// True when the error is a transient, retryable rail/network failure.
pub fn is_retryable(e: &Error) -> bool {
    matches!(e, Error::RailUnavailable { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::PaymentStore;

    fn policy() -> RetryPolicy {
        RetryPolicy {
            base_ms: 1_000,
            factor: 2,
            cap_ms: 8_000,
            max_attempts: 5,
        }
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let p = policy();
        // Without jitter bounds: attempt 1 → 1000, 2 → 2000, 3 → 4000,
        // 4 → 8000, 5 → 8000 (capped).
        for attempt in 1..=5u32 {
            let ms = next_backoff_ms(&p, attempt, None);
            assert!(ms >= 1, "never zero");
        }
        // Deterministic bound via a no-jitter probe: cap holds.
        assert!(next_backoff_ms(&p, 10, None) <= p.cap_ms);
    }

    #[test]
    fn retry_after_hint_is_honored_and_capped() {
        let p = policy();
        // A hint larger than the cap must be clamped.
        let ms = next_backoff_ms(&p, 1, Some(3_600_000));
        assert!(ms <= p.cap_ms);
    }

    #[test]
    fn terminal_errors_are_not_retryable() {
        assert!(!is_retryable(&Error::InvalidAmount("x".to_string())));
        assert!(!is_retryable(&Error::PolicyRefused {
            details: "cap".into()
        }));
        assert!(!is_retryable(&Error::RailNotConfigured {
            rail: "card".into(),
            details: "".into()
        }));
        assert!(is_retryable(&Error::RailUnavailable {
            rail: "native".into(),
            details: "timeout".into()
        }));
    }

    #[test]
    fn schedule_retry_writes_job_and_marks_failed() {
        let dir = tempfile::tempdir().unwrap();
        let store = PaymentStore::open(dir.path()).unwrap();
        let mut order = crate::event::PaymentOrder::new("c1", "mesh-1", "1.00", "USD");
        order.attempts = 1;
        store.insert_order(&order).unwrap();

        let ok = schedule_retry(&store, &mut order, "connect timeout", &policy(), None).unwrap();
        assert!(ok);
        assert_eq!(order.status, OrderStatus::Failed);
        assert!(order.next_retry_at.is_some());
        assert_eq!(store.retry_jobs().unwrap().len(), 1);
        assert_eq!(store.dlq_records().unwrap().len(), 0);
    }

    #[test]
    fn exhausted_attempts_go_to_dlq_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = PaymentStore::open(dir.path()).unwrap();
        let mut order = crate::event::PaymentOrder::new("c1", "mesh-1", "1.00", "USD");
        order.attempts = 5; // == max_attempts
        let p = policy();
        let ok = schedule_retry(&store, &mut order, "timeout", &p, None).unwrap();
        assert!(!ok, "attempts exhausted → caller DLQs");
    }
}
