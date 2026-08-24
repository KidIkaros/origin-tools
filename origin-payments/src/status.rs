// SPDX-License-Identifier: Apache-2.0

//! Ops dashboard (`status`) — one glance at the whole payments root:
//! orders by status, retries + DLQ, journal net, last reconcile run,
//! audit-chain health, and admin posture (2FA / custody). No secrets.

use serde::{Deserialize, Serialize};

use crate::event::OrderStatus;
use crate::journal;
use crate::reconcile::ReconcileStatus;
use crate::store::PaymentStore;

/// Per-status order counts (design §5 wire names).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrderCounts {
    pub not_started: u64,
    pub executing: u64,
    pub success: u64,
    pub failed: u64,
    pub requires_action: u64,
}

/// The dashboard snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub root: String,
    pub initialized: bool,
    pub config: Option<StatusConfig>,
    pub orders: OrderCounts,
    pub retries_due: u64,
    pub retry_jobs: u64,
    pub dlq: u64,
    pub journal_postings: u64,
    /// Net per currency in minor units (always zero when double-entry holds).
    pub journal_net: Vec<(String, i128)>,
    pub reconcile_runs: u64,
    pub last_reconcile: Option<StatusReconcile>,
    pub audit_entries: u64,
    pub audit_chain_valid: Option<bool>,
    pub notifications: u64,
    pub twofa_configured: bool,
    pub custody_vault: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusConfig {
    pub currency: String,
    pub enabled_rails: Vec<String>,
    pub per_tx_cap: Option<String>,
    pub retry: crate::store::RetryPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReconcile {
    pub run_id: String,
    pub date: String,
    pub status: ReconcileStatus,
    pub matches: u64,
    pub mismatches: u64,
}

/// Build the dashboard snapshot for a payments root.
pub fn build(store: &PaymentStore) -> StatusReport {
    let config = store.load_config().ok();
    let initialized = config.is_some() && store.config_path().exists();

    let mut orders = OrderCounts::default();
    if let Ok(all) = store.latest_orders() {
        for o in &all {
            match o.status {
                OrderStatus::NotStarted => orders.not_started += 1,
                OrderStatus::Executing => orders.executing += 1,
                OrderStatus::Success => orders.success += 1,
                OrderStatus::Failed => orders.failed += 1,
                OrderStatus::RequiresAction => orders.requires_action += 1,
            }
        }
    }

    let now = crate::now_rfc3339();
    let (retries_due, retry_jobs) = match store.retry_jobs() {
        Ok(jobs) => (
            jobs.iter()
                .filter(|j| !j.next_retry_at.is_empty() && j.next_retry_at <= now)
                .count() as u64,
            jobs.len() as u64,
        ),
        Err(_) => (0, 0),
    };

    let (journal_postings, journal_net) = match store.postings() {
        Ok(p) => {
            let net = journal::net_by_currency(&p);
            (p.len() as u64, net)
        }
        Err(_) => (0, Vec::new()),
    };

    let (reconcile_runs, last_reconcile) = match crate::reconcile::list(store) {
        Ok(runs) => {
            let last = runs.first().map(|r| StatusReconcile {
                run_id: r.run_id.clone(),
                date: r.date.clone(),
                status: r.status.clone(),
                matches: r.matches,
                mismatches: r.mismatches.len() as u64,
            });
            (runs.len() as u64, last)
        }
        Err(_) => (0, None),
    };

    let (audit_entries, audit_chain_valid) = match store.audit_records() {
        Ok(records) => {
            let valid = crate::audit::verify(store).unwrap_or(false);
            (records.len() as u64, Some(valid))
        }
        Err(_) => (0, None),
    };

    StatusReport {
        root: store.root().display().to_string(),
        initialized,
        config: config.map(|c| StatusConfig {
            currency: c.currency,
            enabled_rails: c.enabled_rails,
            per_tx_cap: c.per_tx_cap,
            retry: c.retry,
        }),
        orders,
        retries_due,
        retry_jobs,
        dlq: store.dlq_records().map(|d| d.len() as u64).unwrap_or(0),
        journal_postings,
        journal_net,
        reconcile_runs,
        last_reconcile,
        audit_entries,
        audit_chain_valid,
        notifications: store.notifications().map(|n| n.len() as u64).unwrap_or(0),
        twofa_configured: crate::twofa::secret_path(store.root()).exists(),
        custody_vault: store.root().join("keys/secrets.vault").exists(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_root_reports_uninitialized() {
        let dir = tempfile::tempdir().unwrap();
        let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
        let s = build(&store);
        assert!(!s.initialized);
        assert_eq!(s.orders.success, 0);
        assert_eq!(s.journal_postings, 0);
        assert_eq!(s.audit_entries, 0);
        assert!(!s.twofa_configured);
        assert!(!s.custody_vault);
    }

    #[test]
    fn dashboard_reflects_activity() {
        let dir = tempfile::tempdir().unwrap();
        let store = PaymentStore::open(&dir.path().join("payments")).unwrap();
        store
            .write_config(&crate::store::PaymentsConfig::default())
            .unwrap();

        // One settled, one failed (DLQ'd), one stuck EXECUTING.
        let mut settled = crate::event::PaymentOrder::new("c", "mesh", "3.15", "USD");
        settled.payment_order_id = "s1".into();
        settled.transition(OrderStatus::Executing).unwrap();
        settled.transition(OrderStatus::Success).unwrap();
        store.insert_order(&settled).unwrap();

        let mut executing = crate::event::PaymentOrder::new("c", "mesh", "1.00", "USD");
        executing.payment_order_id = "e1".into();
        executing.transition(OrderStatus::Executing).unwrap();
        store.insert_order(&executing).unwrap();

        let mut failed = crate::event::PaymentOrder::new("c", "mesh", "1.00", "USD");
        failed.payment_order_id = "f1".into();
        failed.transition(OrderStatus::Failed).unwrap();
        store.insert_order(&failed).unwrap();

        // Journal batch for the settled order (sums to zero).
        journal::append_batch(
            &store,
            "s1",
            "USD",
            &[
                (journal::Account::Debit, "3.15"),
                (journal::Account::Credit, "3.15"),
            ],
            None,
        )
        .unwrap();

        let s = build(&store);
        assert!(s.initialized);
        assert_eq!(s.orders.success, 1);
        assert_eq!(s.orders.executing, 1);
        assert_eq!(s.orders.failed, 1);
        assert_eq!(s.journal_postings, 2);
        assert_eq!(s.journal_net, vec![("USD".to_string(), 0)]);
    }
}
