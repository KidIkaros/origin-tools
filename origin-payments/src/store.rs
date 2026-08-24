// SPDX-License-Identifier: Apache-2.0

//! Append-only file store under the payments root (design §5 "Store
//! layout").
//!
//! Every collection is a JSONL file. The ordering authority is the
//! journal's hash chain + MMR (P2/P5), not a DB server — consistent with
//! the suite's one-home convention. Writes go through an append handle
//! with a flush; tamper-evidence comes from the chain, not from the
//! transport.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::event::{OrderStatus, PaymentEvent, PaymentOrder};
use crate::journal::LedgerPosting;

/// The outcome of inserting an order: a fresh insert, or an idempotent
/// replay that returns the existing order (design §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted,
    Replay(Box<PaymentOrder>),
}

/// Default retry policy (design §4.3): exponential backoff + jitter,
/// with a terminal attempt cap (P4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub base_ms: u64,
    pub factor: u64,
    pub cap_ms: u64,
    /// Attempts before an order is terminal (goes to the DLQ).
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            base_ms: 1_000,
            factor: 2,
            cap_ms: 300_000,
            max_attempts: 5,
        }
    }
}

/// Payments configuration, persisted at init as `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentsConfig {
    pub version: u8,
    pub currency: String,
    /// Rail names: "native" | "http402" | "card" | "ach".
    pub enabled_rails: Vec<String>,
    pub retry: RetryPolicy,
    /// Payments-layer spend cap per transaction (decimal string, P6).
    /// The wallet's own standing policy is enforced by the wallet too.
    #[serde(default)]
    pub per_tx_cap: Option<String>,
    /// How long an order may sit in `EXECUTING` (crash window) before the
    /// TTL sweep re-queues it (design §4.3). Bounded by `retry.max_attempts`;
    /// past that the sweep DLQs instead.
    #[serde(default = "default_executing_ttl_secs")]
    pub executing_ttl_secs: u64,
    /// Deferred settlement (P10): when enabled, the executor rolls signed
    /// x402 authorizations up into a daily `DeferredBatch` (MMR-checkpointed)
    /// instead of settling each immediately. Off by default.
    #[serde(default)]
    pub deferred_settlement_enabled: bool,
    /// Merchant settlement preference: what to do with inbound payments.
    /// - `hold`: keep stablecoin/crypto as-is (default).
    /// - `off_ramp`: convert to fiat and pay out to the merchant's bank
    ///   account (requires a configured off-ramp facilitator).
    /// - `split`: a configurable ratio (e.g. 80/20) between hold and
    ///   off-ramp.
    #[serde(default)]
    pub settlement_preference: SettlementPreference,
    /// When `settlement_preference` is `Split`, the percentage of inbound
    /// payments kept as stablecoin (the rest is off-ramped). 0–100.
    #[serde(default = "default_split_pct")]
    pub split_pct: u8,
}

fn default_split_pct() -> u8 {
    50
}

/// Merchant-level settlement preference (research §4 — Fireblocks PSP
/// blueprint: "per-merchant preference: hold stablecoin, off-ramp to fiat,
/// or a split").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementPreference {
    /// Hold inbound stablecoin/crypto as-is.
    #[default]
    Hold,
    /// Off-ramp all inbound payments to fiat via a configured facilitator.
    OffRamp,
    /// Split: a ratio of hold vs off-ramp (e.g. 80/20). The `split_pct`
    /// field on the config determines the percentage kept as stablecoin.
    Split,
}

fn default_executing_ttl_secs() -> u64 {
    300
}

impl Default for PaymentsConfig {
    fn default() -> Self {
        PaymentsConfig {
            version: 1,
            currency: "USD".to_string(),
            enabled_rails: vec!["native".to_string()],
            retry: RetryPolicy::default(),
            per_tx_cap: None,
            executing_ttl_secs: default_executing_ttl_secs(),
            deferred_settlement_enabled: false,
            settlement_preference: SettlementPreference::default(),
            split_pct: default_split_pct(),
        }
    }
}

/// A retry-queue record (design §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryJob {
    pub payment_order_id: String,
    pub attempt: u32,
    pub next_retry_at: String,
    pub backoff_ms: u64,
    pub last_error: String,
}

/// A dead-letter record (design §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqRecord {
    pub payment_order_id: String,
    pub reason: String,
    pub evidence: serde_json::Value,
    pub created_at: String,
}

/// A settlement notification record (P6; delivery via mail/webhook is a
/// follow-up — the record is the durable trail).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub notification_id: String,
    pub payment_order_id: String,
    pub event: String,
    pub created_at: String,
}

/// The payments root: `~/.origin/payments/` (or `--home`).
#[derive(Debug, Clone)]
pub struct PaymentStore {
    root: PathBuf,
}

impl PaymentStore {
    /// Open (and create, 0700) the payments root.
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root).map_err(|e| Error::IoError {
            details: format!("creating {}: {e}", root.display()),
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o700));
        }
        Ok(PaymentStore {
            root: root.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    // ── paths ──────────────────────────────────────────────────────────

    pub fn events_path(&self) -> PathBuf {
        self.root.join("payment_events.jsonl")
    }
    pub fn orders_path(&self) -> PathBuf {
        self.root.join("payment_orders.jsonl")
    }
    pub fn journal_path(&self) -> PathBuf {
        self.root.join("journal.jsonl")
    }
    pub fn retry_path(&self) -> PathBuf {
        self.root.join("retry_queue.jsonl")
    }
    pub fn dlq_path(&self) -> PathBuf {
        self.root.join("dlq.jsonl")
    }
    pub fn config_path(&self) -> PathBuf {
        self.root.join("config.toml")
    }
    pub fn notifications_path(&self) -> PathBuf {
        self.root.join("notifications.jsonl")
    }
    /// Deferred-settlement commitments awaiting a daily batch (P10).
    pub fn deferred_path(&self) -> PathBuf {
        self.root.join("deferred_commitments.jsonl")
    }
    pub fn settlement_dir(&self) -> PathBuf {
        self.root.join("settlement")
    }
    pub fn runs_dir(&self) -> PathBuf {
        self.root.join("reconcile")
    }
    pub fn mmr_path(&self) -> PathBuf {
        self.root.join("mmr.json")
    }
    pub fn audit_path(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }
    /// Rail-level receipt dedupe cache (x402 spec §4.2 — merchants
    /// settling directly must implement duplicate-settlement detection).
    pub fn receipt_cache_path(&self) -> PathBuf {
        self.root.join("receipt_dedupe.jsonl")
    }

    // ── receipt dedupe (x402 §4.2) ────────────────────────────────────

    /// Record a receipt hash for deduplication. The hash is the SHA-3-256
    /// of the raw receipt bytes; a duplicate is a same-hash settle attempt.
    pub fn record_receipt_hash(&self, order_id: &str, receipt_hash: &[u8; 32]) -> Result<()> {
        let record = serde_json::json!({
            "order_id": order_id,
            "hash": hex::encode(receipt_hash),
            "recorded_at": crate::now_rfc3339(),
        });
        let mut line = serde_json::to_vec(&record).map_err(|e| Error::StoreCorrupted {
            details: format!("serializing receipt dedupe: {e}"),
        })?;
        line.push(b'\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.receipt_cache_path())
            .map_err(|e| Error::IoError {
                details: format!("opening {}: {e}", self.receipt_cache_path().display()),
            })?;
        f.write_all(&line).map_err(|e| Error::IoError {
            details: format!("appending to {}: {e}", self.receipt_cache_path().display()),
        })?;
        f.flush().map_err(|e| Error::IoError {
            details: format!("flushing {}: {e}", self.receipt_cache_path().display()),
        })?;
        Ok(())
    }

    /// True if a receipt with this hash was already settled (duplicate
    /// settlement attempt — the x402 spec requires rejection).
    pub fn is_receipt_settled(&self, receipt_hash: &[u8; 32]) -> Result<bool> {
        let target = hex::encode(receipt_hash);
        if !self.receipt_cache_path().exists() {
            return Ok(false);
        }
        let raw = fs::read_to_string(self.receipt_cache_path()).map_err(|e| Error::IoError {
            details: format!("reading {}: {e}", self.receipt_cache_path().display()),
        })?;
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                if val.get("hash").and_then(|v| v.as_str()) == Some(&target) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    // ── config ──────────────────────────────────────────────────────────

    /// Persist the config. Refuses to overwrite an existing config — the
    /// store must be initialized exactly once (use `--force` at the CLI).
    pub fn write_config(&self, cfg: &PaymentsConfig) -> Result<()> {
        if self.config_path().exists() {
            return Err(Error::AlreadyInitialized(self.config_path()));
        }
        let toml = toml::to_string_pretty(cfg).map_err(|e| Error::StoreCorrupted {
            details: format!("serializing config: {e}"),
        })?;
        write_file(&self.config_path(), toml.as_bytes())
    }

    /// Load the config, or the defaults when the store is not initialized.
    pub fn load_config(&self) -> Result<PaymentsConfig> {
        if !self.config_path().exists() {
            return Ok(PaymentsConfig::default());
        }
        let raw = fs::read_to_string(self.config_path()).map_err(|e| Error::IoError {
            details: format!("reading {}: {e}", self.config_path().display()),
        })?;
        toml::from_str(&raw).map_err(|e| Error::StoreCorrupted {
            details: format!("parsing config: {e}"),
        })
    }

    // ── events ──────────────────────────────────────────────────────────

    pub fn append_event(&self, event: &PaymentEvent) -> Result<()> {
        append_jsonl(&self.events_path(), event)
    }

    pub fn events(&self) -> Result<Vec<PaymentEvent>> {
        read_jsonl(&self.events_path())
    }

    /// Latest snapshot of an event ("latest line wins" on the append-only
    /// event log; order snapshots follow the same convention).
    pub fn latest_event(&self, event_id: &str) -> Result<PaymentEvent> {
        self.events()?
            .into_iter()
            .rev()
            .find(|e| e.event_id == event_id)
            .ok_or_else(|| Error::EventNotFound {
                event_id: event_id.to_string(),
            })
    }

    /// Append a new snapshot of an event (used by the executor's rollup).
    pub fn update_event(&self, event: &PaymentEvent) -> Result<()> {
        self.append_event(event)
    }

    // ── orders (the idempotency surface) ────────────────────────────────

    /// Insert an order under its `payment_order_id` unique key. A
    /// duplicate is an idempotent replay: the existing order is returned
    /// and nothing is written (design §4.3).
    pub fn insert_order(&self, order: &PaymentOrder) -> Result<InsertOutcome> {
        for existing in self.orders()? {
            if existing.payment_order_id == order.payment_order_id {
                return Ok(InsertOutcome::Replay(Box::new(existing)));
            }
        }
        self.append_order(order)?;
        Ok(InsertOutcome::Inserted)
    }

    /// Append an order line (used by `update_order` snapshots too).
    pub fn append_order(&self, order: &PaymentOrder) -> Result<()> {
        append_jsonl(&self.orders_path(), order)
    }

    /// Latest snapshot of an order ("latest line wins" on the append-only
    /// log).
    pub fn get_order(&self, payment_order_id: &str) -> Result<PaymentOrder> {
        self.orders()?
            .into_iter()
            .rev()
            .find(|o| o.payment_order_id == payment_order_id)
            .ok_or_else(|| Error::OrderNotFound {
                payment_order_id: payment_order_id.to_string(),
            })
    }

    /// Every line of the append-only order log (historical snapshots
    /// included) — used for idempotency detection and audits.
    pub fn orders(&self) -> Result<Vec<PaymentOrder>> {
        read_jsonl(&self.orders_path())
    }

    /// Latest snapshot of every order (stale `NOT_STARTED` lines from
    /// previous runs never resurface).
    pub fn latest_orders(&self) -> Result<Vec<PaymentOrder>> {
        let mut latest: std::collections::HashMap<String, PaymentOrder> =
            std::collections::HashMap::new();
        for order in self.orders()? {
            latest.insert(order.payment_order_id.clone(), order);
        }
        Ok(latest.into_values().collect())
    }

    pub fn orders_with_status(&self, status: OrderStatus) -> Result<Vec<PaymentOrder>> {
        Ok(self
            .latest_orders()?
            .into_iter()
            .filter(|o| o.status == status)
            .collect())
    }

    /// Append a new snapshot of an updated order (append-only; reads take
    /// the latest line).
    pub fn update_order(&self, order: &PaymentOrder) -> Result<()> {
        self.append_order(order)
    }

    // ── journal ─────────────────────────────────────────────────────────

    pub fn append_posting(&self, posting: &LedgerPosting) -> Result<()> {
        append_jsonl(&self.journal_path(), posting)
    }

    pub fn postings(&self) -> Result<Vec<LedgerPosting>> {
        read_jsonl(&self.journal_path())
    }

    /// The chain head: hash of the last posting, or [`GENESIS_HASH`].
    pub fn journal_head(&self) -> Result<[u8; 32]> {
        match self.postings()?.last() {
            Some(p) => Ok(crate::journal::posting_hash(p)),
            None => Ok(crate::journal::GENESIS_HASH),
        }
    }

    // ── retry queue / DLQ ───────────────────────────────────────────────

    pub fn append_retry_job(&self, job: &RetryJob) -> Result<()> {
        append_jsonl(&self.retry_path(), job)
    }

    pub fn retry_jobs(&self) -> Result<Vec<RetryJob>> {
        read_jsonl(&self.retry_path())
    }

    pub fn append_dlq(&self, record: &DlqRecord) -> Result<()> {
        append_jsonl(&self.dlq_path(), record)
    }

    pub fn dlq_records(&self) -> Result<Vec<DlqRecord>> {
        read_jsonl(&self.dlq_path())
    }

    /// Latest dead-letter record for an order.
    pub fn dlq_record(&self, payment_order_id: &str) -> Result<DlqRecord> {
        self.dlq_records()?
            .into_iter()
            .rev()
            .find(|r| r.payment_order_id == payment_order_id)
            .ok_or_else(|| Error::OrderNotFound {
                payment_order_id: payment_order_id.to_string(),
            })
    }

    // ── notifications (P6) ─────────────────────────────────────────────

    pub fn append_notification(&self, notification: &Notification) -> Result<()> {
        append_jsonl(&self.notifications_path(), notification)
    }

    pub fn notifications(&self) -> Result<Vec<Notification>> {
        read_jsonl(&self.notifications_path())
    }

    // ── deferred settlement commitments (P10) ──────────────────────────

    /// Append a verified deferred commitment awaiting batch settlement.
    pub fn append_deferred_commitment(&self, item: &crate::settle::DeferredItem) -> Result<()> {
        append_jsonl(&self.deferred_path(), item)
    }

    /// Read all pending deferred commitments (unsettled, in admission order).
    pub fn deferred_commitments(&self) -> Result<Vec<crate::settle::DeferredItem>> {
        read_jsonl(&self.deferred_path())
    }

    /// Clear the pending deferred commitments once a batch is committed.
    pub fn clear_deferred_commitments(&self) -> Result<()> {
        if self.deferred_path().exists() {
            std::fs::remove_file(self.deferred_path()).map_err(|e| Error::IoError {
                details: format!("clearing {}: {e}", self.deferred_path().display()),
            })?;
        }
        Ok(())
    }

    // ── audit stream (P7) ──────────────────────────────────────────────

    pub fn append_audit_record(&self, record: &crate::audit::AuditRecord) -> Result<()> {
        append_jsonl(&self.audit_path(), record)
    }

    pub fn audit_records(&self) -> Result<Vec<crate::audit::AuditRecord>> {
        read_jsonl(&self.audit_path())
    }

    // ── reconcile MMR checkpoint (P5) ──────────────────────────────────

    /// The checkpoint MMR (origin-proof `MmrState`), persisted as JSON.
    pub fn load_mmr(&self) -> Result<crate::proof::CheckpointMmr> {
        if !self.mmr_path().exists() {
            return Ok(crate::proof::CheckpointMmr::new());
        }
        let raw = fs::read_to_string(self.mmr_path()).map_err(|e| Error::IoError {
            details: format!("reading {}: {e}", self.mmr_path().display()),
        })?;
        serde_json::from_str(&raw).map_err(|e| Error::StoreCorrupted {
            details: format!("parsing {}: {e}", self.mmr_path().display()),
        })
    }

    /// Persist the checkpoint MMR (atomic temp + rename).
    pub fn save_mmr(&self, mmr: &crate::proof::CheckpointMmr) -> Result<()> {
        let raw = serde_json::to_vec_pretty(mmr).map_err(|e| Error::StoreCorrupted {
            details: format!("serializing mmr: {e}"),
        })?;
        write_file(&self.mmr_path(), &raw)
    }

    /// Append a checkpoint leaf and persist.
    pub fn checkpoint_mmr(&self, leaf_hash: [u8; 32]) -> Result<[u8; 32]> {
        let mut mmr = self.load_mmr()?;
        mmr.append_hash(leaf_hash);
        let root = mmr.root();
        self.save_mmr(&mmr)?;
        Ok(root)
    }
}

// ── JSONL plumbing ─────────────────────────────────────────────────────

/// Append one serialized record as a JSON line. The append handle is
/// opened per write and flushed; durability (fsync) is deferred to the
/// chain/MMR hardening in P2.
fn append_jsonl<T: Serialize>(path: &Path, item: &T) -> Result<()> {
    let mut line = serde_json::to_vec(item).map_err(|e| Error::StoreCorrupted {
        details: format!("serializing record for {}: {e}", path.display()),
    })?;
    line.push(b'\n');
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| Error::IoError {
            details: format!("opening {}: {e}", path.display()),
        })?;
    f.write_all(&line).map_err(|e| Error::IoError {
        details: format!("appending to {}: {e}", path.display()),
    })?;
    f.flush().map_err(|e| Error::IoError {
        details: format!("flushing {}: {e}", path.display()),
    })
}

/// Read all records; a missing file is an empty log.
fn read_jsonl<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path).map_err(|e| Error::IoError {
        details: format!("reading {}: {e}", path.display()),
    })?;
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let item = serde_json::from_str(line).map_err(|e| Error::StoreCorrupted {
            details: format!("{} line {}: {e}", path.display(), i + 1),
        })?;
        out.push(item);
    }
    Ok(out)
}

/// Atomic write: temp file + rename.
fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, bytes).map_err(|e| Error::IoError {
        details: format!("writing {}: {e}", tmp.display()),
    })?;
    fs::rename(&tmp, path).map_err(|e| Error::IoError {
        details: format!("renaming {} -> {}: {e}", tmp.display(), path.display()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::Account;

    fn tmp_store() -> PaymentStore {
        // Keep the tempdir alive past this fn: dropping it would delete the
        // directory the store just opened.
        let dir = tempfile::tempdir().unwrap();
        PaymentStore::open(&dir.keep()).unwrap()
    }

    #[test]
    fn insert_then_get_roundtrip() {
        let s = tmp_store();
        let o = PaymentOrder::new("c1", "mesh-1", "5.00", "USD");
        assert_eq!(s.insert_order(&o).unwrap(), InsertOutcome::Inserted);
        assert_eq!(s.get_order(&o.payment_order_id).unwrap(), o);
    }

    #[test]
    fn duplicate_order_id_is_idempotent_replay() {
        let s = tmp_store();
        let o = PaymentOrder::new("c1", "mesh-1", "5.00", "USD");
        assert_eq!(s.insert_order(&o).unwrap(), InsertOutcome::Inserted);
        let replay = s.insert_order(&o).unwrap();
        assert_eq!(replay, InsertOutcome::Replay(Box::new(o.clone())));
        // Nothing extra written.
        assert_eq!(s.orders().unwrap().len(), 1);
    }

    #[test]
    fn update_appends_snapshot_latest_wins() {
        let s = tmp_store();
        let mut o = PaymentOrder::new("c1", "mesh-1", "5.00", "USD");
        s.insert_order(&o).unwrap();
        o.transition(OrderStatus::Executing).unwrap();
        s.update_order(&o).unwrap();
        let got = s.get_order(&o.payment_order_id).unwrap();
        assert_eq!(got.status, OrderStatus::Executing);
        assert_eq!(s.orders().unwrap().len(), 2, "append-only: two lines");
    }

    #[test]
    fn orders_with_status_filters() {
        let s = tmp_store();
        let o = PaymentOrder::new("c1", "mesh-1", "1.00", "USD");
        s.insert_order(&o).unwrap();
        assert_eq!(
            s.orders_with_status(OrderStatus::NotStarted).unwrap().len(),
            1
        );
        assert_eq!(s.orders_with_status(OrderStatus::Success).unwrap().len(), 0);
    }

    #[test]
    fn missing_order_not_found() {
        let s = tmp_store();
        let err = s.get_order("nope").unwrap_err();
        assert!(matches!(err, Error::OrderNotFound { .. }));
    }

    #[test]
    fn dlq_and_retry_roundtrip() {
        let s = tmp_store();
        s.append_dlq(&DlqRecord {
            payment_order_id: "o1".to_string(),
            reason: "rail decline".to_string(),
            evidence: serde_json::json!({ "rail": "native" }),
            created_at: "now".to_string(),
        })
        .unwrap();
        assert_eq!(s.dlq_records().unwrap().len(), 1);
        assert_eq!(s.dlq_record("o1").unwrap().reason, "rail decline");
        assert!(s.dlq_record("o2").is_err());
    }

    #[test]
    fn config_roundtrip_and_single_init() {
        let s = tmp_store();
        assert!(s.load_config().is_ok(), "defaults before init");
        s.write_config(&PaymentsConfig::default()).unwrap();
        assert!(s.config_path().exists());
        let err = s.write_config(&PaymentsConfig::default()).unwrap_err();
        assert!(matches!(err, Error::AlreadyInitialized(_)));
        let cfg = s.load_config().unwrap();
        assert_eq!(cfg.currency, "USD");
        assert_eq!(cfg.enabled_rails, vec!["native".to_string()]);
    }

    #[test]
    fn journal_head_is_genesis_then_chains() {
        let s = tmp_store();
        assert_eq!(s.journal_head().unwrap(), crate::journal::GENESIS_HASH);
        let p = LedgerPosting {
            posting_id: "p1".to_string(),
            batch_id: "b1".to_string(),
            payment_order_id: "o1".to_string(),
            account: Account::Debit,
            amount: "1.00".to_string(),
            currency: "USD".to_string(),
            ts: "now".to_string(),
            prev_hash: crate::journal::GENESIS_HASH,
            signature: None,
            signer: None,
            fx_rate: None,
        };
        s.append_posting(&p).unwrap();
        assert_eq!(s.journal_head().unwrap(), crate::journal::posting_hash(&p));
    }
}
