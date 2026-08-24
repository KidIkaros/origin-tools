// SPDX-License-Identifier: Apache-2.0

//! Reconciliation (design §4.4, P5).
//!
//! Compares the PSP's settlement file (pulled per date, provenance-stamped
//! by content hash) against the internal record (settled orders), classifies
//! every order, and checkpoints the run into the MMR — the daily proof that
//! reconciliation ran. Mismatches are classifiable (Adjustable = known
//! delta, corrective entry) or Unclassifiable (finance queue).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::event::OrderStatus;
use crate::journal;
use crate::store::PaymentStore;

/// One row of a PSP settlement file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRow {
    pub payment_order_id: String,
    /// Amount as a decimal string (minor units compared internally).
    pub amount: String,
}

/// A stamped settlement file pulled from a PSP (P5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementFile {
    pub rail: String,
    pub date: String,
    /// Settlement currency for this file. A per-currency export emits one
    /// file per currency; a plain pull leaves this empty.
    #[serde(default)]
    pub currency: String,
    pub rows: Vec<SettlementRow>,
    /// SHA3-256 over the canonical (rail, date, currency, rows) JSON — the
    /// provenance stamp; a file tampered on disk fails verification.
    pub content_hash: String,
}

impl SettlementFile {
    /// The provenance stamp: SHA3-256 of the canonical JSON body.
    pub fn compute_hash(&self) -> String {
        let body = serde_json::json!({
            "rail": self.rail,
            "date": self.date,
            "currency": self.currency,
            "rows": self.rows,
        });
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        hex::encode(origin_crypto_sdk::sha3_256(&bytes))
    }

    /// Verify the stored stamp still matches the body (tamper check).
    pub fn verify_stamp(&self) -> bool {
        self.content_hash == self.compute_hash()
    }
}

/// Outcome of one reconciliation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconcileStatus {
    /// Every row matched.
    Clean,
    /// Mismatches found and classified.
    Mismatches,
    /// The run itself failed (missing/invalid settlement file).
    Failed,
}

/// How a mismatch is handled (design §4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MismatchClass {
    /// PSP row agrees with the journal.
    Match,
    /// Known delta — a corrective journal entry with a signed rationale.
    Adjustable,
    /// Finance team investigates manually.
    Unclassifiable,
}

/// One PSP-vs-internal discrepancy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileMismatch {
    pub run_id: String,
    pub payment_order_id: String,
    pub psp_amount: Option<String>,
    pub journal_amount: Option<String>,
    pub class: MismatchClass,
    pub evidence: Vec<String>,
}

/// One reconciliation run (design §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileRun {
    pub run_id: String,
    pub date: String,
    pub psp_files: Vec<SettlementFile>,
    /// Journal MMR head at checkpoint time.
    pub journal_root: [u8; 32],
    pub matches: u64,
    pub mismatches: Vec<ReconcileMismatch>,
    /// MMR leaf for this run.
    pub mmr_checkpoint: [u8; 32],
    pub status: ReconcileStatus,
    /// ISO 8601 timestamp (run files written before this field are read
    /// as empty and sort oldest-first).
    #[serde(default)]
    pub created_at: String,
}

/// Ingests an externally-provided settlement file: stamps it with its
/// content hash and persists it for the run on that date.
///
/// `currency` is the PSP file's currency; when non-empty the file is
/// persisted per-currency as `<date>.<currency>.json` (matching
/// [`export_per_currency`]) so a multi-currency day can hold several
/// pulled files side by side. An empty `currency` keeps the legacy
/// single-file `<date>.json` layout.
pub fn pull(
    store: &PaymentStore,
    rail: &str,
    date: &str,
    currency: &str,
    rows: Vec<SettlementRow>,
) -> Result<SettlementFile> {
    let file = SettlementFile {
        rail: rail.to_string(),
        date: date.to_string(),
        currency: currency.to_string(),
        content_hash: String::new(),
        rows,
    };
    let mut stamped = file.clone();
    stamped.content_hash = file.compute_hash();
    std::fs::create_dir_all(store.settlement_dir()).map_err(|e| Error::IoError {
        details: format!("creating {}: {e}", store.settlement_dir().display()),
    })?;
    let path = if currency.is_empty() {
        store.settlement_dir().join(format!("{date}.json"))
    } else {
        store
            .settlement_dir()
            .join(format!("{date}.{currency}.json"))
    };
    let raw = serde_json::to_vec_pretty(&stamped).map_err(|e| Error::StoreCorrupted {
        details: format!("serializing settlement file: {e}"),
    })?;
    write_atomic(&path, &raw)?;
    Ok(stamped)
}

/// Export one provenance-stamped, per-currency settlement file per
/// currency (P9): each settled order is attributed to its **settlement
/// currency** (the FX `to` currency when the order converts, else its
/// native `currency`), so a multi-currency day yields `{USD, EUR, ...}`
/// files a PSP can settle independently. Files are written under
/// `<settlement>/<date>.<currency>.json` and provenance-stamped.
pub fn export_per_currency(
    store: &PaymentStore,
    rail: &str,
    date: &str,
) -> Result<Vec<SettlementFile>> {
    let mut by_currency: BTreeMap<String, Vec<SettlementRow>> = BTreeMap::new();
    for order in store.orders()? {
        if order.status != OrderStatus::Success {
            continue;
        }
        // Settlement currency: FX conversion settles in the `to` currency.
        let currency = order
            .fx
            .as_ref()
            .map(|fx| fx.to.clone())
            .unwrap_or_else(|| order.currency.clone());
        by_currency
            .entry(currency)
            .or_default()
            .push(SettlementRow {
                payment_order_id: order.payment_order_id.clone(),
                amount: order.amount.clone(),
            });
    }

    std::fs::create_dir_all(store.settlement_dir()).map_err(|e| Error::IoError {
        details: format!("creating {}: {e}", store.settlement_dir().display()),
    })?;

    let mut files = Vec::new();
    for (currency, rows) in by_currency {
        let mut file = SettlementFile {
            rail: rail.to_string(),
            date: date.to_string(),
            currency: currency.clone(),
            content_hash: String::new(),
            rows,
        };
        file.content_hash = file.compute_hash();
        let path = store
            .settlement_dir()
            .join(format!("{date}.{currency}.json"));
        let raw = serde_json::to_vec_pretty(&file).map_err(|e| Error::StoreCorrupted {
            details: format!("serializing settlement file: {e}"),
        })?;
        write_atomic(&path, &raw)?;
        files.push(file);
    }
    Ok(files)
}

/// Load the stamped settlement file for a date, verifying its provenance
/// stamp (a tampered file is rejected). Legacy single-file layout
/// (`<date>.json`).
pub fn load(store: &PaymentStore, date: &str) -> Result<SettlementFile> {
    let path = store.settlement_dir().join(format!("{date}.json"));
    if !path.exists() {
        return Err(Error::SettlementFileInvalid {
            path: path.clone(),
            details: "no settlement file pulled for this date".to_string(),
        });
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| Error::IoError {
        details: format!("reading {}: {e}", path.display()),
    })?;
    let file: SettlementFile =
        serde_json::from_str(&raw).map_err(|e| Error::SettlementFileInvalid {
            path: path.clone(),
            details: format!("parsing: {e}"),
        })?;
    if !file.verify_stamp() {
        return Err(Error::SettlementStampMismatch { path });
    }
    Ok(file)
}

/// Load **every** stamped settlement file for a date — the legacy
/// `<date>.json` plus all per-currency `<date>.<currency>.json` files —
/// so a multi-currency day reconciles against all pulled PSP files.
/// Each file's provenance stamp is verified (a tampered file is rejected).
pub fn load_all(store: &PaymentStore, date: &str) -> Result<Vec<SettlementFile>> {
    let dir = store.settlement_dir();
    let mut files = Vec::new();

    let legacy = dir.join(format!("{date}.json"));
    if legacy.exists() {
        files.push(load(store, date)?);
    }

    let legacy_name = format!("{date}.json");
    let prefix = format!("{date}.");
    let mut extra: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| Error::IoError {
            details: format!("reading {}: {e}", dir.display()),
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".json") && n != legacy_name)
        })
        .collect();
    extra.sort();
    for path in extra {
        let raw = std::fs::read_to_string(&path).map_err(|e| Error::IoError {
            details: format!("reading {}: {e}", path.display()),
        })?;
        let file: SettlementFile =
            serde_json::from_str(&raw).map_err(|e| Error::SettlementFileInvalid {
                path: path.clone(),
                details: format!("parsing: {e}"),
            })?;
        if !file.verify_stamp() {
            return Err(Error::SettlementStampMismatch { path });
        }
        files.push(file);
    }

    if files.is_empty() {
        return Err(Error::SettlementFileInvalid {
            path: legacy,
            details: "no settlement file pulled for this date".to_string(),
        });
    }
    Ok(files)
}

/// Run reconciliation for a date: compare the settlement file against the
/// internal record, classify, checkpoint into the MMR, persist the run.
pub fn run(store: &PaymentStore, date: Option<String>) -> Result<ReconcileRun> {
    let date = date.unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());
    let settlements = load_all(store, &date)?;
    let run_id = uuid::Uuid::new_v4().to_string();

    // Internal view: settled orders (the double-entry journal's record).
    let mut internal: BTreeMap<String, String> = BTreeMap::new();
    for order in store.orders()? {
        if order.status == OrderStatus::Success {
            internal.insert(order.payment_order_id.clone(), order.amount.clone());
        }
    }
    let mut psp: BTreeMap<String, String> = BTreeMap::new();
    for settlement in &settlements {
        for row in &settlement.rows {
            psp.insert(row.payment_order_id.clone(), row.amount.clone());
        }
    }

    let mut matches = 0u64;
    let mut mismatches = Vec::new();
    let mut order_ids: Vec<&String> = psp.keys().collect();
    for id in internal.keys() {
        if !psp.contains_key(id) {
            order_ids.push(id);
        }
    }
    order_ids.sort();

    for id in order_ids {
        let psp_amount = psp.get(id).cloned();
        let journal_amount = internal.get(id).cloned();
        let class = match (&psp_amount, &journal_amount) {
            (Some(p), Some(j)) if amount_eq(p, j) => {
                matches += 1;
                continue;
            }
            (Some(_), Some(_)) => MismatchClass::Adjustable,
            _ => MismatchClass::Unclassifiable,
        };
        mismatches.push(ReconcileMismatch {
            run_id: run_id.clone(),
            payment_order_id: id.clone(),
            psp_amount,
            journal_amount,
            class,
            evidence: vec![format!("settlement {date}")],
        });
    }

    // MMR checkpoint: sha3(all settlement stamps ‖ journal head).
    let journal_root = store.journal_head()?;
    let mut stamps: Vec<u8> = Vec::new();
    for s in &settlements {
        stamps.extend(hex::decode(&s.content_hash).unwrap_or_default());
    }
    let checkpoint_hash = origin_crypto_sdk::sha3_256(&[stamps, journal_root.to_vec()].concat());
    let mmr_checkpoint = store.checkpoint_mmr(checkpoint_hash)?;

    let status = if mismatches.is_empty() {
        ReconcileStatus::Clean
    } else {
        ReconcileStatus::Mismatches
    };
    let run = ReconcileRun {
        run_id,
        date,
        psp_files: settlements,
        journal_root,
        matches,
        mismatches,
        mmr_checkpoint,
        status,
        created_at: crate::now_rfc3339(),
    };

    std::fs::create_dir_all(store.runs_dir()).map_err(|e| Error::IoError {
        details: format!("creating {}: {e}", store.runs_dir().display()),
    })?;
    let raw = serde_json::to_vec_pretty(&run).map_err(|e| Error::StoreCorrupted {
        details: format!("serializing run: {e}"),
    })?;
    write_atomic(&store.runs_dir().join(format!("{}.json", run.run_id)), &raw)?;
    Ok(run)
}

/// All persisted runs (most recent first).
pub fn list(store: &PaymentStore) -> Result<Vec<ReconcileRun>> {
    let dir = store.runs_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut runs: Vec<ReconcileRun> = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| Error::IoError {
        details: format!("reading {}: {e}", dir.display()),
    })? {
        let path = entry
            .map_err(|e| Error::IoError {
                details: e.to_string(),
            })?
            .path();
        if path.extension().map(|e| e == "json").unwrap_or(false) {
            let raw = std::fs::read_to_string(&path).map_err(|e| Error::IoError {
                details: format!("reading {}: {e}", path.display()),
            })?;
            if let Ok(run) = serde_json::from_str(&raw) {
                runs.push(run);
            }
        }
    }
    // Newest date first; same-day runs tie-break on creation time so the
    // dashboard's "last reconcile" is deterministic (read_dir order is not).
    runs.sort_by(|a, b| {
        b.date
            .cmp(&a.date)
            .then_with(|| b.created_at.cmp(&a.created_at))
    });
    Ok(runs)
}

/// Compliance export of a run (plain text or SOC2/PCI-DSS/HIPAA JSON).
pub fn export(store: &PaymentStore, run_id: &str, format: &str, out: &Path) -> Result<()> {
    let run = load_run(store, run_id)?;
    let export = match format {
        "plain" => plain_export(&run),
        "soc2" | "pcidss" | "hipaa" => compliance_export(&run, format),
        other => {
            return Err(Error::StoreCorrupted {
                details: format!("unknown export format: {other}"),
            })
        }
    };
    write_atomic(out, export.as_bytes())?;
    Ok(())
}

fn load_run(store: &PaymentStore, run_id: &str) -> Result<ReconcileRun> {
    let path = store.runs_dir().join(format!("{run_id}.json"));
    let raw = std::fs::read_to_string(&path).map_err(|e| Error::IoError {
        details: format!("reading {}: {e}", path.display()),
    })?;
    serde_json::from_str(&raw).map_err(|e| Error::StoreCorrupted {
        details: format!("parsing run {run_id}: {e}"),
    })
}

fn plain_export(run: &ReconcileRun) -> String {
    let mut s = format!(
        "Reconcile run {} ({}) — {} matches, {} mismatches, status {:?}\n",
        run.run_id,
        run.date,
        run.matches,
        run.mismatches.len(),
        run.status
    );
    for m in &run.mismatches {
        s.push_str(&format!(
            "  {} psp={:?} journal={:?} class={:?}\n",
            m.payment_order_id, m.psp_amount, m.journal_amount, m.class
        ));
    }
    s
}

fn compliance_export(run: &ReconcileRun, framework: &str) -> String {
    let evidence: Vec<_> = run
        .mismatches
        .iter()
        .map(|m| {
            serde_json::json!({
                "control_id": format!("RECONCILE-{}", m.payment_order_id),
                "control_description": "PSP vs internal settlement comparison",
                "evidence_type": "mismatch",
                "evidence_data": {
                    "payment_order_id": m.payment_order_id,
                    "class": m.class,
                    "psp_amount": m.psp_amount,
                    "journal_amount": m.journal_amount,
                },
            })
        })
        .collect();
    let doc = serde_json::json!({
        "framework": framework,
        "version": "1.0",
        "export_date": chrono::Utc::now().format("%Y-%m-%d").to_string(),
        "period": run.date,
        "run_id": run.run_id,
        "matches": run.matches,
        "mmr_checkpoint": hex::encode(run.mmr_checkpoint),
        "evidence": evidence,
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

fn amount_eq(a: &str, b: &str) -> bool {
    match (journal::parse_amount(a), journal::parse_amount(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| Error::IoError {
        details: format!("writing {}: {e}", tmp.display()),
    })?;
    std::fs::rename(&tmp, path).map_err(|e| Error::IoError {
        details: format!("renaming {} -> {}: {e}", tmp.display(), path.display()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> PaymentStore {
        // Keep the tempdir alive past this fn: dropping it would delete the
        // directory the store just opened.
        let dir = tempfile::tempdir().unwrap();
        PaymentStore::open(&dir.keep()).unwrap()
    }

    #[test]
    fn pull_stamp_verify_roundtrip() {
        let s = tmp_store();
        let file = pull(
            &s,
            "native",
            "2026-08-23",
            "",
            vec![SettlementRow {
                payment_order_id: "o1".into(),
                amount: "3.15".into(),
            }],
        )
        .unwrap();
        assert!(file.verify_stamp());
        let loaded = load(&s, "2026-08-23").unwrap();
        assert_eq!(loaded, file);
        // Tampering with the file on disk breaks the stamp.
        let path = s.settlement_dir().join("2026-08-23.json");
        let raw = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, raw.replace("3.15", "9.99")).unwrap();
        assert!(load(&s, "2026-08-23").is_err());
    }

    #[test]
    fn export_per_currency_groups_and_stamps_by_settlement_currency() {
        let s = tmp_store();
        // Two plain USD orders (settle in USD) and one FX order (USD -> EUR,
        // settles in EUR). All marked Success.
        for (id, amount, fx) in [
            ("o-usd1", "3.15", None),
            ("o-usd2", "5.00", None),
            (
                "o-fx",
                "10.00",
                Some(crate::journal::FxRate {
                    from: "USD".into(),
                    to: "EUR".into(),
                    rate: "0.9".into(),
                    markup_bps: 0,
                }),
            ),
        ] {
            let mut order = crate::event::PaymentOrder::new("c", "mesh", amount, "USD");
            order.payment_order_id = id.to_string();
            order.fx = fx.map(|f| f.clone());
            order.transition(OrderStatus::Executing).unwrap();
            order.transition(OrderStatus::Success).unwrap();
            s.insert_order(&order).unwrap();
        }

        let files = export_per_currency(&s, "native", "2026-08-23").unwrap();
        let mut by_ccy: BTreeMap<String, usize> = BTreeMap::new();
        for f in &files {
            assert!(f.verify_stamp(), "each file provenance-stamped");
            assert!(!f.currency.is_empty(), "currency tagged");
            let path = s
                .settlement_dir()
                .join(format!("2026-08-23.{}.json", f.currency));
            assert!(path.exists(), "file written per currency");
            by_ccy.insert(f.currency.clone(), f.rows.len());
        }
        // USD file holds the two plain orders; EUR file holds the FX order.
        assert_eq!(by_ccy.get("USD"), Some(&2));
        assert_eq!(by_ccy.get("EUR"), Some(&1));
        // The FX order is attributed to its settlement (to) currency.
        let eur = files.iter().find(|f| f.currency == "EUR").unwrap();
        assert_eq!(eur.rows[0].payment_order_id, "o-fx");
    }

    #[test]
    fn run_classifies_match_adjustable_unclassifiable() {
        let s = tmp_store();
        // Two settled orders in the journal; one PSP row matches, one
        // differs (adjustable), one PSP row is missing internally.
        for (id, amount) in [("o1", "3.15"), ("o2", "5.00")] {
            let mut order = crate::event::PaymentOrder::new("c", "mesh", amount, "USD");
            order.payment_order_id = id.to_string();
            order.transition(OrderStatus::Executing).unwrap();
            order.transition(OrderStatus::Success).unwrap();
            s.insert_order(&order).unwrap();
        }
        pull(
            &s,
            "native",
            "2026-08-23",
            "",
            vec![
                SettlementRow {
                    payment_order_id: "o1".into(),
                    amount: "3.15".into(),
                },
                SettlementRow {
                    payment_order_id: "o2".into(),
                    amount: "4.99".into(),
                },
                SettlementRow {
                    payment_order_id: "ghost".into(),
                    amount: "1.00".into(),
                },
            ],
        )
        .unwrap();

        let run = run(&s, Some("2026-08-23".into())).unwrap();
        assert_eq!(run.matches, 1);
        assert_eq!(run.status, ReconcileStatus::Mismatches);
        assert_eq!(run.mismatches.len(), 2);
        let classes: Vec<_> = run.mismatches.iter().map(|m| &m.class).collect();
        assert!(classes.contains(&&MismatchClass::Adjustable));
        assert!(classes.contains(&&MismatchClass::Unclassifiable));
        // MMR checkpoint exists and is provable.
        let mmr = s.load_mmr().unwrap();
        assert_eq!(mmr.leaf_count(), 1);
        assert!(mmr.prove(0).is_ok());
        // The run persisted and lists.
        assert_eq!(list(&s).unwrap().len(), 1);
    }

    #[test]
    fn export_formats() {
        let s = tmp_store();
        let mut order = crate::event::PaymentOrder::new("c", "mesh", "1.00", "USD");
        order.payment_order_id = "o1".into();
        order.transition(OrderStatus::Executing).unwrap();
        order.transition(OrderStatus::Success).unwrap();
        s.insert_order(&order).unwrap();
        pull(
            &s,
            "native",
            "2026-08-23",
            "",
            vec![SettlementRow {
                payment_order_id: "o1".into(),
                amount: "0.99".into(),
            }],
        )
        .unwrap();
        let run = run(&s, Some("2026-08-23".into())).unwrap();

        let dir = tempfile::tempdir().unwrap();
        for fmt in ["plain", "soc2", "pcidss", "hipaa"] {
            let out = dir.path().join(format!("{fmt}.json"));
            export(&s, &run.run_id, fmt, &out).unwrap();
            assert!(out.exists(), "{fmt} export written");
        }
    }

    #[test]
    fn multi_currency_day_reconciles_all_pulled_files() {
        let s = tmp_store();
        // A plain USD order (settles USD) and an FX order (USD -> EUR,
        // settles EUR) — both Success, like a multi-currency day.
        for (id, amount, fx) in [
            ("o-usd", "7.77", None),
            (
                "o-fx",
                "10.00",
                Some(crate::journal::FxRate {
                    from: "USD".into(),
                    to: "EUR".into(),
                    rate: "0.9".into(),
                    markup_bps: 0,
                }),
            ),
        ] {
            let mut order = crate::event::PaymentOrder::new("c", "mesh", amount, "USD");
            order.payment_order_id = id.to_string();
            order.fx = fx;
            order.transition(OrderStatus::Executing).unwrap();
            order.transition(OrderStatus::Success).unwrap();
            s.insert_order(&order).unwrap();
        }

        // Pull one PSP file per currency — the second pull must NOT
        // clobber the first (each persists per-currency).
        pull(
            &s,
            "native",
            "2026-08-23",
            "USD",
            vec![SettlementRow {
                payment_order_id: "o-usd".into(),
                amount: "7.77".into(),
            }],
        )
        .unwrap();
        pull(
            &s,
            "native",
            "2026-08-23",
            "EUR",
            vec![SettlementRow {
                payment_order_id: "o-fx".into(),
                amount: "10.00".into(),
            }],
        )
        .unwrap();
        assert!(
            s.settlement_dir().join("2026-08-23.USD.json").exists(),
            "USD file kept"
        );
        assert!(
            s.settlement_dir().join("2026-08-23.EUR.json").exists(),
            "EUR file kept"
        );

        // The run compares against both pulled files -> CLEAN.
        let run = run(&s, Some("2026-08-23".into())).unwrap();
        assert_eq!(run.matches, 2);
        assert_eq!(run.mismatches.len(), 0);
        assert_eq!(run.status, ReconcileStatus::Clean);
        assert_eq!(run.psp_files.len(), 2, "run records both pulled files");
    }
}
