// SPDX-License-Identifier: Apache-2.0

//! Audit stream (design §3, P7) — an `origin-attest` hash-chained log.
//!
//! Every money movement records an entry: `order_created`, `order_settled`,
//! `order_failed`, `reconcile_run`, `custody`. Entries chain via
//! SHA3-256 (Grigg's triple-entry / Haber-Stornetta model) and are
//! hybrid-signed when the operator identity is available — the same
//! chain shape `origin-attest`'s `AuditLog` verifies.

use origin_attest::audit::AuditEntry;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::OperatorKeys;
use crate::store::PaymentStore;

/// Entry types (application-defined discriminants).
pub const AT_ORDER_CREATED: u8 = 0x01;
pub const AT_ORDER_SETTLED: u8 = 0x02;
pub const AT_ORDER_FAILED: u8 = 0x03;
pub const AT_RECONCILE: u8 = 0x04;
pub const AT_CUSTODY: u8 = 0x05;
/// TTL sweep re-queued a stuck EXECUTING order (crash recovery).
pub const AT_ORDER_REQUEUED: u8 = 0x06;
/// Compliance scorer flagged the order (proceeds with a note).
pub const AT_ORDER_FLAGGED: u8 = 0x07;

/// Persisted form of an audit entry (the payload rides along so the log
/// is human-readable; the chain covers only the hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub prev_hash: [u8; 32],
    pub seq: u32,
    pub entry_type: u8,
    pub payload_hash: [u8; 32],
    pub payload: serde_json::Value,
    pub timestamp: u64,
    pub signature: Option<Vec<u8>>,
}

impl AuditRecord {
    fn to_entry(&self) -> AuditEntry {
        AuditEntry {
            prev_hash: self.prev_hash,
            seq: self.seq,
            entry_type: self.entry_type,
            payload_hash: self.payload_hash,
            timestamp: self.timestamp,
            signature: self.signature.clone(),
        }
    }
}

/// Append an audit entry, hash-chained to the log head, hybrid-signed
/// when `keys` are supplied.
pub fn record(
    store: &PaymentStore,
    entry_type: u8,
    payload: serde_json::Value,
    keys: Option<&OperatorKeys>,
) -> Result<()> {
    let records = store.audit_records()?;
    let seq = records.last().map(|r| r.seq + 1).unwrap_or(0);
    let prev_hash = records
        .last()
        .map(|r| r.to_entry().entry_hash())
        .unwrap_or([0u8; 32]);
    let payload_bytes = serde_json::to_vec(&payload).map_err(|e| Error::StoreCorrupted {
        details: format!("serializing audit payload: {e}"),
    })?;
    let payload_hash = origin_crypto_sdk::sha3_256(&payload_bytes);
    let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;

    let mut rec = AuditRecord {
        prev_hash,
        seq,
        entry_type,
        payload_hash,
        payload,
        timestamp,
        signature: None,
    };
    if let Some(k) = keys {
        let body = rec.to_entry().entry_hash();
        let sig = k
            .bundle
            .try_sign_hybrid(&body)
            .map_err(|e| Error::CryptoError {
                details: e.to_string(),
            })?;
        let hybrid = origin_crypto_sdk::signing::wire::HybridSig::from_sig(&sig);
        let mut encoded = Vec::new();
        hybrid
            .encode(&mut encoded)
            .map_err(|e| Error::CryptoError {
                details: e.to_string(),
            })?;
        rec.signature = Some(encoded);
    }
    store.append_audit_record(&rec)
}

/// Verify the full hash chain (tamper-evidence).
///
/// Verifies the PERSISTED records directly: each record's `prev_hash`
/// must equal the hash of the previous record, and each record's
/// `payload_hash` must match its own payload. (`AuditLog::append`
/// rewrites `prev_hash`, so rebuilding via append would hide tampering
/// of persisted records; the chain shape is still origin-attest's.)
pub fn verify(store: &PaymentStore) -> Result<bool> {
    let records = store.audit_records()?;
    let mut expected_prev = [0u8; 32];
    for r in &records {
        if r.prev_hash != expected_prev {
            return Ok(false);
        }
        let payload_bytes = serde_json::to_vec(&r.payload).map_err(|e| Error::StoreCorrupted {
            details: format!("serializing audit payload: {e}"),
        })?;
        if r.payload_hash != origin_crypto_sdk::sha3_256(&payload_bytes) {
            return Ok(false);
        }
        expected_prev = r.to_entry().entry_hash();
    }
    Ok(true)
}

/// Compliance export of the audit stream (P7).
pub fn export(store: &PaymentStore, format: &str, out: &std::path::Path) -> Result<()> {
    let records = store.audit_records()?;
    let doc = match format {
        "plain" => serde_json::Value::String(
            records
                .iter()
                .map(|r| {
                    format!(
                        "seq={} type=0x{:02x} ts={} payload={}",
                        r.seq,
                        r.entry_type,
                        r.timestamp,
                        serde_json::to_string(&r.payload).unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        "soc2" | "pcidss" | "hipaa" => serde_json::json!({
            "framework": format,
            "version": "1.0",
            "export_date": chrono::Utc::now().format("%Y-%m-%d").to_string(),
            "entries": records.iter().map(|r| serde_json::json!({
                "seq": r.seq,
                "entry_type": r.entry_type,
                "payload": r.payload,
                "payload_hash": hex::encode(r.payload_hash),
                "signed": r.signature.is_some(),
            })).collect::<Vec<_>>(),
        }),
        other => {
            return Err(Error::StoreCorrupted {
                details: format!("unknown export format: {other}"),
            })
        }
    };
    let bytes = serde_json::to_vec_pretty(&doc).map_err(|e| Error::StoreCorrupted {
        details: format!("serializing export: {e}"),
    })?;
    std::fs::write(out, bytes).map_err(|e| Error::IoError {
        details: format!("writing {}: {e}", out.display()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_records_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let store = PaymentStore::open(dir.path()).unwrap();
        record(
            &store,
            AT_ORDER_CREATED,
            serde_json::json!({"order": "o1"}),
            None,
        )
        .unwrap();
        record(
            &store,
            AT_ORDER_SETTLED,
            serde_json::json!({"order": "o1", "amount": "3.15"}),
            None,
        )
        .unwrap();
        record(
            &store,
            AT_RECONCILE,
            serde_json::json!({"date": "2026-08-23"}),
            None,
        )
        .unwrap();
        assert!(verify(&store).unwrap());
        assert_eq!(store.audit_records().unwrap().len(), 3);
    }

    #[test]
    fn tampered_chain_fails_verify() {
        let dir = tempfile::tempdir().unwrap();
        let store = PaymentStore::open(dir.path()).unwrap();
        record(
            &store,
            AT_ORDER_CREATED,
            serde_json::json!({"order": "o1"}),
            None,
        )
        .unwrap();
        record(
            &store,
            AT_ORDER_SETTLED,
            serde_json::json!({"order": "o1"}),
            None,
        )
        .unwrap();
        // Tamper with the first entry's payload hash — the chain breaks.
        let path = store.audit_path();
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut recs: Vec<AuditRecord> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        recs[0].payload_hash = [0xAA; 32];
        let rewritten: Vec<String> = recs
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect();
        std::fs::write(&path, rewritten.join("\n") + "\n").unwrap();
        assert_eq!(verify(&store).unwrap(), false);
    }
}
