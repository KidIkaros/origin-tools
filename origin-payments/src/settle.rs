// SPDX-License-Identifier: Apache-2.0

//! Deferred settlement (research `PAYMENTS_RESEARCH.md` §2 — Cloudflare's
//! x402 "deferred" scheme): instead of settling each x402 payment the
//! instant it is authorized, signature-verified commitments roll up into
//! **daily/batch settlement**. This is a standards-level endorsement of
//! the batching origin-payments already does in the executor +
//! reconciliation loop.
//!
//! A [`DeferredBatch`] gathers the signed payment authorizations
//! collected over a window into a single manifest whose content hash is
//! committed to the checkpoint MMR (origin-proof), so the batched-orders
//! commitment is tamper-evident before settlement is submitted. The
//! batch is then passed to the rail / facilitator to settle in one
//! operation.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::store::PaymentStore;

/// One order's authenticating material folded into a deferred batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredItem {
    pub payment_order_id: String,
    pub amount: String,
    pub currency: String,
    /// The signed x402 payment authorization that committed this payment
    /// (the base64 `PAYMENT-SIGNATURE` payload). Verified before it is
    /// admitted so the batch only ever holds genuine commitments.
    pub signed_payload: Vec<u8>,
    /// The resource URL the authorization was bound to (replay guard).
    pub resource_url: String,
}

/// A tamper-evident manifest of payments deferred into one settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredBatch {
    pub batch_id: String,
    /// ISO 8601 date the batch is settled for (the settlement window).
    pub date: String,
    pub created_at: String,
    pub items: Vec<DeferredItem>,
    /// Content hash over the canonical batch bytes (see
    /// [`batch_content_hash`]) — the MMR leaf for this batch.
    pub content_hash: [u8; 32],
    pub total_minor: i128,
}

/// Path under the payments root where deferred batches are stored.
pub fn batch_path(batch_id: &str) -> String {
    format!("settlement/deferred/{batch_id}.json")
}

/// Canonical bytes of a batch's contents — stable and order-independent
/// only where it matters (items keep their admission order, but the total
/// and date are explicit so a re-ordering is still detectable via the
/// content hash over the serialized items).
pub fn batch_content_hash(items: &[DeferredItem], date: &str) -> [u8; 32] {
    origin_crypto_sdk::sha3_256(
        &serde_json::to_vec(&serde_json::json!({
            "date": date,
            "items": items,
        }))
        .unwrap_or_default(),
    )
}

/// The merchant's authenticating material for a single deferred order.
/// `signed_payload` is the raw `PAYMENT-SIGNATURE` payload; callers must
/// verify it against the resource URL ([`crate::x402::verify_payment_payload`])
/// before admitting it — [`DeferredBatch::push`] does that check at the
/// batch level.
impl DeferredBatch {
    /// Start a new empty batch for `date`.
    pub fn new(date: &str) -> Result<Self> {
        if date.trim().is_empty() {
            return Err(Error::StoreCorrupted {
                details: "deferred batch date is empty".to_string(),
            });
        }
        let batch_id = uuid::Uuid::new_v4().to_string();
        let created_at = crate::now_rfc3339();
        Ok(DeferredBatch {
            content_hash: batch_content_hash(&[], date),
            batch_id,
            date: date.to_string(),
            created_at,
            items: Vec::new(),
            total_minor: 0,
        })
    }

    /// Append an order's signed authorization. The payload is **verified
    /// against its bound resource URL before it is admitted** — a forged
    /// or tampered `PAYMENT-SIGNATURE` is refused, so the batch never
    /// rolls up an unverifiable commitment.
    pub fn push(&mut self, item: DeferredItem) -> Result<()> {
        // The batch only holds genuine, verified commitments.
        let ok = crate::x402::verify_payment_payload(&item.signed_payload, &item.resource_url)
            .map_err(|e| Error::StoreCorrupted {
                details: format!("verifying deferred commitment: {e}"),
            })?;
        if !ok {
            return Err(Error::ReceiptVerificationFailed {
                details: format!(
                    "deferred commitment for {} did not verify — refused",
                    item.payment_order_id
                ),
            });
        }
        let minor = crate::journal::parse_amount(&item.amount)?;
        self.items.push(item);
        self.total_minor += minor;
        self.content_hash = batch_content_hash(&self.items, &self.date);
        Ok(())
    }
}

/// Roll the store's pending deferred commitments (the verified x402
/// authorizations the executor recorded during the window) into a daily
/// batch, persist it under `settlement/deferred/`, checkpoint its content
/// hash into the MMR, and clear the pending queue.
///
/// At this point the batch is **committed** (tamper-evident manifest in
/// the store + MMR root) but not yet settled; a later pass submits it to
/// the rail / facilitator in one operation. Returns the committed batch
/// (empty if nothing was pending).
pub fn commit_deferred_batch(store: &PaymentStore, date: &str) -> Result<DeferredBatch> {
    let mut batch = DeferredBatch::new(date)?;
    for item in store.deferred_commitments()? {
        // Re-verify each commitment against its bound resource URL before
        // admitting it (a forged/replayed authorization is refused).
        let ok = crate::x402::verify_payment_payload(&item.signed_payload, &item.resource_url)
            .map_err(|e| Error::StoreCorrupted {
                details: format!("verifying deferred commitment: {e}"),
            })?;
        if !ok {
            return Err(Error::ReceiptVerificationFailed {
                details: format!(
                    "deferred commitment for {} did not verify — refused",
                    item.payment_order_id
                ),
            });
        }
        batch.push(item)?;
    }
    // Persist the tamper-evident manifest.
    let bytes = serde_json::to_vec_pretty(&batch).map_err(|e| Error::StoreCorrupted {
        details: format!("serializing deferred batch: {e}"),
    })?;
    let path = store.root().join(batch_path(&batch.batch_id));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::IoError {
            details: format!("creating {}: {e}", parent.display()),
        })?;
    }
    std::fs::write(&path, bytes).map_err(|e| Error::IoError {
        details: format!("writing {}: {e}", path.display()),
    })?;
    // Tamper-evident commitment to the append-only MMR.
    store.checkpoint_mmr(batch.content_hash)?;
    // The commitments are now folded into the batch and provable.
    store.clear_deferred_commitments()?;
    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::{HybridSigner, PaymentRequirements, PaymentSigner};

    fn tmp_store() -> PaymentStore {
        let dir = tempfile::tempdir().unwrap();
        PaymentStore::open(&dir.keep()).unwrap()
    }

    fn test_keys() -> crate::identity::OperatorKeys {
        let dir = tempfile::tempdir().unwrap();
        let home = origin_common::OriginHome::with_root(dir.path().join("home")).unwrap();
        let _store = origin_common::IdentityStore::create(
            &home,
            "test-pass",
            origin_common::MemoryTier::Nano,
        )
        .unwrap();
        crate::identity::load_operator_keys_from(&home, "test-pass").unwrap()
    }

    fn a_signed_payload(resource_url: &str) -> Vec<u8> {
        let keys = test_keys();
        let signer = HybridSigner::new(&keys);
        let req = PaymentRequirements {
            accepts: vec![crate::x402::PaymentOption {
                scheme: "exact".to_string(),
                network: "eip155:8453".to_string(),
                pay_to: "0xMerchant".to_string(),
                amount: "100".to_string(),
                max_timeout_secs: Some(300),
                payment_details: serde_json::json!({}),
            }],
        };
        signer.sign(&req, resource_url).unwrap()
    }

    #[test]
    fn batch_refuses_tampered_or_forged_commitment() {
        let mut batch = DeferredBatch::new("2026-08-23").unwrap();
        let url = "http://127.0.0.1:9999/paid";
        let good = a_signed_payload(url);
        // The genuine signed payload is admitted.
        batch
            .push(DeferredItem {
                payment_order_id: "o1".to_string(),
                amount: "1.00".to_string(),
                currency: "USD".to_string(),
                signed_payload: good.clone(),
                resource_url: url.to_string(),
            })
            .unwrap();
        assert_eq!(batch.items.len(), 1);
        // A replayed-for-another-resource payload is refused.
        let err = batch
            .push(DeferredItem {
                payment_order_id: "o2".to_string(),
                amount: "1.00".to_string(),
                currency: "USD".to_string(),
                signed_payload: good,
                resource_url: "http://elsewhere/paid".to_string(),
            })
            .unwrap_err();
        assert!(matches!(err, Error::ReceiptVerificationFailed { .. }));
        assert_eq!(batch.items.len(), 1, "nothing admitted on refusal");
    }

    #[test]
    fn batch_totals_and_hashes_accumulate() {
        let mut batch = DeferredBatch::new("2026-08-23").unwrap();
        let url = "http://127.0.0.1:9999/a";
        batch
            .push(DeferredItem {
                payment_order_id: "o1".to_string(),
                amount: "1.50".to_string(),
                currency: "USD".to_string(),
                signed_payload: a_signed_payload(url),
                resource_url: url.to_string(),
            })
            .unwrap();
        assert_eq!(batch.total_minor, 150);
        let hash1 = batch.content_hash;
        batch
            .push(DeferredItem {
                payment_order_id: "o2".to_string(),
                amount: "2.50".to_string(),
                currency: "USD".to_string(),
                signed_payload: a_signed_payload(url),
                resource_url: url.to_string(),
            })
            .unwrap();
        assert_eq!(batch.total_minor, 400);
        assert_ne!(batch.content_hash, hash1, "content hash tracks additions");
    }

    #[test]
    fn commit_deferred_batch_is_persisted_and_checkpointed() {
        let s = tmp_store();
        let batch = commit_deferred_batch(&s, "2026-08-23").unwrap();
        // Persisted under the settlement dir.
        let path = s.root().join(batch_path(&batch.batch_id));
        assert!(path.exists(), "batch manifest written");
        // Its content hash is a leaf in the checkpoint MMR: the last
        // leaf's membership proof verifies against the current root.
        let mmr = s.load_mmr().unwrap();
        assert_eq!(mmr.leaf_count(), 1, "one leaf committed");
        let proof = mmr.prove(0).unwrap();
        assert!(
            mmr.verify_proof(&proof, &mmr.root()),
            "batch leaf provable in the MMR"
        );
    }
}
