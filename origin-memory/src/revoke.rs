// SPDX-License-Identifier: Apache-2.0

//! revoke — tamper-evident retraction built on origin-attest's revocation journal.
//!
//! Retraction is an append-only, hash-chained journal: a node is never deleted
//! (that would break provenance and the layer MMRs), it is *revoked* by content
//! hash. The journal is signed with the origin-crypto-sdk Falcon-1024 component
//! (reusing `HybridSigningKeyBundle::sign_hybrid`), so a revocation is itself
//! attributable and the chain is verifiable (`verify_integrity`).

use origin_attest::revocation::{RevocationJournal, RevocationRecord};
use origin_crypto_sdk::pqc::falcon1024::{verify as falcon_verify, FalconSignature};
use origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle;
use std::path::{Path, PathBuf};

pub struct RevocationStore {
    journal: RevocationJournal,
    path: PathBuf,
}

impl RevocationStore {
    pub fn open(root: &Path) -> Self {
        let path = root.join("revocations.json");
        let journal = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { journal, path }
    }

    /// Revoke a node by its content hash. `revoked_by` is the signer fingerprint
    /// (the bundle's Ed25519 public key hex). Returns the appended record.
    pub fn revoke(
        &mut self,
        content_hash: [u8; 32],
        revoked_by: &str,
        reason: &str,
        bundle: &HybridSigningKeyBundle,
    ) -> RevocationRecord {
        let mut record = RevocationRecord {
            target_hash: content_hash,
            revoked_by: revoked_by.to_string(),
            reason: reason.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            prev_hash: self.journal.tip_hash(),
            signature: Vec::new(),
        };
        // Sign with the Falcon-1024 component of the hybrid bundle.
        let falcon_sig = bundle.sign_hybrid(&record.signable_bytes()).falcon_sig;
        record.signature = falcon_sig.as_bytes().to_vec();
        self.journal.append(record.clone());
        let _ = self.persist();
        record
    }

    /// Is this content hash revoked?
    pub fn is_revoked(&self, content_hash: &[u8; 32]) -> bool {
        self.journal.is_revoked(content_hash)
    }

    /// Verify the hash chain AND every record's Falcon-1024 signature.
    pub fn verify(&self, bundle: &HybridSigningKeyBundle) -> bool {
        if self.journal.verify_integrity().is_err() {
            return false;
        }
        for r in &self.journal.records {
            let falcon_sig = match FalconSignature::from_bytes(&r.signature) {
                Ok(s) => s,
                Err(_) => return false,
            };
            if falcon_verify(&r.signable_bytes(), &falcon_sig, bundle.falcon1024_pk()).is_err() {
                return false;
            }
        }
        true
    }

    pub fn len(&self) -> usize {
        self.journal.len()
    }

    pub fn is_empty(&self) -> bool {
        self.journal.is_empty()
    }

    fn persist(&self) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(&self.journal)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&self.path, json)
    }
}
