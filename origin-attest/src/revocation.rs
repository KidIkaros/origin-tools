//! Revocation journal — track revoked claims and endorsements.
//!
//! A revocation journal is an append-only record of revocations.
//! Each revocation references the hash of the item being revoked
//! and includes a reason and timestamp.

use serde::{Deserialize, Serialize};

use origin_crypto_sdk::sha3_256;

/// A single revocation record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// SHA3-256 hash of the revoked item (claim or endorsement).
    pub target_hash: [u8; 32],
    /// Fingerprint of the entity that issued the revocation (hex).
    pub revoked_by: String,
    /// Human-readable reason.
    pub reason: String,
    /// Unix timestamp of the revocation.
    pub timestamp: i64,
    /// SHA3-256 hash of the previous revocation (zeros for first).
    pub prev_hash: [u8; 32],
    /// Falcon-1024 signature over `signable_bytes()`.
    pub signature: Vec<u8>,
}

impl RevocationRecord {
    /// Canonical bytes for signing/verification.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.target_hash);
        buf.extend_from_slice(self.revoked_by.as_bytes());
        buf.extend_from_slice(self.reason.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.prev_hash);
        buf
    }

    /// SHA3-256 hash of this revocation record.
    pub fn hash(&self) -> [u8; 32] {
        sha3_256(&self.signable_bytes())
    }
}

/// Append-only journal of revocations, hash-chained.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RevocationJournal {
    /// Ordered revocation records.
    pub records: Vec<RevocationRecord>,
}

impl RevocationJournal {
    /// Create an empty journal.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Append a revocation, setting its `prev_hash` to the current tip.
    pub fn append(&mut self, mut record: RevocationRecord) {
        record.prev_hash = self.tip_hash();
        self.records.push(record);
    }

    /// Hash of the last record (zeros if empty).
    pub fn tip_hash(&self) -> [u8; 32] {
        self.records
            .last()
            .map(|r| r.hash())
            .unwrap_or([0u8; 32])
    }

    /// Check if a given hash has been revoked.
    pub fn is_revoked(&self, target_hash: &[u8; 32]) -> bool {
        self.records.iter().any(|r| &r.target_hash == target_hash)
    }

    /// Get the revocation record for a given target hash, if any.
    pub fn get_revocation(&self, target_hash: &[u8; 32]) -> Option<&RevocationRecord> {
        self.records.iter().find(|r| &r.target_hash == target_hash)
    }

    /// Verify the integrity of the hash chain.
    pub fn verify_integrity(&self) -> Result<(), crate::error::AttestError> {
        let mut expected_prev = [0u8; 32];
        for (i, record) in self.records.iter().enumerate() {
            if record.prev_hash != expected_prev {
                return Err(crate::error::AttestError::ChainBroken(i));
            }
            expected_prev = record.hash();
        }
        Ok(())
    }

    /// Number of revocation records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the journal is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_revocation(target: [u8; 32], by: &str) -> RevocationRecord {
        RevocationRecord {
            target_hash: target,
            revoked_by: by.to_string(),
            reason: "compromised".to_string(),
            timestamp: 1000,
            prev_hash: [0u8; 32],
            signature: vec![],
        }
    }

    #[test]
    fn test_journal_append_chains() {
        let mut journal = RevocationJournal::new();
        assert!(journal.is_empty());

        let target1 = [1u8; 32];
        journal.append(make_revocation(target1, "admin"));
        assert_eq!(journal.records[0].prev_hash, [0u8; 32]);

        let tip1 = journal.tip_hash();
        let target2 = [2u8; 32];
        journal.append(make_revocation(target2, "admin"));
        assert_eq!(journal.records[1].prev_hash, tip1);
    }

    #[test]
    fn test_journal_is_revoked() {
        let mut journal = RevocationJournal::new();
        let target = [0xAB; 32];
        assert!(!journal.is_revoked(&target));

        journal.append(make_revocation(target, "admin"));
        assert!(journal.is_revoked(&target));
        assert!(!journal.is_revoked(&[0xCD; 32]));
    }

    #[test]
    fn test_journal_get_revocation() {
        let mut journal = RevocationJournal::new();
        let target = [0xAB; 32];
        journal.append(make_revocation(target, "admin"));

        let record = journal.get_revocation(&target).unwrap();
        assert_eq!(record.revoked_by, "admin");
        assert_eq!(record.reason, "compromised");
        assert!(journal.get_revocation(&[0xFF; 32]).is_none());
    }

    #[test]
    fn test_journal_verify_integrity() {
        let mut journal = RevocationJournal::new();
        journal.append(make_revocation([1u8; 32], "a"));
        journal.append(make_revocation([2u8; 32], "b"));
        journal.append(make_revocation([3u8; 32], "c"));
        assert!(journal.verify_integrity().is_ok());
    }

    #[test]
    fn test_journal_tamper_detection() {
        let mut journal = RevocationJournal::new();
        journal.append(make_revocation([1u8; 32], "a"));
        journal.append(make_revocation([2u8; 32], "b"));

        // Tamper with the first record
        journal.records[0].reason = "hacked".to_string();
        assert!(journal.verify_integrity().is_err());
    }

    #[test]
    fn test_revocation_record_hash_deterministic() {
        let r1 = make_revocation([1u8; 32], "admin");
        let r2 = make_revocation([1u8; 32], "admin");
        assert_eq!(r1.hash(), r2.hash());
    }
}
