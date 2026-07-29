//! Hash-chained audit log for session interactions.
//!
//! Each entry in a session can be recorded in an append-only hash chain.
//! The chain proves temporal ordering and integrity of all entries.
//! Both sides of a session hold identical logs — no server can unilaterally
//! alter history (Grigg's triple-entry accounting).
//!
//! The audit log is optional — agents can opt out for privacy. If present,
//! it is deniable but shows message ordering if needed by a third party
//! for adjudication (Haber-Stornetta timestamping model).

use origin_crypto_sdk::sha3_256;

/// A single entry in the hash-chained audit log.
#[derive(Clone, Debug)]
pub struct AuditEntry {
    /// SHA3-256 hash of the previous entry (all zeros for the first entry).
    pub prev_hash: [u8; 32],
    /// Entry sequence number.
    pub seq: u32,
    /// Entry type discriminant (application-defined).
    pub entry_type: u8,
    /// SHA3-256 hash of the payload.
    pub payload_hash: [u8; 32],
    /// Unix-nanos timestamp.
    pub timestamp: u64,
    /// Optional signature of this entry (authenticated sessions only).
    pub signature: Option<Vec<u8>>,
}

impl AuditEntry {
    /// Compute the hash of this entry for chaining.
    /// hash = SHA3-256(prev_hash || seq || entry_type || payload_hash || timestamp)
    pub fn entry_hash(&self) -> [u8; 32] {
        let mut combined = Vec::with_capacity(32 + 4 + 1 + 32 + 8);
        combined.extend_from_slice(&self.prev_hash);
        combined.extend_from_slice(&self.seq.to_be_bytes());
        combined.extend_from_slice(&[self.entry_type]);
        combined.extend_from_slice(&self.payload_hash);
        combined.extend_from_slice(&self.timestamp.to_be_bytes());
        sha3_256(&combined)
    }
}

/// Append-only hash-chained audit log.
#[derive(Clone, Debug)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    /// SHA3-256 of the last entry — the chain root. All zeros when empty.
    pub root_hash: [u8; 32],
}

impl AuditLog {
    /// Create a new empty audit log.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            root_hash: [0u8; 32],
        }
    }

    /// Append a new entry to the chain.
    pub fn append(&mut self, mut entry: AuditEntry) {
        entry.prev_hash = self.root_hash;
        self.root_hash = entry.entry_hash();
        self.entries.push(entry);
    }

    /// Get the number of entries in the log.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get a reference to all entries.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Verify the integrity of the entire hash chain.
    pub fn verify_chain(&self) -> Result<bool, crate::error::AttestError> {
        if self.entries.is_empty() {
            return Ok(true);
        }

        let mut expected_prev = [0u8; 32];
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.prev_hash != expected_prev {
                return Err(crate::error::AttestError::AuditBroken(i));
            }
            expected_prev = entry.entry_hash();
        }

        if self.root_hash != expected_prev {
            return Err(crate::error::AttestError::AuditBroken(self.entries.len()));
        }

        Ok(true)
    }

    /// Extract the sequence numbers of all entries.
    pub fn seqs(&self) -> Vec<u32> {
        self.entries.iter().map(|e| e.seq).collect()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(seq: u32, entry_type: u8) -> AuditEntry {
        AuditEntry {
            prev_hash: [0u8; 32],
            seq,
            entry_type,
            payload_hash: [0u8; 32],
            timestamp: 0,
            signature: None,
        }
    }

    #[test]
    fn test_empty_log() {
        let log = AuditLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn test_append_and_verify() {
        let mut log = AuditLog::new();
        log.append(make_entry(1, 3));
        log.append(make_entry(2, 4));
        log.append(make_entry(3, 5));

        assert_eq!(log.len(), 3);
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn test_tamper_detection() {
        let mut log = AuditLog::new();
        log.append(make_entry(1, 3));
        log.append(make_entry(2, 4));
        log.append(make_entry(3, 5));

        // Tamper: modify an entry's type
        log.entries[1].entry_type = 99;
        assert!(log.verify_chain().is_err());
    }

    #[test]
    fn test_root_hash_tamper() {
        let mut log = AuditLog::new();
        log.append(make_entry(1, 3));
        log.append(make_entry(2, 4));

        log.root_hash = [1u8; 32];
        assert!(log.verify_chain().is_err());
    }

    #[test]
    fn test_entry_hash_deterministic() {
        let e1 = make_entry(1, 3);
        let e2 = make_entry(1, 3);
        assert_eq!(e1.entry_hash(), e2.entry_hash());
    }

    #[test]
    fn test_entry_ordering() {
        let mut log = AuditLog::new();
        log.append(make_entry(1, 3));
        log.append(make_entry(2, 4));
        log.append(make_entry(3, 5));

        assert_eq!(log.seqs(), vec![1, 2, 3]);
    }
}
