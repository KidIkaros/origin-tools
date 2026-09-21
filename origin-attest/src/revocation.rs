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
    ///
    /// For signed records this MUST equal `revoker_fingerprint_hex(&revoker_falcon_pk)`
    /// (see [`revoker_fingerprint_hex`]) — the journal-native identity convention.
    /// Legacy unsigned records may carry any label.
    pub revoked_by: String,
    /// Human-readable reason.
    pub reason: String,
    /// Unix timestamp of the revocation.
    pub timestamp: i64,
    /// SHA3-256 hash of the previous revocation (zeros for first).
    pub prev_hash: [u8; 32],
    /// Falcon-1024 signature over `signable_bytes()`.
    pub signature: Vec<u8>,
    /// Falcon-1024 public key of the revoker (optional; empty for legacy records).
    ///
    /// Carrying the pk makes the record self-verifiable with no external
    /// fingerprint→pk mapping (OQ1 distribution brief, ticket 08). The pk is
    /// authenticated transitively: the signature binds the content, and the
    /// fingerprint-consistency check in [`RevocationRecord::verify_signature`]
    /// binds the pk to `revoked_by`. `signable_bytes()` deliberately does NOT
    /// include this field — it feeds `hash()`, which anchors the journal chain.
    #[serde(default)]
    pub revoker_falcon_pk: Vec<u8>,
}

/// Journal-native identity convention: hex SHA3-256 of the revoker's Falcon-1024
/// public key. Signed records must carry `revoked_by` equal to this over their
/// embedded pk.
pub fn revoker_fingerprint_hex(falcon_pk: &[u8]) -> String {
    hex::encode(origin_crypto_sdk::sha3_256(falcon_pk))
}

/// Result of verifying a record's signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Signature present, pk carried, fingerprint consistent, Falcon verify passed.
    Valid,
    /// No signature — a legacy (pre-ticket-08) record. Not a failure; classified.
    Unsigned,
    /// Signature present but verification failed: tampered content/signature,
    /// missing pk carrier, or pk inconsistent with `revoked_by`.
    Invalid,
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

    /// Verify this record's Falcon-1024 signature.
    ///
    /// Classification (never panics):
    /// - empty `signature` ⇒ [`SignatureStatus::Unsigned`] (legacy record)
    /// - signed but empty `revoker_falcon_pk` ⇒ [`SignatureStatus::Invalid`]
    ///   (a signed record with no pk carrier is unverifiable by design)
    /// - pk inconsistent with `revoked_by` (fingerprint mismatch) ⇒ [`SignatureStatus::Invalid`]
    /// - otherwise Falcon-1024 verify over `signable_bytes()`
    pub fn verify_signature(&self) -> SignatureStatus {
        if self.signature.is_empty() {
            return SignatureStatus::Unsigned;
        }
        if self.revoker_falcon_pk.is_empty() {
            return SignatureStatus::Invalid;
        }
        if self.revoked_by != revoker_fingerprint_hex(&self.revoker_falcon_pk) {
            return SignatureStatus::Invalid;
        }
        if !origin_crypto_sdk::signing::postquantum::Falcon1024Signer::verify_with_pubkey(
            &self.revoker_falcon_pk,
            &self.signable_bytes(),
            &self.signature,
        ) {
            return SignatureStatus::Invalid;
        }
        SignatureStatus::Valid
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

    /// Append a **signed** revocation record.
    ///
    /// Sequences the fields that must be derived at append time: sets
    /// `prev_hash` to the current tip, fills `revoker_falcon_pk` and
    /// `revoked_by` from the signer (overriding any caller-supplied values —
    /// this method owns the record's identity fields), signs
    /// `signable_bytes()` with Falcon-1024, then pushes.
    ///
    /// Callers supply `target_hash`, `reason`, and `timestamp`. Use
    /// [`RevocationJournal::verify_signatures`] to audit the result.
    pub fn append_signed(
        &mut self,
        mut record: RevocationRecord,
        signer: &origin_crypto_sdk::signing::postquantum::Falcon1024Signer,
    ) -> crate::Result<()> {
        record.prev_hash = self.tip_hash();
        record.revoker_falcon_pk = signer.public_key_bytes();
        record.revoked_by = revoker_fingerprint_hex(&record.revoker_falcon_pk);
        record.signature = signer
            .sign(&record.signable_bytes())
            .map_err(|e| crate::error::AttestError::Crypto(e.to_string()))?;
        self.records.push(record);
        Ok(())
    }

    /// Indices of records whose signatures FAIL verification.
    ///
    /// [`SignatureStatus::Unsigned`] (legacy) and [`SignatureStatus::Valid`]
    /// records are not failures — only [`SignatureStatus::Invalid`] is reported.
    /// Distinct from [`RevocationJournal::verify_integrity`], which checks the
    /// hash chain: "chain broken" and "record forged" are different findings.
    pub fn verify_signatures(&self) -> Vec<usize> {
        self.records
            .iter()
            .enumerate()
            .filter(|(_, r)| r.verify_signature() == SignatureStatus::Invalid)
            .map(|(i, _)| i)
            .collect()
    }

    /// Hash of the last record (zeros if empty).
    pub fn tip_hash(&self) -> [u8; 32] {
        self.records.last().map(|r| r.hash()).unwrap_or([0u8; 32])
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
            revoker_falcon_pk: vec![],
        }
    }

    #[test]
    fn test_signed_record_roundtrip_and_audit() {
        let mut journal = RevocationJournal::new();
        let signer =
            origin_crypto_sdk::signing::postquantum::Falcon1024Signer::from_seed(&[7u8; 32])
                .expect("valid seed");

        journal
            .append_signed(make_revocation([9u8; 32], "will-be-overridden"), &signer)
            .expect("sign");
        // Unsigned legacy record coexists with signed ones
        journal.append(make_revocation([1u8; 32], "legacy-label"));

        // Identity fields are journal-owned
        let rec = &journal.records[0];
        assert_eq!(
            rec.revoked_by,
            revoker_fingerprint_hex(&rec.revoker_falcon_pk)
        );
        assert_eq!(rec.verify_signature(), SignatureStatus::Valid);
        assert_eq!(
            journal.records[1].verify_signature(),
            SignatureStatus::Unsigned
        );

        // Journal audit: no failures (valid + unsigned are not failures)
        assert!(journal.verify_signatures().is_empty());
        // Chain still verifies with mixed records
        assert!(journal.verify_integrity().is_ok());
    }

    #[test]
    fn test_tampered_record_fails() {
        let mut journal = RevocationJournal::new();
        let signer =
            origin_crypto_sdk::signing::postquantum::Falcon1024Signer::from_seed(&[8u8; 32])
                .expect("valid seed");
        journal
            .append_signed(make_revocation([5u8; 32], "x"), &signer)
            .expect("sign");

        // Tamper the content AFTER signing
        let mut rec = journal.records.pop().unwrap();
        rec.reason = "tampered".to_string();
        assert_eq!(rec.verify_signature(), SignatureStatus::Invalid);
    }

    /// Cross-check against an independent Python reference (ticket 08).
    ///
    /// Golden values below were derived with Python `hashlib.sha3_256` over the
    /// re-derived serialization recipe — NOT by calling this crate. Covers: pk
    /// size, the `hex(sha3_256(pk))` fingerprint convention, and the
    /// `signable_bytes` → `hash()` recipe that anchors the journal chain.
    /// Falcon sign/verify itself is the SDK's pre-existing audited primitive;
    /// no independent Python Falcon implementation is available in this
    /// environment (probed: `oqs`, `cryptography.falcon` — both absent).
    #[test]
    fn test_cross_check_python_goldens() {
        let signer =
            origin_crypto_sdk::signing::postquantum::Falcon1024Signer::from_seed(&[7u8; 32])
                .expect("valid seed");
        let pk = signer.public_key_bytes();
        assert_eq!(pk.len(), 1793, "Falcon-1024 pk size (python-confirmed)");
        assert_eq!(
            revoker_fingerprint_hex(&pk),
            "48f0554a3743debbed3308f4b9ef17578864affe7d8bedef0af0070d70193633"
        );

        let rec = RevocationRecord {
            target_hash: [9u8; 32],
            revoked_by: revoker_fingerprint_hex(&pk),
            reason: "compromised".to_string(),
            timestamp: 1000,
            prev_hash: [0u8; 32],
            signature: vec![],
            revoker_falcon_pk: pk,
        };
        assert_eq!(
            hex::encode(rec.hash()),
            "d76d0e23eb5120a6d1dc02e3f1149ff59891a69e3e499b983a6d744178b383f3"
        );
    }

    /// Serde backward-compat: a pre-ticket-08 journal (JSON without the
    /// `revoker_falcon_pk` field) must deserialize and classify as Unsigned.
    #[test]
    fn test_legacy_json_deserializes() {
        let legacy_json = r#"{
            "target_hash": [9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],
            "revoked_by": "legacy-label",
            "reason": "compromised",
            "timestamp": 1000,
            "prev_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "signature": []
        }"#;
        let rec: RevocationRecord =
            serde_json::from_str(legacy_json).expect("legacy record deserializes");
        assert!(rec.revoker_falcon_pk.is_empty());
        assert_eq!(rec.verify_signature(), SignatureStatus::Unsigned);
    }

    #[test]
    fn test_pk_swap_fails_fingerprint_consistency() {
        let mut journal = RevocationJournal::new();
        let signer_a =
            origin_crypto_sdk::signing::postquantum::Falcon1024Signer::from_seed(&[1u8; 32])
                .expect("valid seed");
        let signer_b =
            origin_crypto_sdk::signing::postquantum::Falcon1024Signer::from_seed(&[2u8; 32])
                .expect("valid seed");
        journal
            .append_signed(make_revocation([5u8; 32], "x"), &signer_a)
            .expect("sign");

        let mut rec = journal.records.pop().unwrap();
        // Swap in B's pk (signature still A's) — fingerprint consistency must catch it
        rec.revoker_falcon_pk = signer_b.public_key_bytes();
        assert_eq!(rec.verify_signature(), SignatureStatus::Invalid);
    }

    #[test]
    fn test_signed_record_without_pk_is_invalid() {
        let signer =
            origin_crypto_sdk::signing::postquantum::Falcon1024Signer::from_seed(&[3u8; 32])
                .expect("valid seed");
        let mut rec = make_revocation([5u8; 32], "x");
        rec.prev_hash = [0u8; 32];
        rec.signature = signer.sign(&rec.signable_bytes()).expect("sign");
        // pk carrier left empty
        assert_eq!(rec.verify_signature(), SignatureStatus::Invalid);
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
