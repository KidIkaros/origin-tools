//! Core attestation types: claims, endorsements, chains.
//!
//! All signing is done via injected signatures (caller provides bytes).
//! Verification uses origin-crypto-sdk's Falcon-1024 directly.
//! No dependency on any identity crate — fingerprints and keys are hex strings.

use serde::{Deserialize, Serialize};

use origin_crypto_sdk::sha3_256;

// ── Endorsement tiers ─────────────────────────────────────────────

/// Endorsement tier — how strong the vouch is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndorsementTier {
    /// Tier 1: basic attestation ("I have seen this agent").
    Tier1,
    /// Tier 2: strong vouch ("I trust this agent's capability").
    Tier2,
}

impl EndorsementTier {
    /// Convert from a u8 discriminant.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Tier1),
            2 => Some(Self::Tier2),
            _ => None,
        }
    }

    /// Convert to a u8 discriminant.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Tier1 => 1,
            Self::Tier2 => 2,
        }
    }
}

// ── Capability claim ──────────────────────────────────────────────

/// A signed claim of capabilities by an agent.
///
/// The agent asserts "I have these capabilities" and signs the claim
/// with its Falcon-1024 key. The signature is provided by the caller
/// (the identity layer signs `signable_bytes()`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityClaim {
    /// Fingerprint of the claiming agent (hex).
    pub fingerprint: String,
    /// Falcon-1024 public key (hex).
    pub falcon_pk: String,
    /// Key epoch for rotation tracking.
    pub epoch: u32,
    /// Claimed capability domains (e.g. "code-review", "translation").
    pub capabilities: Vec<String>,
    /// Free-form metadata.
    pub metadata: serde_json::Value,
    /// Unix timestamp when the claim was created.
    pub timestamp: i64,
    /// Unix timestamp when the claim expires (0 = never).
    pub expires: i64,
    /// Falcon-1024 signature over `signable_bytes()`.
    pub falcon_signature: Vec<u8>,
}

impl CapabilityClaim {
    /// Canonical bytes for signing/verification.
    ///
    /// `fingerprint || falcon_pk || epoch || capabilities || timestamp || expires`
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.fingerprint.as_bytes());
        buf.extend_from_slice(self.falcon_pk.as_bytes());
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        for cap in &self.capabilities {
            buf.extend_from_slice(cap.as_bytes());
            buf.push(0); // separator
        }
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.expires.to_be_bytes());
        buf
    }

    /// SHA3-256 hash of the signable bytes.
    pub fn hash(&self) -> [u8; 32] {
        sha3_256(&self.signable_bytes())
    }

    /// Check if this claim has expired.
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires != 0 && now > self.expires
    }

    /// Verify the Falcon-1024 signature over the signable bytes.
    ///
    /// Returns true if the signature is valid for the embedded `falcon_pk`.
    pub fn verify_signature(&self) -> bool {
        let pk_bytes = match hex::decode(&self.falcon_pk) {
            Ok(b) => b,
            Err(_) => return false,
        };
        origin_crypto_sdk::signing::postquantum::Falcon1024Signer::verify_with_pubkey(
            &pk_bytes,
            &self.signable_bytes(),
            &self.falcon_signature,
        )
    }
}

// ── Endorsement ───────────────────────────────────────────────────

/// A signed endorsement of one agent by another.
///
/// Endorsements are hash-chained: `prev_hash` links to the previous
/// endorsement in the endorser's chain. The signature covers all fields
/// including `prev_hash`, making the chain tamper-evident.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Endorsement {
    /// Endorsement tier (Tier1 = attestation, Tier2 = vouch).
    pub tier: EndorsementTier,
    /// Fingerprint of the endorsing agent (hex).
    pub endorser_fp: String,
    /// Fingerprint of the endorsed agent (hex).
    pub endorsee_fp: String,
    /// Capability domain this endorsement covers.
    pub capability_domain: String,
    /// Confidence score [0.0, 1.0].
    pub confidence: f64,
    /// Free-form context/reason.
    pub context: String,
    /// Unix timestamp when the endorsement was created.
    pub timestamp: i64,
    /// Unix timestamp when the endorsement expires (0 = never).
    pub valid_until: i64,
    /// Hash of the previous endorsement in the chain (zeros for first).
    pub prev_hash: [u8; 32],
    /// Monotonic nonce to prevent replay.
    pub nonce: u64,
    /// Falcon-1024 signature over `signable_bytes()`.
    pub falcon_signature: Vec<u8>,
    /// Whether this endorsement has been revoked.
    pub revocation: bool,
    /// Hash of the endorsement this one supersedes (if any).
    pub supersedes: Option<[u8; 32]>,
}

impl Endorsement {
    /// Canonical bytes for signing/verification.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.tier.as_u8());
        buf.extend_from_slice(self.endorser_fp.as_bytes());
        buf.extend_from_slice(self.endorsee_fp.as_bytes());
        buf.extend_from_slice(self.capability_domain.as_bytes());
        buf.extend_from_slice(&self.confidence.to_be_bytes());
        buf.extend_from_slice(self.context.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.valid_until.to_be_bytes());
        buf.extend_from_slice(&self.prev_hash);
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        buf.extend_from_slice(&[self.revocation as u8]);
        if let Some(ref s) = self.supersedes {
            buf.extend_from_slice(s);
        }
        buf
    }

    /// SHA3-256 hash of this endorsement.
    pub fn hash(&self) -> [u8; 32] {
        sha3_256(&self.signable_bytes())
    }

    /// Check if this endorsement has expired.
    pub fn is_expired(&self, now: i64) -> bool {
        self.valid_until != 0 && now > self.valid_until
    }

    /// Check if this endorsement is currently valid (not expired, not revoked).
    pub fn is_valid(&self, now: i64) -> bool {
        !self.revocation && !self.is_expired(now)
    }

    /// Verify the Falcon-1024 signature.
    ///
    /// Requires the endorser's public key (hex) since the endorsement
    /// only stores the endorser's fingerprint.
    pub fn verify_signature(&self, endorser_falcon_pk_hex: &str) -> bool {
        let pk_bytes = match hex::decode(endorser_falcon_pk_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        origin_crypto_sdk::signing::postquantum::Falcon1024Signer::verify_with_pubkey(
            &pk_bytes,
            &self.signable_bytes(),
            &self.falcon_signature,
        )
    }
}

// ── Endorsement chain ─────────────────────────────────────────────

/// A hash-chained sequence of endorsements.
///
/// Each endorsement's `prev_hash` must equal the hash of the previous
/// endorsement in the chain. The first endorsement has `prev_hash` of
/// all zeros.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EndorsementChain {
    /// Ordered list of endorsements.
    pub endorsements: Vec<Endorsement>,
}

impl EndorsementChain {
    /// Create an empty chain.
    pub fn new() -> Self {
        Self {
            endorsements: Vec::new(),
        }
    }

    /// Append an endorsement to the chain.
    ///
    /// Sets the endorsement's `prev_hash` to the current tip hash
    /// before appending.
    pub fn append(&mut self, mut endorsement: Endorsement) {
        endorsement.prev_hash = self.tip_hash();
        self.endorsements.push(endorsement);
    }

    /// Hash of the last endorsement (zeros if empty).
    pub fn tip_hash(&self) -> [u8; 32] {
        self.endorsements
            .last()
            .map(|e| e.hash())
            .unwrap_or([0u8; 32])
    }

    /// Hash of the first endorsement (zeros if empty).
    pub fn root_hash(&self) -> [u8; 32] {
        self.endorsements
            .first()
            .map(|e| e.hash())
            .unwrap_or([0u8; 32])
    }

    /// Verify the integrity of the entire hash chain.
    ///
    /// Checks that each endorsement's `prev_hash` matches the hash of
    /// the previous endorsement.
    pub fn verify_integrity(&self) -> Result<(), crate::error::AttestError> {
        let mut expected_prev = [0u8; 32];
        for (i, endorsement) in self.endorsements.iter().enumerate() {
            if endorsement.prev_hash != expected_prev {
                return Err(crate::error::AttestError::ChainBroken(i));
            }
            expected_prev = endorsement.hash();
        }
        Ok(())
    }

    /// Number of endorsements in the chain.
    pub fn len(&self) -> usize {
        self.endorsements.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.endorsements.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claim(fp: &str) -> CapabilityClaim {
        CapabilityClaim {
            fingerprint: fp.to_string(),
            falcon_pk: "aa".repeat(897), // placeholder
            epoch: 1,
            capabilities: vec!["code-review".to_string()],
            metadata: serde_json::json!({}),
            timestamp: 1000,
            expires: 0,
            falcon_signature: vec![],
        }
    }

    fn make_endorsement(endorser: &str, endorsee: &str, domain: &str) -> Endorsement {
        Endorsement {
            tier: EndorsementTier::Tier2,
            endorser_fp: endorser.to_string(),
            endorsee_fp: endorsee.to_string(),
            capability_domain: domain.to_string(),
            confidence: 0.9,
            context: "test".to_string(),
            timestamp: 1000,
            valid_until: 0,
            prev_hash: [0u8; 32],
            nonce: 1,
            falcon_signature: vec![],
            revocation: false,
            supersedes: None,
        }
    }

    #[test]
    fn test_claim_signable_bytes_deterministic() {
        let c1 = make_claim("abc");
        let c2 = make_claim("abc");
        assert_eq!(c1.signable_bytes(), c2.signable_bytes());
        assert_eq!(c1.hash(), c2.hash());
    }

    #[test]
    fn test_claim_expiry() {
        let mut c = make_claim("abc");
        assert!(!c.is_expired(500));
        c.expires = 1000;
        assert!(!c.is_expired(999));
        assert!(c.is_expired(1001));
    }

    #[test]
    fn test_endorsement_signable_bytes_deterministic() {
        let e1 = make_endorsement("a", "b", "rust");
        let e2 = make_endorsement("a", "b", "rust");
        assert_eq!(e1.signable_bytes(), e2.signable_bytes());
        assert_eq!(e1.hash(), e2.hash());
    }

    #[test]
    fn test_endorsement_validity() {
        let mut e = make_endorsement("a", "b", "rust");
        assert!(e.is_valid(500));
        e.valid_until = 1000;
        assert!(e.is_valid(999));
        assert!(!e.is_valid(1001));
        e.revocation = true;
        assert!(!e.is_valid(500));
    }

    #[test]
    fn test_endorsement_tier_roundtrip() {
        assert_eq!(EndorsementTier::from_u8(1), Some(EndorsementTier::Tier1));
        assert_eq!(EndorsementTier::from_u8(2), Some(EndorsementTier::Tier2));
        assert_eq!(EndorsementTier::from_u8(3), None);
        assert_eq!(EndorsementTier::Tier1.as_u8(), 1);
        assert_eq!(EndorsementTier::Tier2.as_u8(), 2);
    }

    #[test]
    fn test_chain_append_sets_prev_hash() {
        let mut chain = EndorsementChain::new();
        assert_eq!(chain.tip_hash(), [0u8; 32]);

        let e1 = make_endorsement("a", "b", "rust");
        chain.append(e1);
        assert_eq!(chain.endorsements[0].prev_hash, [0u8; 32]);

        let tip1 = chain.tip_hash();
        let e2 = make_endorsement("b", "c", "rust");
        chain.append(e2);
        assert_eq!(chain.endorsements[1].prev_hash, tip1);
    }

    #[test]
    fn test_chain_verify_integrity() {
        let mut chain = EndorsementChain::new();
        chain.append(make_endorsement("a", "b", "rust"));
        chain.append(make_endorsement("b", "c", "rust"));
        chain.append(make_endorsement("c", "d", "rust"));
        assert!(chain.verify_integrity().is_ok());
    }

    #[test]
    fn test_chain_tamper_detection() {
        let mut chain = EndorsementChain::new();
        chain.append(make_endorsement("a", "b", "rust"));
        chain.append(make_endorsement("b", "c", "rust"));

        // Tamper with the first endorsement
        chain.endorsements[0].confidence = 0.1;
        assert!(chain.verify_integrity().is_err());
    }

    #[test]
    fn test_chain_root_and_tip() {
        let mut chain = EndorsementChain::new();
        assert_eq!(chain.root_hash(), [0u8; 32]);
        assert_eq!(chain.tip_hash(), [0u8; 32]);

        chain.append(make_endorsement("a", "b", "rust"));
        let root = chain.root_hash();
        assert_ne!(root, [0u8; 32]);

        chain.append(make_endorsement("b", "c", "rust"));
        // Root stays the same
        assert_eq!(chain.root_hash(), root);
        // Tip changes
        assert_ne!(chain.tip_hash(), root);
    }

    #[test]
    fn test_chain_len() {
        let mut chain = EndorsementChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        chain.append(make_endorsement("a", "b", "rust"));
        assert!(!chain.is_empty());
        assert_eq!(chain.len(), 1);
    }
}
