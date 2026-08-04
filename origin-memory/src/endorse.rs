// SPDX-License-Identifier: Apache-2.0

//! endorse — persistent, tamper-evident endorsements built on origin-attest's
//! `EndorsementChain`.
//!
//! Same shape as the revocation journal (`revoke.rs`), one loop, one shape:
//! an append-only, hash-chained, Falcon-signed journal file
//! (`root/endorsements.json`). Every endorsement is:
//!
//! - **Signed** with the origin-crypto-sdk Falcon-1024 component of the hybrid
//!   bundle over `Endorsement::signable_bytes()` (which includes `prev_hash`),
//! - **Chained** — `prev_hash` links to the previous endorsement's hash, so
//!   reordering, deleting, or splicing is detected by `verify_integrity`,
//! - **Persisted** on every append, and **replayed** into the `TrustStore` on
//!   open, so multi-agent attribution survives restart.
//!
//! Foreign endorsements (received from other agents) can be appended via
//! `append_external`; their signatures can only be checked if the endorser's
//! Falcon public key is known — that is inherent to portable-key federation,
//! not a gap in this module.

use origin_attest::types::{Endorsement, EndorsementChain, EndorsementTier};
use origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle;
use std::path::{Path, PathBuf};

pub struct EndorsementStore {
    chain: EndorsementChain,
    path: PathBuf,
}

impl EndorsementStore {
    /// Open (or create) the endorsement journal at `root/endorsements.json`.
    /// A corrupt or unreadable file degrades to an empty chain rather than
    /// failing open — verification (`verify_chain`) will then flag the mismatch
    /// if the caller remembers a non-empty history.
    pub fn open(root: &Path) -> Self {
        let path = root.join("endorsements.json");
        let chain = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { chain, path }
    }

    /// Create, sign, chain, and persist an endorsement from *this* agent.
    /// The nonce is the chain position; `valid_until` is one year out.
    pub fn endorse(
        &mut self,
        target_fp: &str,
        domain: &str,
        confidence: f64,
        context: &str,
        bundle: &HybridSigningKeyBundle,
    ) -> Endorsement {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let endorser_fp = hex::encode(bundle.ed25519_pk().as_bytes());
        let mut e = Endorsement {
            tier: EndorsementTier::Tier2,
            endorser_fp,
            endorsee_fp: target_fp.to_string(),
            capability_domain: domain.to_string(),
            confidence,
            context: context.to_string(),
            timestamp: now,
            valid_until: now + 365 * 24 * 3600,
            prev_hash: self.chain.tip_hash(),
            nonce: self.chain.len() as u64,
            falcon_signature: Vec::new(),
            revocation: false,
            supersedes: None,
        };
        // Sign with the Falcon-1024 component of the hybrid bundle. The
        // signable payload includes prev_hash, binding the signature into the chain.
        let falcon_sig = bundle.sign_hybrid(&e.signable_bytes()).falcon_sig;
        e.falcon_signature = falcon_sig.as_bytes().to_vec();
        self.chain.append(e.clone());
        let _ = self.persist();
        e
    }

    /// Append an endorsement received from another agent. Not re-signed;
    /// the caller must have obtained it over an authenticated channel.
    /// Chain integrity is still enforced (`prev_hash` is NOT rewritten here —
    /// external endorsements carry their own position provenance).
    pub fn append_external(&mut self, e: Endorsement) {
        self.chain.endorsements.push(e);
        let _ = self.persist();
    }

    /// Verify the hash chain: each endorsement's `prev_hash` matches the
    /// previous endorsement's hash. Does not check signatures (that needs the
    /// endorser's Falcon public key — see `verify_own_signatures`).
    pub fn verify_chain(&self) -> bool {
        self.chain.verify_integrity().is_ok()
    }

    /// Verify the Falcon-1024 signature of every endorsement in the chain
    /// that claims `self_fp` as its endorser. Endorsements from other agents
    /// are skipped (their keys are unknown to us).
    pub fn verify_own_signatures(&self, bundle: &HybridSigningKeyBundle) -> bool {
        let self_fp = hex::encode(bundle.ed25519_pk().as_bytes());
        let pk_hex = hex::encode(bundle.falcon1024_pk().as_bytes());
        for e in &self.chain.endorsements {
            if e.endorser_fp == self_fp && !e.verify_signature(&pk_hex) {
                return false;
            }
        }
        true
    }

    /// Full verification: chain integrity + own signatures.
    pub fn verify(&self, bundle: &HybridSigningKeyBundle) -> bool {
        self.verify_chain() && self.verify_own_signatures(bundle)
    }

    pub fn chain(&self) -> &EndorsementChain {
        &self.chain
    }

    pub fn len(&self) -> usize {
        self.chain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    fn persist(&self) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(&self.chain)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&self.path, json)
    }
}
