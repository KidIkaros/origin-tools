// SPDX-License-Identifier: Apache-2.0

//! Signed delegation attestations — the mechanism behind "acting on behalf of"
//! relationships between identities.
//!
//! A [`DelegationAttestation`] is a parent identity's signed statement that a
//! child identity may act with a bounded set of capabilities until an expiry.
//! Attestations form a [`DelegationChain`] (e.g. `human → agent → sub-agent`)
//! that a verifier can validate **offline** by walking the chain to a trusted
//! root fingerprint.
//!
//! # Security model
//!
//! Signatures are hybrid Ed25519 + Falcon-1024 over the canonical JSON encoding.
//! The root link's signing key is bound to its fingerprint by an out-of-band
//! trusted-roots table. Non-root links embed the parent's public keys and
//! connect to the previous link by fingerprint equality.
//!
//! Capabilities narrow **monotonically** down the chain: a child can never hold
//! more than its parent delegated.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use origin_crypto_sdk::{Ed25519Signature, Ed25519VerifyingKey};
use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle};

use crate::capabilities::CapabilitySet;

/// Maximum number of links permitted in a delegation chain.
///
/// Default of 3 supports `human → agent → sub-agent`. Caps verification cost
/// and the blast radius of any single compromised link.
pub const MAX_DELEGATION_DEPTH: usize = 3;

/// A parent's signed statement delegating bounded authority to a child.
///
/// Field order is fixed; serialization via [`canonical_bytes`](DelegationAttestation::canonical_bytes)
/// produces the deterministic byte string that is signed and verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationAttestation {
    /// Stable kind marker for this attestation format/version.
    pub kind: String,
    /// Format version (currently 1).
    pub version: u8,
    /// SHA3-256 fingerprint (hex) of the delegating (parent) identity.
    pub parent_fingerprint: String,
    /// SHA3-256 fingerprint (hex) of the delegate (child) identity.
    pub child_fingerprint: String,
    /// Human-readable relationship label (e.g. `"agent:hermes"`, `"service:ci"`).
    pub label: String,
    /// Capabilities granted, as raw `CapabilitySet` bits.
    pub capabilities: u64,
    /// Unix timestamp (seconds) when issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when this attestation expires.
    pub expires_at: u64,
    /// Optional audience fingerprint — if set, only this verifier should
    /// accept the delegation. Prevents cross-context replay.
    pub audience: Option<String>,
    /// Optional resource/action scope (e.g. `"wallet:send"`, `"task:review"`).
    pub resource_scope: Option<String>,
    /// Hex-encoded 16-byte OS CSPRNG nonce for replay prevention.
    pub nonce: String,
}

impl DelegationAttestation {
    /// The capability set granted by this attestation.
    pub fn capability_set(&self) -> CapabilitySet {
        CapabilitySet::from_bits_truncate(self.capabilities)
    }

    /// Canonical byte encoding used for signing and verification.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("canonical serialize: {e}"))
    }

    /// Whether this attestation has expired relative to `now_secs`.
    pub fn is_expired(&self, now_secs: u64) -> bool {
        self.expires_at <= now_secs
    }

    /// Check if this attestation is valid for the given audience and resource.
    pub fn is_scoped_to(&self, verifier_fp: Option<&str>, resource: Option<&str>) -> bool {
        if let Some(aud) = &self.audience {
            match verifier_fp {
                Some(fp) if fp == aud => {}
                _ => return false,
            }
        }
        if let Some(scope) = &self.resource_scope {
            match resource {
                Some(r) if r == scope => {}
                _ => return false,
            }
        }
        true
    }

    /// Generate a random 16-byte nonce from the OS CSPRNG.
    fn random_nonce() -> Result<String, String> {
        let mut buf = [0u8; 16];
        origin_crypto_sdk::fill_random(&mut buf).map_err(|_| "OS CSPRNG failed".to_string())?;
        Ok(hex::encode(buf))
    }
}

/// A delegation attestation together with the parent's hybrid signature and
/// the public keys needed to verify it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedDelegation {
    /// The attestation being signed.
    pub attestation: DelegationAttestation,
    /// The parent's Falcon-1024 public key (hex).
    pub parent_falcon_pk: String,
    /// The parent's Ed25519 public key (hex).
    pub parent_ed25519_pk: String,
    /// Hybrid Ed25519 + Falcon-1024 signature over `attestation.canonical_bytes()`
    /// (hex-encoded: ed25519_sig ‖ falcon_sig).
    pub signature: String,
}

impl SignedDelegation {
    /// Issue a signed delegation from a parent key bundle to a child fingerprint.
    ///
    /// `ttl_secs` must be non-zero. The parent signs with its hybrid key bundle.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        parent_bundle: &HybridSigningKeyBundle,
        parent_fingerprint: &str,
        child_fingerprint: &str,
        label: &str,
        capabilities: CapabilitySet,
        issued_at: u64,
        ttl_secs: u64,
    ) -> Result<Self, String> {
        Self::issue_scoped(
            parent_bundle,
            parent_fingerprint,
            child_fingerprint,
            label,
            capabilities,
            issued_at,
            ttl_secs,
            None,
            None,
        )
    }

    /// Issue a signed delegation with audience and resource scope.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_scoped(
        parent_bundle: &HybridSigningKeyBundle,
        parent_fingerprint: &str,
        child_fingerprint: &str,
        label: &str,
        capabilities: CapabilitySet,
        issued_at: u64,
        ttl_secs: u64,
        audience: Option<String>,
        resource_scope: Option<String>,
    ) -> Result<Self, String> {
        if ttl_secs == 0 {
            return Err("ttl_secs must be > 0".into());
        }
        let expires_at = issued_at
            .checked_add(ttl_secs)
            .ok_or("delegation expiry overflow")?;

        let attestation = DelegationAttestation {
            kind: "origin-delegation-v1".to_string(),
            version: 1,
            parent_fingerprint: parent_fingerprint.to_string(),
            child_fingerprint: child_fingerprint.to_string(),
            label: label.to_string(),
            capabilities: capabilities.bits(),
            issued_at,
            expires_at,
            audience,
            resource_scope,
            nonce: DelegationAttestation::random_nonce()?,
        };

        let canonical = attestation.canonical_bytes()?;
        let sig = parent_bundle.sign_hybrid(&canonical);

        Ok(SignedDelegation {
            attestation,
            parent_falcon_pk: hex::encode(parent_bundle.falcon1024_pk().as_bytes()),
            parent_ed25519_pk: hex::encode(parent_bundle.ed25519_pk().to_bytes()),
            signature: hex::encode(
                [
                    sig.ed25519_sig.to_bytes().as_slice(),
                    sig.falcon_sig.as_bytes(),
                ]
                .concat(),
            ),
        })
    }

    /// Verify this link's signature against its embedded parent public keys.
    ///
    /// This does NOT establish trust in the parent — only that the embedded
    /// keys signed the attestation. Chain validation binds the root key to a
    /// trusted fingerprint separately.
    pub fn verify_signature(&self) -> Result<bool, String> {
        let ed25519_pk_bytes = hex::decode(&self.parent_ed25519_pk)
            .map_err(|e| format!("invalid parent_ed25519_pk hex: {e}"))?;
        let falcon_pk_bytes = hex::decode(&self.parent_falcon_pk)
            .map_err(|e| format!("invalid parent_falcon_pk hex: {e}"))?;
        let sig_bytes =
            hex::decode(&self.signature).map_err(|e| format!("invalid signature hex: {e}"))?;

        // Ed25519 signature is 64 bytes, Falcon-1024 is the rest
        if sig_bytes.len() < 64 {
            return Err("signature too short".into());
        }
        let ed25519_sig = Ed25519Signature::from_slice(&sig_bytes[..64])
            .map_err(|e| format!("invalid ed25519 signature: {e}"))?;
        let falcon_sig =
            origin_crypto_sdk::pqc::falcon1024::FalconSignature::from_bytes(&sig_bytes[64..])
                .map_err(|e| format!("invalid falcon signature: {e}"))?;

        let ed25519_pk = Ed25519VerifyingKey::from_bytes(
            ed25519_pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "invalid ed25519 pk length")?,
        )
        .map_err(|e| format!("invalid ed25519 pk: {e}"))?;
        let falcon_pk =
            origin_crypto_sdk::pqc::falcon1024::FalconPublicKey::from_bytes(&falcon_pk_bytes)
                .map_err(|e| format!("invalid falcon pk: {e}"))?;

        let sdk_sig = Ed25519Falcon1024 {
            ed25519_sig,
            falcon_sig,
        };
        let canonical = self.attestation.canonical_bytes()?;
        Ok(Ed25519Falcon1024::verify(&ed25519_pk, &falcon_pk, &canonical, &sdk_sig).is_ok())
    }
}

/// An ordered chain of signed delegations from a trusted root to a leaf.
///
/// Index 0 is the root link (its parent must be a trusted root); each
/// subsequent link's parent fingerprint must equal the previous link's child
/// fingerprint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationChain {
    /// Ordered links, root first.
    pub links: Vec<SignedDelegation>,
}

impl DelegationChain {
    /// Create a chain from an ordered list of links (root first).
    pub fn new(links: Vec<SignedDelegation>) -> Self {
        Self { links }
    }

    /// The leaf (final) child fingerprint, if the chain is non-empty.
    pub fn leaf_fingerprint(&self) -> Option<&str> {
        self.links
            .last()
            .map(|l| l.attestation.child_fingerprint.as_str())
    }

    /// Validate the chain and compute the effective capabilities at the leaf.
    ///
    /// `trusted_roots` maps a trusted root fingerprint (hex) to its
    /// authoritative Falcon-1024 public key bytes. `now_secs` is the current
    /// Unix time.
    ///
    /// Checks performed:
    /// 1. Chain is non-empty and within [`MAX_DELEGATION_DEPTH`].
    /// 2. Root link's parent fingerprint is trusted, and its embedded key
    ///    matches the authoritative key.
    /// 3. Every link's signature verifies.
    /// 4. Links connect: `link[i+1].parent == link[i].child`.
    /// 5. No link is expired.
    /// 6. Capabilities narrow monotonically (each child ⊆ its parent's grant).
    ///
    /// Returns the effective [`CapabilitySet`] at the leaf on success.
    pub fn verify(
        &self,
        trusted_roots: &HashMap<String, Vec<u8>>,
        now_secs: u64,
    ) -> Result<CapabilitySet, String> {
        if self.links.is_empty() {
            return Err("delegation chain is empty".into());
        }
        if self.links.len() > MAX_DELEGATION_DEPTH {
            return Err(format!(
                "delegation chain depth {} exceeds maximum {}",
                self.links.len(),
                MAX_DELEGATION_DEPTH
            ));
        }

        // Root binding: the first link's parent must be a trusted root, and the
        // embedded key must match the authoritative key for that root.
        let root = &self.links[0];
        let root_parent_fp = &root.attestation.parent_fingerprint;
        let authoritative_pk = trusted_roots
            .get(root_parent_fp)
            .ok_or_else(|| format!("root parent {root_parent_fp} is not a trusted root"))?;
        let embedded_pk =
            hex::decode(&root.parent_falcon_pk).map_err(|e| format!("invalid root pk hex: {e}"))?;
        if &embedded_pk != authoritative_pk {
            return Err("root link public key does not match trusted root".into());
        }

        let mut effective = CapabilitySet::all();
        let mut expected_parent: Option<&str> = None;

        for (i, link) in self.links.iter().enumerate() {
            let att = &link.attestation;

            // Chain connectivity.
            if let Some(parent) = expected_parent {
                if att.parent_fingerprint != parent {
                    return Err(format!(
                        "chain break at link {i}: parent does not match previous child"
                    ));
                }
            }

            // Expiry.
            if att.is_expired(now_secs) {
                return Err(format!("delegation link {i} expired"));
            }

            // Signature.
            if !link.verify_signature()? {
                return Err(format!("delegation link {i} signature invalid"));
            }

            // Monotonic narrowing.
            effective = effective.intersect(att.capability_set());

            expected_parent = Some(&att.child_fingerprint);
        }

        Ok(effective)
    }

    /// Validate the chain with audience and resource scope checking.
    ///
    /// In addition to all checks in [`verify`](Self::verify), this method:
    /// - Checks that every link's `audience` (if set) matches `verifier_fp`.
    /// - Checks that every link's `resource_scope` (if set) matches `resource`.
    /// - Rejects chains containing nonces in `seen_nonces` (replay prevention).
    pub fn verify_scoped(
        &self,
        trusted_roots: &HashMap<String, Vec<u8>>,
        now_secs: u64,
        verifier_fp: Option<&str>,
        resource: Option<&str>,
        seen_nonces: &HashSet<String>,
    ) -> Result<CapabilitySet, String> {
        for link in &self.links {
            if !link.attestation.is_scoped_to(verifier_fp, resource) {
                return Err("delegation link audience or resource scope mismatch".into());
            }
            if seen_nonces.contains(&link.attestation.nonce) {
                return Err("delegation link nonce replay detected".into());
            }
        }
        self.verify(trusted_roots, now_secs)
    }
}

/// A signed revocation of a previously issued delegation.
///
/// The revoking parent signs a statement that the delegation with the
/// matching nonce is no longer valid.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationRevocation {
    /// Stable kind marker.
    pub kind: String,
    /// Format version.
    pub version: u8,
    /// Fingerprint (hex) of the revoking parent.
    pub parent_fingerprint: String,
    /// Nonce of the delegation being revoked.
    pub revoked_nonce: String,
    /// Unix timestamp when the revocation was issued.
    pub issued_at: u64,
    /// The parent's Falcon-1024 public key (hex).
    pub parent_falcon_pk: String,
    /// The parent's Ed25519 public key (hex).
    pub parent_ed25519_pk: String,
    /// Hybrid signature over the canonical encoding (hex).
    pub signature: String,
}

impl DelegationRevocation {
    /// Issue a revocation for a previously signed delegation.
    pub fn issue(
        parent_bundle: &HybridSigningKeyBundle,
        parent_fingerprint: &str,
        revoked: &SignedDelegation,
        issued_at: u64,
    ) -> Result<Self, String> {
        let revocation = DelegationRevocation {
            kind: "origin-revocation-v1".to_string(),
            version: 1,
            parent_fingerprint: parent_fingerprint.to_string(),
            revoked_nonce: revoked.attestation.nonce.clone(),
            issued_at,
            parent_falcon_pk: hex::encode(parent_bundle.falcon1024_pk().as_bytes()),
            parent_ed25519_pk: hex::encode(parent_bundle.ed25519_pk().to_bytes()),
            signature: String::new(), // placeholder, signed below
        };

        let canonical = revocation.canonical_bytes()?;
        let sig = parent_bundle.sign_hybrid(&canonical);

        Ok(DelegationRevocation {
            signature: hex::encode(
                [
                    sig.ed25519_sig.to_bytes().as_slice(),
                    sig.falcon_sig.as_bytes(),
                ]
                .concat(),
            ),
            ..revocation
        })
    }

    /// Canonical byte encoding used for signing and verification.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        // Serialize with empty signature for canonical form
        let mut clone = self.clone();
        clone.signature = String::new();
        serde_json::to_vec(&clone).map_err(|e| format!("canonical serialize: {e}"))
    }

    /// Verify this revocation's signature.
    pub fn verify_signature(&self) -> Result<bool, String> {
        let ed25519_pk_bytes = hex::decode(&self.parent_ed25519_pk)
            .map_err(|e| format!("invalid parent_ed25519_pk hex: {e}"))?;
        let falcon_pk_bytes = hex::decode(&self.parent_falcon_pk)
            .map_err(|e| format!("invalid parent_falcon_pk hex: {e}"))?;
        let sig_bytes =
            hex::decode(&self.signature).map_err(|e| format!("invalid signature hex: {e}"))?;

        if sig_bytes.len() < 64 {
            return Err("signature too short".into());
        }
        let ed25519_sig = Ed25519Signature::from_slice(&sig_bytes[..64])
            .map_err(|e| format!("invalid ed25519 signature: {e}"))?;
        let falcon_sig =
            origin_crypto_sdk::pqc::falcon1024::FalconSignature::from_bytes(&sig_bytes[64..])
                .map_err(|e| format!("invalid falcon signature: {e}"))?;

        let ed25519_pk = Ed25519VerifyingKey::from_bytes(
            ed25519_pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "invalid ed25519 pk length")?,
        )
        .map_err(|e| format!("invalid ed25519 pk: {e}"))?;
        let falcon_pk =
            origin_crypto_sdk::pqc::falcon1024::FalconPublicKey::from_bytes(&falcon_pk_bytes)
                .map_err(|e| format!("invalid falcon pk: {e}"))?;

        let sdk_sig = Ed25519Falcon1024 {
            ed25519_sig,
            falcon_sig,
        };
        let canonical = self.canonical_bytes()?;
        Ok(Ed25519Falcon1024::verify(&ed25519_pk, &falcon_pk, &canonical, &sdk_sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_bundle() -> (Arc<HybridSigningKeyBundle>, String) {
        let seed = [0x42u8; 32];
        let bundle = HybridSigningKeyBundle::from_seed_cached(&seed, "test:v1").unwrap();
        let fp = hex::encode(origin_crypto_sdk::sha3_256(
            bundle.falcon1024_pk().as_bytes(),
        ));
        (bundle, fp)
    }

    #[test]
    fn issue_and_verify_single_link() {
        let (parent_bundle, parent_fp) = test_bundle();
        let child_fp = hex::encode([0xABu8; 32]);

        let delegation = SignedDelegation::issue(
            &parent_bundle,
            &parent_fp,
            &child_fp,
            "test-agent",
            CapabilitySet::agent(),
            1000,
            3600,
        )
        .unwrap();

        assert!(delegation.verify_signature().unwrap());
        assert_eq!(delegation.attestation.parent_fingerprint, parent_fp);
        assert_eq!(delegation.attestation.child_fingerprint, child_fp);
        assert!(!delegation.attestation.is_expired(2000));
        assert!(delegation.attestation.is_expired(5000));
    }

    #[test]
    fn chain_verification_two_links() {
        let (root_bundle, root_fp) = test_bundle();
        let seed2 = [0x43u8; 32];
        let mid_bundle = HybridSigningKeyBundle::from_seed_cached(&seed2, "test:v1").unwrap();
        let mid_fp = hex::encode(origin_crypto_sdk::sha3_256(
            mid_bundle.falcon1024_pk().as_bytes(),
        ));
        let leaf_fp = hex::encode([0xCDu8; 32]);

        let link1 = SignedDelegation::issue(
            &root_bundle,
            &root_fp,
            &mid_fp,
            "root-to-agent",
            CapabilitySet::human(),
            1000,
            7200,
        )
        .unwrap();

        let link2 = SignedDelegation::issue(
            &mid_bundle,
            &mid_fp,
            &leaf_fp,
            "agent-to-sub",
            CapabilitySet::SIGN | CapabilitySet::STAMP,
            1000,
            3600,
        )
        .unwrap();

        let chain = DelegationChain::new(vec![link1, link2]);
        let mut trusted = HashMap::new();
        trusted.insert(
            root_fp.clone(),
            hex::decode(&chain.links[0].parent_falcon_pk).unwrap(),
        );

        let effective = chain.verify(&trusted, 2000).unwrap();
        // Effective = human() ∩ (SIGN | STAMP) = SIGN
        assert!(effective.has(CapabilitySet::SIGN));
        assert!(!effective.has(CapabilitySet::DELEGATE));
        assert_eq!(chain.leaf_fingerprint(), Some(leaf_fp.as_str()));
    }

    #[test]
    fn chain_rejects_untrusted_root() {
        let (root_bundle, root_fp) = test_bundle();
        let child_fp = hex::encode([0xABu8; 32]);

        let link = SignedDelegation::issue(
            &root_bundle,
            &root_fp,
            &child_fp,
            "test",
            CapabilitySet::SIGN,
            1000,
            3600,
        )
        .unwrap();

        let chain = DelegationChain::new(vec![link]);
        let trusted = HashMap::new(); // empty — no trusted roots
        assert!(chain.verify(&trusted, 2000).is_err());
    }

    #[test]
    fn chain_rejects_expired_link() {
        let (root_bundle, root_fp) = test_bundle();
        let child_fp = hex::encode([0xABu8; 32]);

        let link = SignedDelegation::issue(
            &root_bundle,
            &root_fp,
            &child_fp,
            "test",
            CapabilitySet::SIGN,
            1000,
            3600,
        )
        .unwrap();

        let chain = DelegationChain::new(vec![link]);
        let mut trusted = HashMap::new();
        trusted.insert(
            root_fp,
            hex::decode(&chain.links[0].parent_falcon_pk).unwrap(),
        );

        // Verify at time 5000 — past expiry (1000 + 3600 = 4600)
        assert!(chain.verify(&trusted, 5000).is_err());
    }

    #[test]
    fn chain_rejects_broken_link() {
        let (root_bundle, root_fp) = test_bundle();
        let seed2 = [0x43u8; 32];
        let mid_bundle = HybridSigningKeyBundle::from_seed_cached(&seed2, "test:v1").unwrap();
        let mid_fp = hex::encode(origin_crypto_sdk::sha3_256(
            mid_bundle.falcon1024_pk().as_bytes(),
        ));
        let wrong_fp = hex::encode([0xFFu8; 32]);

        let link1 = SignedDelegation::issue(
            &root_bundle,
            &root_fp,
            &mid_fp,
            "root-to-agent",
            CapabilitySet::human(),
            1000,
            7200,
        )
        .unwrap();

        // link2 claims parent is wrong_fp, not mid_fp
        let link2 = SignedDelegation::issue(
            &mid_bundle,
            &wrong_fp,
            &hex::encode([0xCDu8; 32]),
            "broken",
            CapabilitySet::SIGN,
            1000,
            3600,
        )
        .unwrap();

        let chain = DelegationChain::new(vec![link1, link2]);
        let mut trusted = HashMap::new();
        trusted.insert(
            root_fp,
            hex::decode(&chain.links[0].parent_falcon_pk).unwrap(),
        );

        assert!(chain.verify(&trusted, 2000).is_err());
    }

    #[test]
    fn revocation_issue_and_verify() {
        let (parent_bundle, parent_fp) = test_bundle();
        let child_fp = hex::encode([0xABu8; 32]);

        let delegation = SignedDelegation::issue(
            &parent_bundle,
            &parent_fp,
            &child_fp,
            "test",
            CapabilitySet::SIGN,
            1000,
            3600,
        )
        .unwrap();

        let revocation =
            DelegationRevocation::issue(&parent_bundle, &parent_fp, &delegation, 2000).unwrap();

        assert!(revocation.verify_signature().unwrap());
        assert_eq!(revocation.revoked_nonce, delegation.attestation.nonce);
    }

    #[test]
    fn scoped_delegation_audience_check() {
        let (parent_bundle, parent_fp) = test_bundle();
        let child_fp = hex::encode([0xABu8; 32]);
        let audience_fp = hex::encode([0xEEu8; 32]);

        let delegation = SignedDelegation::issue_scoped(
            &parent_bundle,
            &parent_fp,
            &child_fp,
            "scoped",
            CapabilitySet::SIGN,
            1000,
            3600,
            Some(audience_fp.clone()),
            Some("wallet:send".to_string()),
        )
        .unwrap();

        assert!(delegation
            .attestation
            .is_scoped_to(Some(&audience_fp), Some("wallet:send")));
        assert!(!delegation
            .attestation
            .is_scoped_to(Some("wrong"), Some("wallet:send")));
        assert!(!delegation
            .attestation
            .is_scoped_to(Some(&audience_fp), Some("wrong")));
    }

    #[test]
    fn ttl_zero_rejected() {
        let (parent_bundle, parent_fp) = test_bundle();
        let child_fp = hex::encode([0xABu8; 32]);

        let result = SignedDelegation::issue(
            &parent_bundle,
            &parent_fp,
            &child_fp,
            "test",
            CapabilitySet::SIGN,
            1000,
            0,
        );
        assert!(result.is_err());
    }
}
