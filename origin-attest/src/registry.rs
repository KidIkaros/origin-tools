//! Agent registry — in-memory store of known agents and their data.
//!
//! The `AgentRegistry` is the local knowledge base. It stores everything
//! we know about each agent: their public key, claims, endorsements,
//! and when we last heard from them. It does NOT compute trust — that's
//! `TrustGraph`'s job.

use std::collections::HashMap;

use crate::types::{CapabilityClaim, Endorsement, EndorsementChain};

/// A complete record of everything we know about an agent.
#[derive(Clone, Debug)]
pub struct AgentRecord {
    /// Fingerprint (hex) — the primary key.
    pub fingerprint: String,
    /// Falcon-1024 public key (hex).
    pub falcon_pk: String,
    /// Key epoch for rotation.
    pub epoch: u32,
    /// HTTPS endpoint where this agent's manifest is served.
    pub endpoint: Option<String>,
    /// Capability claims issued by this agent.
    pub claims: Vec<CapabilityClaim>,
    /// Endorsements this agent has received.
    pub endorsements_received: Vec<Endorsement>,
    /// Endorsements this agent has given.
    pub endorsements_given: Vec<Endorsement>,
    /// Hash-chained endorsement log.
    pub chain: EndorsementChain,
    /// Unix timestamp when this agent was first discovered.
    pub discovered_at: i64,
    /// Unix timestamp of last contact/update.
    pub last_seen: i64,
}

impl AgentRecord {
    /// Create a minimal agent record.
    pub fn new(fingerprint: String, falcon_pk: String, epoch: u32) -> Self {
        let now = now_secs();
        AgentRecord {
            fingerprint,
            falcon_pk,
            epoch,
            endpoint: None,
            claims: Vec::new(),
            endorsements_received: Vec::new(),
            endorsements_given: Vec::new(),
            chain: EndorsementChain::new(),
            discovered_at: now,
            last_seen: now,
        }
    }

    /// Touch the last_seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen = now_secs();
    }
}

/// In-memory registry of known agents, keyed by fingerprint hex.
#[derive(Clone, Debug, Default)]
pub struct AgentRegistry {
    agents: HashMap<String, AgentRecord>,
}

impl AgentRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        AgentRegistry {
            agents: HashMap::new(),
        }
    }

    /// Register a new agent record.
    pub fn register(&mut self, record: AgentRecord) {
        let fp = record.fingerprint.clone();
        self.agents.insert(fp, record);
    }

    /// Look up an agent by fingerprint.
    pub fn get(&self, fp: &str) -> Option<&AgentRecord> {
        self.agents.get(fp)
    }

    /// Look up an agent by fingerprint (mutable).
    pub fn get_mut(&mut self, fp: &str) -> Option<&mut AgentRecord> {
        self.agents.get_mut(fp)
    }

    /// Add a capability claim to an agent.
    pub fn add_claim(
        &mut self,
        fp: &str,
        claim: CapabilityClaim,
    ) -> Result<(), crate::error::AttestError> {
        let agent = self
            .agents
            .get_mut(fp)
            .ok_or_else(|| crate::error::AttestError::NotFound(fp.to_string()))?;
        agent.claims.push(claim);
        agent.touch();
        Ok(())
    }

    /// Add an endorsement, updating both endorser and endorsee records.
    pub fn add_endorsement(
        &mut self,
        endorsement: Endorsement,
    ) -> Result<(), crate::error::AttestError> {
        let endorser_fp = endorsement.endorser_fp.clone();
        let endorsee_fp = endorsement.endorsee_fp.clone();

        {
            let endorser = self
                .agents
                .get_mut(&endorser_fp)
                .ok_or_else(|| crate::error::AttestError::NotFound(endorser_fp.clone()))?;
            endorser.endorsements_given.push(endorsement.clone());
            endorser.chain.append(endorsement.clone());
            endorser.touch();
        }

        {
            let endorsee = self
                .agents
                .get_mut(&endorsee_fp)
                .ok_or_else(|| crate::error::AttestError::NotFound(endorsee_fp.clone()))?;
            endorsee.endorsements_received.push(endorsement);
            endorsee.touch();
        }

        Ok(())
    }

    /// Return all registered fingerprint hex strings.
    pub fn fingerprints(&self) -> Vec<String> {
        self.agents.keys().cloned().collect()
    }

    /// Number of registered agents.
    pub fn count(&self) -> usize {
        self.agents.len()
    }

    /// Search for agents that have claimed a specific capability domain.
    pub fn search_by_capability(&self, domain: &str) -> Vec<&AgentRecord> {
        self.agents
            .values()
            .filter(|agent| {
                agent
                    .claims
                    .iter()
                    .any(|claim| claim.capabilities.iter().any(|c| c == domain))
            })
            .collect()
    }

    /// Check if an agent is registered.
    pub fn contains(&self, fp: &str) -> bool {
        self.agents.contains_key(fp)
    }

    /// Remove an agent from the registry.
    pub fn remove(&mut self, fp: &str) -> Option<AgentRecord> {
        self.agents.remove(fp)
    }
}

fn now_secs() -> i64 {
    // Fall back to 0 if the system clock is before Unix epoch (pre-1970).
    // This is safer than panicking — a zero timestamp will simply make records
    // appear very old, which is handled by expiry logic.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EndorsementTier;

    fn fp(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn make_record(c: char) -> AgentRecord {
        AgentRecord::new(fp(c), format!("pk_{}", c), 1)
    }

    #[test]
    fn test_register_and_get() {
        let mut reg = AgentRegistry::new();
        reg.register(make_record('a'));
        assert!(reg.get(&fp('a')).is_some());
        assert!(reg.get(&fp('z')).is_none());
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn test_fingerprints() {
        let mut reg = AgentRegistry::new();
        reg.register(make_record('a'));
        reg.register(make_record('b'));
        assert_eq!(reg.fingerprints().len(), 2);
    }

    #[test]
    fn test_add_claim() {
        let mut reg = AgentRegistry::new();
        reg.register(make_record('a'));

        let claim = CapabilityClaim {
            fingerprint: fp('a'),
            falcon_pk: "pk_a".to_string(),
            epoch: 1,
            capabilities: vec!["code-review".to_string()],
            metadata: serde_json::json!({}),
            timestamp: 1000,
            expires: 0,
            falcon_signature: vec![],
        };

        reg.add_claim(&fp('a'), claim).unwrap();
        let agent = reg.get(&fp('a')).unwrap();
        assert_eq!(agent.claims.len(), 1);
        assert_eq!(agent.claims[0].capabilities[0], "code-review");
    }

    #[test]
    fn test_add_claim_not_found() {
        let mut reg = AgentRegistry::new();
        let claim = CapabilityClaim {
            fingerprint: fp('z'),
            falcon_pk: "pk".to_string(),
            epoch: 1,
            capabilities: vec![],
            metadata: serde_json::json!({}),
            timestamp: 1000,
            expires: 0,
            falcon_signature: vec![],
        };
        assert!(reg.add_claim(&fp('z'), claim).is_err());
    }

    #[test]
    fn test_add_endorsement() {
        let mut reg = AgentRegistry::new();
        reg.register(make_record('a'));
        reg.register(make_record('b'));

        let endorsement = Endorsement {
            tier: EndorsementTier::Tier2,
            endorser_fp: fp('a'),
            endorsee_fp: fp('b'),
            capability_domain: "review".to_string(),
            confidence: 0.9,
            context: "test".to_string(),
            timestamp: 1000,
            valid_until: 0,
            prev_hash: [0u8; 32],
            nonce: 1,
            falcon_signature: vec![],
            revocation: false,
            supersedes: None,
        };

        reg.add_endorsement(endorsement).unwrap();

        let a = reg.get(&fp('a')).unwrap();
        let b = reg.get(&fp('b')).unwrap();
        assert_eq!(a.endorsements_given.len(), 1);
        assert_eq!(b.endorsements_received.len(), 1);
        assert_eq!(a.chain.len(), 1);
    }

    #[test]
    fn test_add_endorsement_missing_endorser() {
        let mut reg = AgentRegistry::new();
        reg.register(make_record('b'));

        let endorsement = Endorsement {
            tier: EndorsementTier::Tier1,
            endorser_fp: fp('a'),
            endorsee_fp: fp('b'),
            capability_domain: "test".to_string(),
            confidence: 0.5,
            context: "".to_string(),
            timestamp: 1000,
            valid_until: 0,
            prev_hash: [0u8; 32],
            nonce: 1,
            falcon_signature: vec![],
            revocation: false,
            supersedes: None,
        };

        assert!(reg.add_endorsement(endorsement).is_err());
    }

    #[test]
    fn test_search_by_capability() {
        let mut reg = AgentRegistry::new();
        reg.register(make_record('a'));
        reg.register(make_record('b'));

        let claim_a = CapabilityClaim {
            fingerprint: fp('a'),
            falcon_pk: "pk_a".to_string(),
            epoch: 1,
            capabilities: vec!["code-review".to_string(), "audit".to_string()],
            metadata: serde_json::json!({}),
            timestamp: 1000,
            expires: 0,
            falcon_signature: vec![],
        };
        reg.add_claim(&fp('a'), claim_a).unwrap();

        let results = reg.search_by_capability("code-review");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].fingerprint, fp('a'));

        assert!(reg.search_by_capability("translation").is_empty());
    }

    #[test]
    fn test_contains_and_remove() {
        let mut reg = AgentRegistry::new();
        reg.register(make_record('a'));
        assert!(reg.contains(&fp('a')));
        assert!(!reg.contains(&fp('z')));

        let removed = reg.remove(&fp('a'));
        assert!(removed.is_some());
        assert!(!reg.contains(&fp('a')));
        assert_eq!(reg.count(), 0);
    }
}
