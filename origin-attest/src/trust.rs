//! Trust computation — personalized PageRank over the endorsement graph.
//!
//! Capability-specific trust: there is no global trust score. Each capability
//! domain has its own trust subgraph. Trust propagates only through Tier-2
//! endorsements (vouches).
//!
//! # Algorithm
//!
//! Personalized PageRank restricted to a single capability domain:
//! 1. Seed nodes (directly trusted by this agent) start with weight 1.0.
//! 2. For each seed, follow Tier-2 endorsements in the given domain.
//! 3. Each hop applies a damping factor (0.85) and the endorsement confidence.
//! 4. Trust decays exponentially with path length.
//! 5. Scores are normalized to [0.0, 1.0].
//!
//! Anti-monopoly balancing (Meadows Level-8):
//! - Hub damping (B1): high-degree agents get diminishing returns.
//! - Long-tail boost (B2): low-degree (new) agents get a bootstrap boost.
//! - Decay (B3): endorsements decay over time, requiring fresh vouches.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::types::{CapabilityClaim, Endorsement, EndorsementTier};

/// Minimum number of Tier-2 endorsements an agent must have received
/// before it can issue Tier-2 endorsements.
pub const THRESHOLD: usize = 3;

/// Damping factor for trust propagation (personalized PageRank).
pub const DAMPING: f64 = 0.85;

/// Maximum hop distance for trust propagation.
pub const MAX_HOPS: usize = 6;

/// Configuration for trust graph propagation.
#[derive(Clone, Debug)]
pub struct TrustGraphConfig {
    /// Damping factor applied per hop (default 0.85).
    pub damping: f64,
    /// Maximum hop distance for propagation (default 6).
    pub max_hops: usize,
    /// Minimum Tier-2 endorsements required to issue Tier-2 (default 3).
    pub threshold: usize,
    /// Anti-monopoly hub-damping coefficient (α, default 0.1).
    pub alpha: f64,
    /// Anti-monopoly long-tail boost coefficient (β, default 0.5).
    pub beta: f64,
    /// Decay rate per day (γ, default 0.01).
    pub gamma: f64,
}

impl Default for TrustGraphConfig {
    fn default() -> Self {
        Self {
            damping: DAMPING,
            max_hops: MAX_HOPS,
            threshold: THRESHOLD,
            alpha: 0.1,
            beta: 0.5,
            gamma: 0.01,
        }
    }
}

/// Trait for accessing endorsement edge data uniformly.
///
/// Implement this for any endorsement-like type to feed it into the
/// trust graph without coupling to a specific struct.
pub trait EndorsementEdge {
    fn endorser_fp(&self) -> &str;
    fn endorsee_fp(&self) -> &str;
    fn capability_domain(&self) -> &str;
    fn confidence(&self) -> f64;
    fn tier(&self) -> EndorsementTier;
    fn timestamp(&self) -> i64;
    fn valid_until(&self) -> i64;
    fn is_valid(&self, now: i64) -> bool;
}

impl EndorsementEdge for Endorsement {
    fn endorser_fp(&self) -> &str {
        &self.endorser_fp
    }
    fn endorsee_fp(&self) -> &str {
        &self.endorsee_fp
    }
    fn capability_domain(&self) -> &str {
        &self.capability_domain
    }
    fn confidence(&self) -> f64 {
        self.confidence
    }
    fn tier(&self) -> EndorsementTier {
        self.tier
    }
    fn timestamp(&self) -> i64 {
        self.timestamp
    }
    fn valid_until(&self) -> i64 {
        self.valid_until
    }
    fn is_valid(&self, now: i64) -> bool {
        self.is_valid(now)
    }
}

/// A node in the trust graph, keyed by fingerprint hex.
#[derive(Clone, Debug)]
pub struct TrustNode {
    /// Fingerprint (hex) of this agent.
    pub fingerprint: String,
    /// Endorsements this agent has received.
    pub endorsements_received: Vec<Endorsement>,
    /// Endorsements this agent has given.
    pub endorsements_given: Vec<Endorsement>,
    /// Capability claims this agent has made.
    pub claims: Vec<CapabilityClaim>,
}

impl TrustNode {
    fn new(fingerprint: String) -> Self {
        TrustNode {
            fingerprint,
            endorsements_received: Vec::new(),
            endorsements_given: Vec::new(),
            claims: Vec::new(),
        }
    }
}

/// Trust graph with personalized PageRank over the endorsement network.
///
/// The graph is directed: edges are endorsements from endorser → endorsee.
/// Trust propagates only through Tier-2 endorsements in a specific
/// capability domain.
#[derive(Clone, Debug)]
pub struct TrustGraph {
    /// All known agents, keyed by fingerprint hex.
    nodes: HashMap<String, TrustNode>,
    /// Fingerprint hex strings of this agent's directly trusted seeds.
    seed_fps: HashSet<String>,
    /// Propagation configuration.
    config: TrustGraphConfig,
}

impl TrustGraph {
    /// Create a new trust graph with the given seed fingerprints and default config.
    pub fn new(seed_fps: Vec<String>) -> Self {
        TrustGraph {
            nodes: HashMap::new(),
            seed_fps: seed_fps.into_iter().collect(),
            config: TrustGraphConfig::default(),
        }
    }

    /// Create a new trust graph with custom configuration.
    pub fn with_config(seed_fps: Vec<String>, config: TrustGraphConfig) -> Self {
        TrustGraph {
            nodes: HashMap::new(),
            seed_fps: seed_fps.into_iter().collect(),
            config,
        }
    }

    /// Return the graph configuration.
    pub fn config(&self) -> &TrustGraphConfig {
        &self.config
    }

    /// Add an endorsement to the graph.
    pub fn add_endorsement(&mut self, endorsement: Endorsement) {
        self.ensure_node(&endorsement.endorser_fp);
        self.ensure_node(&endorsement.endorsee_fp);

        if let Some(endorser) = self.nodes.get_mut(&endorsement.endorser_fp) {
            endorser.endorsements_given.push(endorsement.clone());
        }
        if let Some(endorsee) = self.nodes.get_mut(&endorsement.endorsee_fp) {
            endorsee.endorsements_received.push(endorsement);
        }
    }

    /// Add a capability claim to the appropriate node.
    pub fn add_claim(&mut self, claim: CapabilityClaim) {
        self.ensure_node(&claim.fingerprint);
        if let Some(node) = self.nodes.get_mut(&claim.fingerprint) {
            node.claims.push(claim);
        }
    }

    /// Check if an agent can issue Tier-2 endorsements (any domain).
    pub fn can_issue_tier2(&self, fingerprint: &str) -> bool {
        let now = now_secs();
        self.nodes
            .get(fingerprint)
            .map(|node| {
                node.endorsements_received
                    .iter()
                    .filter(|e| e.tier == EndorsementTier::Tier2 && e.is_valid(now))
                    .count()
                    >= self.config.threshold
            })
            .unwrap_or(false)
    }

    /// Check if an agent can issue Tier-2 endorsements in a specific domain.
    pub fn can_issue_tier2_in_domain(&self, fingerprint: &str, domain: &str) -> bool {
        let now = now_secs();
        self.nodes
            .get(fingerprint)
            .map(|node| {
                node.endorsements_received
                    .iter()
                    .filter(|e| {
                        e.tier == EndorsementTier::Tier2
                            && e.capability_domain == domain
                            && e.is_valid(now)
                    })
                    .count()
                    >= self.config.threshold
            })
            .unwrap_or(false)
    }

    /// Compute a capability-specific trust score for an agent.
    ///
    /// Returns a value in [0.0, 1.0] based on personalized PageRank
    /// restricted to the given capability domain.
    pub fn trust_score(&self, fingerprint: &str, capability_domain: &str) -> f64 {
        if self.seed_fps.contains(fingerprint) {
            return 1.0;
        }

        let now = now_secs();

        // Build directed adjacency: endorser → [(endorsee, confidence)]
        let mut adjacency: HashMap<&str, Vec<(&str, f64)>> = HashMap::new();
        for (fp, node) in &self.nodes {
            let mut edges = Vec::new();
            for e in &node.endorsements_given {
                if e.tier == EndorsementTier::Tier2
                    && e.capability_domain == capability_domain
                    && e.is_valid(now)
                {
                    edges.push((e.endorsee_fp.as_str(), e.confidence));
                }
            }
            if !edges.is_empty() {
                adjacency.insert(fp.as_str(), edges);
            }
        }

        // BFS propagation from each seed with cycle detection.
        let mut scores: HashMap<&str, f64> = HashMap::new();
        for seed_fp in &self.seed_fps {
            scores.insert(seed_fp.as_str(), 1.0);
        }

        let max_hops = self.config.max_hops;
        let damping = self.config.damping;

        let mut queue: VecDeque<(&str, f64, usize, HashSet<String>)> = VecDeque::new();
        for seed_fp in &self.seed_fps {
            let mut visited = HashSet::new();
            visited.insert(seed_fp.clone());
            queue.push_back((seed_fp.as_str(), 1.0, 0, visited));
        }

        while let Some((current_fp, current_weight, depth, visited)) = queue.pop_front() {
            if depth >= max_hops {
                continue;
            }
            if let Some(edges) = adjacency.get(current_fp) {
                for &(next_fp, confidence) in edges {
                    let propagated = current_weight * damping * confidence;
                    let entry = scores.entry(next_fp).or_insert(0.0);
                    *entry += propagated;

                    if !visited.contains(next_fp) {
                        let mut next_visited = visited.clone();
                        next_visited.insert(next_fp.to_string());
                        queue.push_back((next_fp, propagated, depth + 1, next_visited));
                    }
                }
            }
        }

        let raw_score = scores.get(fingerprint).copied().unwrap_or(0.0);

        // Anti-monopoly balancing
        let degree = self.total_degree(fingerprint);
        let balanced = self.balanced_score(raw_score, degree);
        balanced.clamp(0.0, 1.0)
    }

    // ── Anti-monopoly balancing ───────────────────────────────────

    /// Hub-damping coefficient (B1).
    pub fn hub_damping_alpha(&self) -> f64 {
        self.config.alpha
    }

    /// Long-tail boost coefficient (B2).
    pub fn long_tail_boost_beta(&self) -> f64 {
        self.config.beta
    }

    /// Decay rate per day (B3).
    pub fn decay_gamma(&self) -> f64 {
        self.config.gamma
    }

    /// Apply hub damping (B1): `base / (1 + α * deg)`.
    pub fn damped_score(base: f64, degree: usize, alpha: f64) -> f64 {
        let deg = (degree as f64).max(1.0);
        base / (1.0 + alpha * deg)
    }

    /// Apply long-tail boost (B2): `base * (1 + β / (deg + 1))`.
    pub fn boosted_score(base: f64, degree: usize, beta: f64) -> f64 {
        let deg = degree as f64;
        base * (1.0 + beta / (deg + 1.0))
    }

    /// Decay factor (B3) for a given age in days: `exp(-γ * age)`.
    pub fn decay_factor(age_days: f64, gamma: f64) -> f64 {
        (-gamma * age_days).exp()
    }

    /// Combined balancing score (B1 × B2), clamped to [0, 1].
    pub fn balanced_score(&self, base: f64, degree: usize) -> f64 {
        let alpha = self.hub_damping_alpha();
        let beta = self.long_tail_boost_beta();
        let balanced =
            Self::boosted_score(base, degree, beta) / (1.0 + alpha * (degree as f64).max(1.0));
        balanced.clamp(0.0, 1.0)
    }

    /// Return all agents with trust score >= min_score in a domain, sorted descending.
    pub fn trusted_agents(&self, capability_domain: &str, min_score: f64) -> Vec<(String, f64)> {
        let mut results = Vec::new();
        for fp in self.nodes.keys() {
            let score = self.trust_score(fp, capability_domain);
            if score >= min_score {
                results.push((fp.clone(), score));
            }
        }
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Find the shortest trust path between two agents through Tier-2 endorsements.
    pub fn shortest_trust_path(&self, from: &str, to: &str, domain: &str) -> Option<Vec<String>> {
        let now = now_secs();

        if from == to {
            return Some(vec![from.to_string()]);
        }

        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
        for (fp, node) in &self.nodes {
            for e in &node.endorsements_given {
                if e.tier == EndorsementTier::Tier2
                    && e.capability_domain == domain
                    && e.is_valid(now)
                {
                    adjacency
                        .entry(fp.as_str())
                        .or_default()
                        .push(&e.endorsee_fp);
                }
            }
        }

        let mut visited: HashSet<&str> = HashSet::new();
        let mut parent: HashMap<&str, &str> = HashMap::new();
        let mut queue: VecDeque<&str> = VecDeque::new();

        visited.insert(from);
        queue.push_back(from);

        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = adjacency.get(current) {
                for &neighbor in neighbors {
                    if visited.insert(neighbor) {
                        parent.insert(neighbor, current);
                        if neighbor == to {
                            let mut path = Vec::new();
                            let mut step: &str = to;
                            path.push(step.to_string());
                            while let Some(&p) = parent.get(step) {
                                path.push(p.to_string());
                                step = p;
                            }
                            path.reverse();
                            return Some(path);
                        }
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        None
    }

    // ── Graph metrics ─────────────────────────────────────────────

    /// Get a reference to a trust node.
    pub fn get_node(&self, fingerprint: &str) -> Option<&TrustNode> {
        self.nodes.get(fingerprint)
    }

    /// Get all node fingerprints.
    pub fn node_fps(&self) -> Vec<String> {
        self.nodes.keys().cloned().collect()
    }

    /// Number of nodes in the graph.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Out-degree of a node (endorsements given).
    pub fn out_degree(&self, fingerprint: &str) -> usize {
        self.nodes
            .get(fingerprint)
            .map(|n| n.endorsements_given.len())
            .unwrap_or(0)
    }

    /// In-degree of a node (endorsements received).
    pub fn in_degree(&self, fingerprint: &str) -> usize {
        self.nodes
            .get(fingerprint)
            .map(|n| n.endorsements_received.len())
            .unwrap_or(0)
    }

    /// Total degree (in + out).
    pub fn total_degree(&self, fingerprint: &str) -> usize {
        self.in_degree(fingerprint) + self.out_degree(fingerprint)
    }

    /// Total number of endorsement edges.
    pub fn edge_count(&self) -> usize {
        self.nodes
            .values()
            .map(|n| n.endorsements_given.len())
            .sum()
    }

    /// Graph density: edges / (nodes * (nodes-1)).
    pub fn density(&self) -> f64 {
        let n = self.nodes.len();
        if n < 2 {
            return 0.0;
        }
        let edges = self.edge_count() as f64;
        let max_edges = (n * (n - 1)) as f64;
        edges / max_edges
    }

    fn ensure_node(&mut self, fingerprint: &str) {
        self.nodes
            .entry(fingerprint.to_string())
            .or_insert_with(|| TrustNode::new(fingerprint.to_string()));
    }
}

fn now_secs() -> i64 {
    // Fall back to 0 if the system clock is before Unix epoch (pre-1970).
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EndorsementTier;

    fn fp(hex_char: char) -> String {
        hex_char.to_string().repeat(64)
    }

    fn make_tier2(endorser: &str, endorsee: &str, domain: &str, confidence: f64) -> Endorsement {
        Endorsement {
            tier: EndorsementTier::Tier2,
            endorser_fp: endorser.to_string(),
            endorsee_fp: endorsee.to_string(),
            capability_domain: domain.to_string(),
            confidence,
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

    fn make_tier1(endorser: &str, endorsee: &str, domain: &str) -> Endorsement {
        Endorsement {
            tier: EndorsementTier::Tier1,
            endorser_fp: endorser.to_string(),
            endorsee_fp: endorsee.to_string(),
            capability_domain: domain.to_string(),
            confidence: 0.8,
            context: "test".to_string(),
            timestamp: 1000,
            valid_until: 0,
            prev_hash: [0u8; 32],
            nonce: 2,
            falcon_signature: vec![],
            revocation: false,
            supersedes: None,
        }
    }

    #[test]
    fn test_seed_gets_max_score() {
        let seed = fp('a');
        let graph = TrustGraph::new(vec![seed.clone()]);
        assert_eq!(graph.trust_score(&seed, "any"), 1.0);
    }

    #[test]
    fn test_unknown_gets_zero() {
        let graph = TrustGraph::new(vec![fp('a')]);
        assert_eq!(graph.trust_score(&fp('z'), "any"), 0.0);
    }

    #[test]
    fn test_one_hop_trust() {
        let seed = fp('a');
        let target = fp('b');
        let mut graph = TrustGraph::new(vec![seed.clone()]);
        graph.add_endorsement(make_tier2(&seed, &target, "code-review", 1.0));

        let score = graph.trust_score(&target, "code-review");
        assert!(score > 0.0);
        // Anti-monopoly: 0.85 * (1 + 0.5/2) / (1 + 0.1*1) ≈ 0.966
        assert!((score - 0.966).abs() < 0.02, "got {}", score);
    }

    #[test]
    fn test_tier1_does_not_propagate() {
        let seed = fp('a');
        let target = fp('b');
        let mut graph = TrustGraph::new(vec![seed.clone()]);
        graph.add_endorsement(make_tier1(&seed, &target, "code-review"));

        let score = graph.trust_score(&target, "code-review");
        assert!(score < 0.01, "Tier-1 should not propagate, got {}", score);
    }

    #[test]
    fn test_can_issue_tier2() {
        let target = fp('b');
        let mut graph = TrustGraph::new(vec![fp('a')]);

        for i in 0..2 {
            let endorser = fp(char::from_digit(i + 1, 10).unwrap());
            graph.add_endorsement(make_tier2(&endorser, &target, "test", 0.9));
        }
        assert!(!graph.can_issue_tier2(&target));

        graph.add_endorsement(make_tier2(&fp('3'), &target, "test", 0.9));
        assert!(graph.can_issue_tier2(&target));
    }

    #[test]
    fn test_shortest_trust_path() {
        let a = fp('a');
        let b = fp('b');
        let c = fp('c');
        let mut graph = TrustGraph::new(vec![a.clone()]);

        graph.add_endorsement(make_tier2(&a, &b, "x", 1.0));
        graph.add_endorsement(make_tier2(&b, &c, "x", 1.0));

        let path = graph.shortest_trust_path(&a, &c, "x").unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], a);
        assert_eq!(path[2], c);
    }

    #[test]
    fn test_shortest_trust_path_not_found() {
        let a = fp('a');
        let graph = TrustGraph::new(vec![a.clone()]);
        assert!(graph.shortest_trust_path(&a, &fp('z'), "x").is_none());
    }

    #[test]
    fn test_trusted_agents_filters() {
        let seed = fp('a');
        let b = fp('b');
        let c = fp('c');
        let mut graph = TrustGraph::new(vec![seed.clone()]);

        graph.add_endorsement(make_tier2(&seed, &b, "review", 1.0));
        graph.add_endorsement(make_tier2(&seed, &c, "review", 0.3));

        let agents = graph.trusted_agents("review", 0.5);
        assert!(agents.iter().any(|(fp, _)| fp == &b));
        assert!(!agents.iter().any(|(fp, _)| fp == &c));
    }

    #[test]
    fn test_wrong_domain_zero() {
        let seed = fp('a');
        let target = fp('b');
        let mut graph = TrustGraph::new(vec![seed.clone()]);
        graph.add_endorsement(make_tier2(&seed, &target, "code-review", 1.0));
        assert_eq!(graph.trust_score(&target, "translation"), 0.0);
    }

    #[test]
    fn test_two_hop_decay() {
        let a = fp('a');
        let b = fp('b');
        let c = fp('c');
        let mut graph = TrustGraph::new(vec![a.clone()]);

        graph.add_endorsement(make_tier2(&a, &b, "test", 1.0));
        graph.add_endorsement(make_tier2(&b, &c, "test", 1.0));

        let score_c = graph.trust_score(&c, "test");
        // 0.85^2 * (1 + 0.5/2) / (1 + 0.1*1) ≈ 0.821
        assert!((score_c - 0.821).abs() < 0.02, "got {}", score_c);
    }

    #[test]
    fn test_cycle_does_not_inflate() {
        let a = fp('a');
        let b = fp('b');
        let c = fp('c');
        let mut graph = TrustGraph::new(vec![a.clone()]);

        graph.add_endorsement(make_tier2(&a, &b, "test", 1.0));
        graph.add_endorsement(make_tier2(&b, &c, "test", 1.0));
        graph.add_endorsement(make_tier2(&c, &a, "test", 1.0));

        assert_eq!(graph.trust_score(&a, "test"), 1.0);

        let score_b = graph.trust_score(&b, "test");
        assert!((score_b - 0.826).abs() < 0.02, "B: got {}", score_b);

        let score_c = graph.trust_score(&c, "test");
        assert!((score_c - 0.703).abs() < 0.02, "C: got {}", score_c);
    }

    #[test]
    fn test_domain_filtered_path() {
        let a = fp('a');
        let b = fp('b');
        let c = fp('c');
        let mut graph = TrustGraph::new(vec![a.clone()]);

        graph.add_endorsement(make_tier2(&a, &b, "rust", 1.0));
        graph.add_endorsement(make_tier2(&b, &c, "translation", 1.0));

        assert!(graph.shortest_trust_path(&a, &b, "rust").is_some());
        assert!(graph.shortest_trust_path(&a, &c, "rust").is_none());
        assert!(graph.shortest_trust_path(&a, &b, "translation").is_none());
    }

    #[test]
    fn test_can_issue_tier2_domain_specific() {
        let target = fp('b');
        let mut graph = TrustGraph::new(vec![fp('a')]);

        for i in 0..3 {
            let endorser = fp(char::from_digit(i + 1, 10).unwrap());
            graph.add_endorsement(make_tier2(&endorser, &target, "rust", 0.9));
        }

        assert!(graph.can_issue_tier2_in_domain(&target, "rust"));
        assert!(!graph.can_issue_tier2_in_domain(&target, "translation"));
        assert!(graph.can_issue_tier2(&target));
    }

    #[test]
    fn test_degree_methods() {
        let a = fp('a');
        let b = fp('b');
        let c = fp('c');
        let mut graph = TrustGraph::new(vec![a.clone()]);

        graph.add_endorsement(make_tier2(&a, &b, "test", 1.0));
        graph.add_endorsement(make_tier2(&a, &c, "test", 1.0));
        graph.add_endorsement(make_tier2(&b, &c, "test", 1.0));

        assert_eq!(graph.out_degree(&a), 2);
        assert_eq!(graph.in_degree(&a), 0);
        assert_eq!(graph.total_degree(&a), 2);
        assert_eq!(graph.out_degree(&b), 1);
        assert_eq!(graph.in_degree(&b), 1);
        assert_eq!(graph.out_degree(&c), 0);
        assert_eq!(graph.in_degree(&c), 2);
        assert_eq!(graph.edge_count(), 3);
    }

    #[test]
    fn test_density() {
        let a = fp('a');
        let b = fp('b');
        let mut graph = TrustGraph::new(vec![a.clone()]);
        assert_eq!(graph.density(), 0.0);

        graph.add_endorsement(make_tier2(&a, &b, "test", 1.0));
        assert!((graph.density() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_custom_config() {
        let a = fp('a');
        let b = fp('b');
        let c = fp('c');
        let config = TrustGraphConfig {
            damping: 0.5,
            max_hops: 2,
            threshold: 5,
            alpha: 0.1,
            beta: 0.5,
            gamma: 0.01,
        };
        let mut graph = TrustGraph::with_config(vec![a.clone()], config);

        graph.add_endorsement(make_tier2(&a, &b, "test", 1.0));
        graph.add_endorsement(make_tier2(&b, &c, "test", 1.0));

        let score_b = graph.trust_score(&b, "test");
        assert!((score_b - 0.486).abs() < 0.02, "B: got {}", score_b);

        let score_c = graph.trust_score(&c, "test");
        assert!((score_c - 0.284).abs() < 0.02, "C: got {}", score_c);

        assert!(!graph.can_issue_tier2(&b));
    }

    #[test]
    fn test_aggregation_sums_paths() {
        let seed_a = fp('a');
        let seed_b = fp('b');
        let target = fp('c');
        let mut graph = TrustGraph::new(vec![seed_a.clone(), seed_b.clone()]);

        graph.add_endorsement(make_tier2(&seed_a, &target, "rust", 1.0));
        graph.add_endorsement(make_tier2(&seed_b, &target, "rust", 1.0));

        let score = graph.trust_score(&target, "rust");
        assert!(score > DAMPING + 0.01, "got {}", score);
        assert_eq!(score, 1.0, "clamped to 1.0");
    }
}
