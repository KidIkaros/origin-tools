//! End-to-end integration test for origin-attest.
//!
//! Full pipeline: generate keys → sign claim → endorse → build chain →
//! feed trust graph → compute trust scores → revoke → verify revocation
//! journal integrity → audit log → anti-DoS cookies.

use origin_attest::{
    AgentRecord, AgentRegistry, AuditEntry, AuditLog, CapabilityClaim, CookieSecret, Endorsement,
    EndorsementChain, EndorsementTier, RevocationJournal, RevocationRecord, TrustGraph,
};
use origin_crypto_sdk::signing::postquantum::Falcon1024Signer;

/// Helper: generate a Falcon-1024 signer from a deterministic seed.
fn make_signer(seed_byte: u8) -> Falcon1024Signer {
    let seed = [seed_byte; 32];
    Falcon1024Signer::from_seed(&seed).expect("keygen should succeed")
}

/// Helper: hex fingerprint from a signer's public key (first 32 bytes hashed).
fn fingerprint(signer: &Falcon1024Signer) -> String {
    let pk = signer.public_key_bytes();
    let hash = origin_crypto_sdk::sha3_256(&pk);
    hex::encode(hash)
}

/// Helper: hex-encoded public key.
fn pk_hex(signer: &Falcon1024Signer) -> String {
    hex::encode(signer.public_key_bytes())
}

/// Helper: sign a claim with the given signer.
fn sign_claim(claim: &mut CapabilityClaim, signer: &Falcon1024Signer) {
    claim.falcon_signature = signer.sign(&claim.signable_bytes()).expect("sign");
}

/// Helper: sign an endorsement with the given signer.
fn sign_endorsement(endorsement: &mut Endorsement, signer: &Falcon1024Signer) {
    endorsement.falcon_signature = signer.sign(&endorsement.signable_bytes()).expect("sign");
}

/// Helper: build a Tier-2 endorsement.
fn make_tier2(
    endorser_fp: &str,
    endorsee_fp: &str,
    domain: &str,
    confidence: f64,
    nonce: u64,
) -> Endorsement {
    Endorsement {
        tier: EndorsementTier::Tier2,
        endorser_fp: endorser_fp.to_string(),
        endorsee_fp: endorsee_fp.to_string(),
        capability_domain: domain.to_string(),
        confidence,
        context: "integration test".to_string(),
        timestamp: 1_700_000_000,
        valid_until: 0, // never expires
        prev_hash: [0u8; 32],
        nonce,
        falcon_signature: vec![],
        revocation: false,
        supersedes: None,
    }
}

// ── Full pipeline test ────────────────────────────────────────────

#[test]
fn full_attestation_pipeline() {
    // ── 1. Generate keys for three agents ─────────────────────────
    let alice = make_signer(0xAA);
    let bob = make_signer(0xBB);
    let carol = make_signer(0xCC);

    let alice_fp = fingerprint(&alice);
    let bob_fp = fingerprint(&bob);
    let carol_fp = fingerprint(&carol);

    let alice_pk = pk_hex(&alice);
    let bob_pk = pk_hex(&bob);
    let carol_pk = pk_hex(&carol);

    // Fingerprints must be distinct
    assert_ne!(alice_fp, bob_fp);
    assert_ne!(bob_fp, carol_fp);
    assert_ne!(alice_fp, carol_fp);

    // ── 2. Alice signs a capability claim ─────────────────────────
    let mut claim = CapabilityClaim {
        fingerprint: alice_fp.clone(),
        falcon_pk: alice_pk.clone(),
        epoch: 1,
        capabilities: vec!["code-review".to_string(), "security-audit".to_string()],
        metadata: serde_json::json!({"org": "origin-tools"}),
        timestamp: 1_700_000_000,
        expires: 0,
        falcon_signature: vec![],
    };
    sign_claim(&mut claim, &alice);

    // ── 3. Verify the claim signature ─────────────────────────────
    assert!(
        claim.verify_signature(),
        "Alice's claim signature must verify"
    );

    // Tamper detection: modifying capabilities breaks the signature
    let mut tampered = claim.clone();
    tampered.capabilities.push("hacking".to_string());
    assert!(
        !tampered.verify_signature(),
        "tampered claim must fail verification"
    );

    // ── 4. Register all agents ────────────────────────────────────
    let mut registry = AgentRegistry::new();
    registry.register(AgentRecord::new(alice_fp.clone(), alice_pk.clone(), 1));
    registry.register(AgentRecord::new(bob_fp.clone(), bob_pk.clone(), 1));
    registry.register(AgentRecord::new(carol_fp.clone(), carol_pk.clone(), 1));
    assert_eq!(registry.count(), 3);

    // Add Alice's claim to the registry
    registry.add_claim(&alice_fp, claim.clone()).unwrap();
    let alice_record = registry.get(&alice_fp).unwrap();
    assert_eq!(alice_record.claims.len(), 1);
    assert_eq!(alice_record.claims[0].capabilities.len(), 2);

    // Search by capability
    let reviewers = registry.search_by_capability("code-review");
    assert_eq!(reviewers.len(), 1);
    assert_eq!(reviewers[0].fingerprint, alice_fp);

    // ── 5. Bob and Carol endorse Alice (Tier-2) ───────────────────
    let mut e_bob = make_tier2(&bob_fp, &alice_fp, "code-review", 0.95, 1);
    sign_endorsement(&mut e_bob, &bob);
    assert!(e_bob.verify_signature(&bob_pk));

    let mut e_carol = make_tier2(&carol_fp, &alice_fp, "code-review", 0.85, 1);
    sign_endorsement(&mut e_carol, &carol);
    assert!(e_carol.verify_signature(&carol_pk));

    // Wrong key must fail
    assert!(!e_bob.verify_signature(&carol_pk));

    // ── 6. Build endorsement chain ────────────────────────────────
    let mut chain = EndorsementChain::new();
    chain.append(e_bob.clone());
    chain.append(e_carol.clone());
    assert_eq!(chain.len(), 2);
    assert!(chain.verify_integrity().is_ok());

    // Chain links: second endorsement's prev_hash == first's hash
    assert_eq!(
        chain.endorsements[1].prev_hash,
        chain.endorsements[0].hash()
    );

    // Tamper detection
    let mut tampered_chain = chain.clone();
    tampered_chain.endorsements[0].confidence = 0.01;
    assert!(tampered_chain.verify_integrity().is_err());

    // ── 7. Feed trust graph and compute scores ────────────────────
    // Bob is our seed (directly trusted). Alice should get trust via Bob.
    let mut graph = TrustGraph::new(vec![bob_fp.clone()]);
    graph.add_endorsement(e_bob.clone());
    graph.add_endorsement(e_carol.clone());
    graph.add_claim(claim.clone());

    // Bob is a seed → trust score 1.0
    let bob_score = graph.trust_score(&bob_fp, "code-review");
    assert!(
        (bob_score - 1.0).abs() < f64::EPSILON,
        "seed must have trust 1.0, got {bob_score}"
    );

    // Alice gets trust via Bob's Tier-2 endorsement (damped by confidence)
    let alice_score = graph.trust_score(&alice_fp, "code-review");
    assert!(
        alice_score > 0.0,
        "Alice must have positive trust via Bob's endorsement"
    );
    assert!(
        alice_score < 1.0,
        "Alice's trust must be < 1.0 (not a seed)"
    );

    // Carol has no path from seeds → trust 0
    let carol_score = graph.trust_score(&carol_fp, "code-review");
    assert!(
        carol_score < 0.01,
        "Carol has no trust path from seeds, got {carol_score}"
    );

    // Domain isolation: no endorsements in "translation" → zero trust
    let alice_translation = graph.trust_score(&alice_fp, "translation");
    assert!(
        alice_translation < 0.01,
        "no endorsements in 'translation' domain"
    );

    // ── 8. Threshold: can_issue_tier2 requires 3+ Tier-2 endorsements ──
    // Alice has 2 Tier-2 endorsements (from Bob and Carol) → below threshold
    assert!(
        !graph.can_issue_tier2(&alice_fp),
        "Alice has only 2 Tier-2 endorsements, needs 3"
    );

    // Add a third endorsement from a new agent
    let dave = make_signer(0xDD);
    let dave_fp = fingerprint(&dave);
    registry.register(AgentRecord::new(dave_fp.clone(), pk_hex(&dave), 1));

    let mut e_dave = make_tier2(&dave_fp, &alice_fp, "code-review", 0.80, 1);
    sign_endorsement(&mut e_dave, &dave);
    graph.add_endorsement(e_dave.clone());

    // Now Alice has 3 Tier-2 endorsements → can issue Tier-2
    assert!(
        graph.can_issue_tier2(&alice_fp),
        "Alice now has 3 Tier-2 endorsements"
    );

    // ── 9. Shortest trust path ────────────────────────────────────
    let path = graph.shortest_trust_path(&bob_fp, &alice_fp, "code-review");
    assert!(path.is_some(), "path from Bob to Alice must exist");
    let path = path.unwrap();
    assert_eq!(path[0], bob_fp);
    assert_eq!(path[path.len() - 1], alice_fp);

    // No path from Bob to Dave in code-review (Dave only endorsed, not endorsed by seeds)
    let no_path = graph.shortest_trust_path(&bob_fp, &dave_fp, "code-review");
    assert!(no_path.is_none(), "no trust path from Bob to Dave");

    // ── 10. Revoke an endorsement ─────────────────────────────────
    let mut journal = RevocationJournal::new();
    let revoked_hash = e_carol.hash();

    let revocation = RevocationRecord {
        target_hash: revoked_hash,
        revoked_by: carol_fp.clone(),
        reason: "key compromise".to_string(),
        timestamp: 1_700_001_000,
        prev_hash: [0u8; 32],
        signature: vec![],
    };
    journal.append(revocation);

    assert!(journal.is_revoked(&revoked_hash));
    assert!(!journal.is_revoked(&e_bob.hash()));
    assert!(journal.verify_integrity().is_ok());

    // Revoked endorsement is no longer valid
    let mut revoked_e = e_carol.clone();
    revoked_e.revocation = true;
    assert!(!revoked_e.is_valid(1_700_000_500));

    // ── 11. Audit log for the session ─────────────────────────────
    let mut audit = AuditLog::new();
    let payload1 = origin_crypto_sdk::sha3_256(b"alice-claims-code-review");
    let payload2 = origin_crypto_sdk::sha3_256(b"bob-endorses-alice");
    let payload3 = origin_crypto_sdk::sha3_256(b"carol-endorses-alice");

    audit.append(AuditEntry {
        prev_hash: [0u8; 32],
        seq: 1,
        entry_type: 1, // claim
        payload_hash: payload1,
        timestamp: 1_700_000_000,
        signature: None,
    });
    audit.append(AuditEntry {
        prev_hash: [0u8; 32],
        seq: 2,
        entry_type: 2, // endorsement
        payload_hash: payload2,
        timestamp: 1_700_000_100,
        signature: None,
    });
    audit.append(AuditEntry {
        prev_hash: [0u8; 32],
        seq: 3,
        entry_type: 2, // endorsement
        payload_hash: payload3,
        timestamp: 1_700_000_200,
        signature: None,
    });

    assert_eq!(audit.len(), 3);
    assert!(audit.verify_chain().unwrap());
    assert_eq!(audit.seqs(), vec![1, 2, 3]);

    // ── 12. Anti-DoS cookie handshake ─────────────────────────────
    let cookie_secret = CookieSecret::new().unwrap();
    let initiator_ip = "203.0.113.42";

    // Responder generates a cookie for the initiator's IP
    let cookie = cookie_secret.generate(initiator_ip);

    // Initiator echoes the cookie back — responder verifies
    assert!(
        cookie_secret.verify(initiator_ip, &cookie),
        "valid cookie must verify"
    );

    // Spoofed IP must fail
    assert!(
        !cookie_secret.verify("198.51.100.1", &cookie),
        "cookie for different IP must fail"
    );

    // Corrupted cookie must fail
    let mut bad_cookie = cookie;
    bad_cookie[0] ^= 0xFF;
    assert!(!cookie_secret.verify(initiator_ip, &bad_cookie));

    // ── 13. Graph metrics sanity ──────────────────────────────────
    assert_eq!(graph.len(), 4); // alice, bob, carol, dave
    assert!(graph.edge_count() >= 3);
    assert!(graph.density() > 0.0);
    assert!(graph.in_degree(&alice_fp) >= 3);
    assert_eq!(graph.out_degree(&alice_fp), 0); // Alice endorsed nobody

    // trusted_agents returns sorted results
    let trusted = graph.trusted_agents("code-review", 0.01);
    assert!(!trusted.is_empty());
    // Scores must be descending
    for w in trusted.windows(2) {
        assert!(w[0].1 >= w[1].1, "trusted_agents must be sorted descending");
    }
}

// ── Multi-hop trust propagation ───────────────────────────────────

#[test]
fn multi_hop_trust_propagation() {
    // Seed → A → B → C: trust decays with each hop
    let seed = make_signer(0x01);
    let a = make_signer(0x02);
    let b = make_signer(0x03);
    let c = make_signer(0x04);

    let seed_fp = fingerprint(&seed);
    let a_fp = fingerprint(&a);
    let b_fp = fingerprint(&b);
    let c_fp = fingerprint(&c);

    let mut graph = TrustGraph::new(vec![seed_fp.clone()]);

    // Seed → A (confidence 0.9)
    let mut e1 = make_tier2(&seed_fp, &a_fp, "rust", 0.9, 1);
    sign_endorsement(&mut e1, &seed);
    graph.add_endorsement(e1);

    // A → B (confidence 0.8)
    let mut e2 = make_tier2(&a_fp, &b_fp, "rust", 0.8, 2);
    sign_endorsement(&mut e2, &a);
    graph.add_endorsement(e2);

    // B → C (confidence 0.7)
    let mut e3 = make_tier2(&b_fp, &c_fp, "rust", 0.7, 3);
    sign_endorsement(&mut e3, &b);
    graph.add_endorsement(e3);

    let score_a = graph.trust_score(&a_fp, "rust");
    let score_b = graph.trust_score(&b_fp, "rust");
    let score_c = graph.trust_score(&c_fp, "rust");

    // Trust must decay: A > B > C > 0
    assert!(score_a > score_b, "A ({score_a}) > B ({score_b})");
    assert!(score_b > score_c, "B ({score_b}) > C ({score_c})");
    assert!(score_c > 0.0, "C must have positive trust");

    // Shortest path: seed → A → B → C
    let path = graph.shortest_trust_path(&seed_fp, &c_fp, "rust").unwrap();
    assert_eq!(path.len(), 4);
    assert_eq!(path[0], seed_fp);
    assert_eq!(path[3], c_fp);
}

// ── Revocation journal chain integrity ───────────────────────────

#[test]
fn revocation_journal_multi_entry_chain() {
    let mut journal = RevocationJournal::new();

    let targets: Vec<[u8; 32]> = (0..5u8).map(|i| [i; 32]).collect();

    for (i, target) in targets.iter().enumerate() {
        journal.append(RevocationRecord {
            target_hash: *target,
            revoked_by: format!("admin-{i}"),
            reason: format!("reason-{i}"),
            timestamp: 1_700_000_000 + i as i64,
            prev_hash: [0u8; 32],
            signature: vec![],
        });
    }

    assert_eq!(journal.len(), 5);
    assert!(journal.verify_integrity().is_ok());

    // All targets are revoked
    for target in &targets {
        assert!(journal.is_revoked(target));
    }

    // Unknown target is not revoked
    assert!(!journal.is_revoked(&[0xFF; 32]));

    // Tamper with a middle record → chain breaks
    let mut tampered = journal.clone();
    tampered.records[2].reason = "hacked".to_string();
    assert!(tampered.verify_integrity().is_err());
}

// ── Registry + chain integration ──────────────────────────────────

#[test]
fn registry_endorsement_chain_grows() {
    let alice = make_signer(0xAA);
    let bob = make_signer(0xBB);
    let carol = make_signer(0xCC);

    let alice_fp = fingerprint(&alice);
    let bob_fp = fingerprint(&bob);
    let carol_fp = fingerprint(&carol);

    let mut registry = AgentRegistry::new();
    registry.register(AgentRecord::new(alice_fp.clone(), pk_hex(&alice), 1));
    registry.register(AgentRecord::new(bob_fp.clone(), pk_hex(&bob), 1));
    registry.register(AgentRecord::new(carol_fp.clone(), pk_hex(&carol), 1));

    // Bob endorses Alice, then Carol endorses Alice
    let mut e1 = make_tier2(&bob_fp, &alice_fp, "review", 0.9, 1);
    sign_endorsement(&mut e1, &bob);
    registry.add_endorsement(e1).unwrap();

    let mut e2 = make_tier2(&carol_fp, &alice_fp, "review", 0.8, 1);
    sign_endorsement(&mut e2, &carol);
    registry.add_endorsement(e2).unwrap();

    // Bob's chain should have 1 endorsement
    let bob_record = registry.get(&bob_fp).unwrap();
    assert_eq!(bob_record.chain.len(), 1);
    assert!(bob_record.chain.verify_integrity().is_ok());

    // Alice received 2 endorsements
    let alice_record = registry.get(&alice_fp).unwrap();
    assert_eq!(alice_record.endorsements_received.len(), 2);
    assert_eq!(alice_record.endorsements_given.len(), 0);
}

// ── Cookie rotation ───────────────────────────────────────────────

#[test]
fn cookie_rotation_preserves_old_cookies() {
    let mut secret = CookieSecret::new().unwrap();
    let ip = "192.0.2.1";

    let cookie_before = secret.generate(ip);
    assert!(secret.verify(ip, &cookie_before));

    // Rotate — old cookie must still verify (previous secret kept)
    secret.force_rotate().unwrap();
    assert!(
        secret.verify(ip, &cookie_before),
        "old cookie must verify after rotation"
    );

    // New cookie differs
    let cookie_after = secret.generate(ip);
    assert_ne!(cookie_before, cookie_after);
    assert!(secret.verify(ip, &cookie_after));
}
