// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-attest` as a foundational dependency.
//!
//! Attestation primitives through the typed library API, with REAL
//! Falcon-1024 signatures (the SDK is the sole crypto provider):
//! signed capability claims, hash-chained endorsements, an agent
//! registry, personalized-PageRank trust scores, hash-chained audit
//! logs, revocation, and anti-DoS cookies.
//!
//! Run with: `cargo run -p origin-attest --example dogfood`

use origin_attest::audit::{AuditEntry, AuditLog};
use origin_attest::cookie::{Cookie, CookieSecret};
use origin_attest::registry::{AgentRecord, AgentRegistry};
use origin_attest::revocation::{RevocationJournal, RevocationRecord};
use origin_attest::trust::TrustGraph;
use origin_attest::types::{CapabilityClaim, Endorsement, EndorsementTier};
use origin_crypto_sdk::signing::postquantum::Falcon1024Signer;

fn fp(seed: u8) -> String {
    format!("{:02x}", seed).repeat(64)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Four agents, each with a real Falcon-1024 keypair.
    let mut signers = Vec::new();
    for i in 0..4u8 {
        let s = Falcon1024Signer::from_seed(&[0x10 + i; 32]).map_err(|e| e.to_string())?;
        signers.push(s);
    }
    let fps: Vec<String> = (0..4).map(|i| fp(0x10 + i as u8)).collect();
    let pks: Vec<String> = signers
        .iter()
        .map(|s| hex::encode(s.public_key_bytes()))
        .collect();

    // ── signed capability claim (Alice: "code-review") ───────────────
    let mut claim = CapabilityClaim {
        fingerprint: fps[0].clone(),
        falcon_pk: pks[0].clone(),
        epoch: 1,
        capabilities: vec!["code-review".to_string()],
        metadata: serde_json::json!({ "org": "origin-tools" }),
        timestamp: 1_700_000_000,
        expires: 0,
        falcon_signature: Vec::new(),
    };
    claim.falcon_signature = signers[0]
        .sign(&claim.signable_bytes())
        .map_err(|e| e.to_string())?;
    assert!(claim.verify_signature(), "signed claim must verify");
    // Tamper → signature breaks.
    let mut tampered = claim.clone();
    tampered.capabilities = vec!["admin".to_string()];
    assert!(
        !tampered.verify_signature(),
        "tampered claim must not verify"
    );
    println!("✓ signed CapabilityClaim (Falcon-1024) + tamper detection");

    // ── endorsement chain with real signatures ───────────────────────
    let now = 1_700_000_000i64;
    let mut chain = Vec::new();
    for hop in 0..3usize {
        let mut e = Endorsement {
            tier: EndorsementTier::Tier2,
            endorser_fp: fps[hop].clone(),
            endorsee_fp: fps[hop + 1].clone(),
            capability_domain: "code-review".to_string(),
            confidence: 0.95,
            context: "dogfood vouch".to_string(),
            timestamp: now + hop as i64,
            valid_until: 0,
            prev_hash: [0u8; 32],
            nonce: hop as u64 + 1,
            falcon_signature: Vec::new(),
            revocation: false,
            supersedes: None,
        };
        e.falcon_signature = signers[hop]
            .sign(&e.signable_bytes())
            .map_err(|e| e.to_string())?;
        // Verify each signature against the endorser's public key.
        assert!(
            e.verify_signature(&pks[hop]),
            "endorsement {hop} must verify against endorser pk"
        );
        chain.push(e);
    }
    println!("✓ endorsement chain: 3 signed Tier-2 vouches");

    // ── agent registry: claims + endorsements in one knowledge base ──
    let mut registry = AgentRegistry::new();
    for i in 0..4 {
        registry.register(AgentRecord::new(fps[i].clone(), pks[i].clone(), 1));
    }
    registry.add_claim(&fps[0], claim.clone())?;
    for e in &chain {
        registry.add_endorsement(e.clone())?;
    }
    assert_eq!(registry.count(), 4);
    assert_eq!(
        registry.search_by_capability("code-review").len(),
        1,
        "only Alice claimed code-review"
    );
    assert_eq!(
        registry.get(&fps[1]).unwrap().endorsements_received.len(),
        1
    );
    assert_eq!(registry.get(&fps[3]).unwrap().endorsements_given.len(), 0);
    println!("✓ AgentRegistry (register / claim / endorsement bookkeeping)");

    // ── trust graph: personalized PageRank over the vouches ──────────
    let mut graph = TrustGraph::new(vec![fps[0].clone()]);
    for e in &chain {
        graph.add_endorsement(e.clone());
    }
    let score_bob = graph.trust_score(&fps[1], "code-review");
    let score_carol = graph.trust_score(&fps[2], "code-review");
    let score_dave = graph.trust_score(&fps[3], "code-review");
    assert!(score_bob > 0.5, "bob directly vouched (score {score_bob})");
    assert!(
        score_carol > 0.2 && score_carol < score_bob,
        "carol one hop further (score {score_carol})"
    );
    assert!(score_dave < score_carol, "dave decays with distance");
    assert_eq!(graph.trust_score(&fps[0], "code-review"), 1.0, "seed = 1.0");
    let path = graph
        .shortest_trust_path(&fps[0], &fps[3], "code-review")
        .ok_or("trust path alice→dave must exist")?;
    assert_eq!(path.len(), 4);
    println!("✓ TrustGraph scores: bob={score_bob:.3} carol={score_carol:.3} dave={score_dave:.3}");

    // ── audit log: hash-chained session record ───────────────────────
    let mut log = AuditLog::new();
    for i in 0..3 {
        log.append(AuditEntry {
            prev_hash: [0u8; 32],
            seq: i,
            entry_type: 1,
            payload_hash: origin_crypto_sdk::sha3_256(format!("interaction {i}").as_bytes()),
            timestamp: 1_700_000_000 + i as u64,
            signature: None,
        });
    }
    assert!(log.verify_chain().map_err(|e| format!("{e}"))?);
    // Tamper with the chain root — the public field — and the chain breaks.
    log.root_hash[0] ^= 0xFF;
    assert!(
        log.verify_chain().is_err(),
        "tampered audit log must fail chain verification"
    );
    println!("✓ AuditLog hash chain + tamper detection");

    // ── revocation journal ───────────────────────────────────────────
    let mut journal = RevocationJournal::new();
    let target = claim.hash();
    journal.append(RevocationRecord {
        target_hash: target,
        revoked_by: fps[0].clone(),
        reason: "key rotation".to_string(),
        timestamp: now,
        prev_hash: [0u8; 32],
        signature: Vec::new(),
    });
    assert!(journal.is_revoked(&target));
    assert!(journal.verify_integrity().is_ok());
    println!("✓ RevocationJournal (append + lookup + chain)");

    // ── anti-DoS cookie (WireGuard-style) ────────────────────────────
    let secret = CookieSecret::new().map_err(|e| e.to_string())?;
    let cookie: Cookie = secret.generate("203.0.113.9");
    assert!(secret.verify("203.0.113.9", &cookie), "cookie verifies");
    assert!(
        !secret.verify("198.51.100.7", &cookie),
        "cookie is source-IP-bound"
    );
    let encoded = origin_attest::cookie::encode_cookie_challenge(&cookie);
    let decoded = origin_attest::cookie::decode_cookie_frame(&encoded).expect("round-trip");
    assert!(secret.verify("203.0.113.9", &decoded));
    println!("✓ CookieSecret mint → verify → encode/decode");

    println!("\norigin-attest dogfood OK — usable as a foundational dependency");
    Ok(())
}
