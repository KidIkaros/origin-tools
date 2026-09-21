// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-attest` as a foundational dependency.
//!
//! Agent attestation through the typed library API (`origin_attest`):
//! register agents, sign a capability claim with Falcon-1024 (via the SDK),
//! build a hash-chained endorsement chain, revoke an endorsement, and rank
//! trust with the graph — including negative paths (tampered signature,
//! broken chain, revoked endorsement). No CLI, no files.
//!
//! Run with: `cargo run -p origin-attest --example dogfood`

use origin_attest::{
    AgentRecord, AgentRegistry, AttestError, CapabilityClaim, Endorsement, EndorsementChain,
    EndorsementTier, RevocationJournal, RevocationRecord, TrustGraph,
};
use origin_crypto_sdk::signing::postquantum::Falcon1024Signer;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Falcon-1024 identities for two agents (via the SDK) ───────────
    let merchant = Falcon1024Signer::from_seed(&[0xA1u8; 32])?;
    let worker = Falcon1024Signer::from_seed(&[0xB2u8; 32])?;
    let merchant_pk = hex::encode(merchant.public_key_bytes());
    let worker_pk = hex::encode(worker.public_key_bytes());
    let merchant_fp = hex::encode(origin_crypto_sdk::sha3_256(&merchant.public_key_bytes()));
    let worker_fp = hex::encode(origin_crypto_sdk::sha3_256(&worker.public_key_bytes()));
    println!("✓ Falcon-1024 identities derived (SDK)");

    // ── signed capability claim ───────────────────────────────────────
    let mut claim = CapabilityClaim {
        fingerprint: worker_fp.clone(),
        falcon_pk: worker_pk.clone(),
        epoch: 1,
        capabilities: vec!["code-review".into(), "translation".into()],
        metadata: serde_json::json!({}),
        timestamp: now(),
        expires: 0,
        falcon_signature: vec![],
    };
    claim.falcon_signature = worker.sign(&claim.signable_bytes())?;
    assert!(claim.verify_signature(), "claim signature must verify");
    println!("✓ capability claim signed + verified (Falcon-1024)");

    // Tampered claim must fail verification.
    let mut bad = claim.clone();
    bad.capabilities.push("admin".into());
    assert!(!bad.verify_signature(), "tampered claim must fail");
    println!("✓ tampered claim rejected");

    // ── registry + endorsement chain ──────────────────────────────────
    let mut registry = AgentRegistry::new();
    registry.register(AgentRecord::new(
        merchant_fp.clone(),
        merchant_pk.clone(),
        1,
    ));
    registry.register(AgentRecord::new(worker_fp.clone(), worker_pk.clone(), 1));
    assert_eq!(registry.count(), 2);

    let mut endorsement = Endorsement {
        tier: EndorsementTier::Tier2,
        endorser_fp: merchant_fp.clone(),
        endorsee_fp: worker_fp.clone(),
        capability_domain: "code-review".into(),
        confidence: 0.9,
        context: "vetted in three review sessions".into(),
        timestamp: now(),
        valid_until: 0,
        prev_hash: [0u8; 32],
        nonce: 1,
        falcon_signature: vec![],
        revocation: false,
        supersedes: None,
    };
    endorsement.falcon_signature = merchant.sign(&endorsement.signable_bytes())?;
    assert!(endorsement.verify_signature(&merchant_pk));

    let mut chain = EndorsementChain::new();
    chain.append(endorsement.clone());
    chain.verify_integrity()?;
    assert_eq!(chain.len(), 1);
    println!("✓ endorsement signed, chained, integrity verified");

    // Broken chain must raise the typed error.
    let mut broken = EndorsementChain::new();
    let mut e2 = endorsement.clone();
    e2.nonce = 2;
    e2.falcon_signature = merchant.sign(&e2.signable_bytes())?;
    broken.append(endorsement.clone());
    broken.append(e2);
    broken.endorsements[0].prev_hash = [9u8; 32]; // tamper
    match broken.verify_integrity() {
        Err(AttestError::ChainBroken(0)) => println!("✓ broken chain → AttestError::ChainBroken"),
        other => panic!("expected ChainBroken, got {other:?}"),
    }

    // ── revocation journal ────────────────────────────────────────────
    let mut journal = RevocationJournal::new();
    let target = endorsement.hash();
    journal.append_signed(
        RevocationRecord {
            target_hash: target,
            revoked_by: merchant_fp.clone(), // overridden: journal-owned identity fields
            reason: "context changed".into(),
            timestamp: now(),
            prev_hash: [0u8; 32],
            signature: vec![],
            revoker_falcon_pk: vec![],
        },
        &merchant,
    )?;
    assert!(journal.is_revoked(&target));
    journal.verify_integrity()?;
    assert_eq!(
        journal.records[0].verify_signature(),
        origin_attest::revocation::SignatureStatus::Valid
    );
    assert!(journal.verify_signatures().is_empty());
    println!("✓ revocation journaled + hash-chained + signature-verified");

    // ── trust graph ranking ───────────────────────────────────────────
    let mut graph = TrustGraph::new(vec![merchant_fp.clone()]);
    graph.add_claim(claim.clone());
    graph.add_endorsement(endorsement.clone());
    let score = graph.trust_score(&worker_fp, "code-review");
    assert!(
        score > 0.0,
        "endorsed agent must score above 0, got {score}"
    );
    assert!(
        !graph.can_issue_tier2(&worker_fp),
        "one Tier-2 vouch is below threshold"
    );
    println!("✓ trust_score(worker, code-review) = {score:.4}; Tier-2 gate enforced");

    println!("\norigin-attest dogfood OK — usable as a foundational dependency");
    Ok(())
}
