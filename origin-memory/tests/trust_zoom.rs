// SPDX-License-Identifier: Apache-2.0

//! R3: trust-weighted zoom — closes M4 (signer trust documented but never wired
//! into `zoom_scored` / `zoom`).
//!
//! Multi-agent scenario: agent A owns the memory, agent B injects a node into
//! the same store. B's node loads (data is never dropped) but its signature
//! can't verify against A's bundle, so it lands in `tampered()` — that's the
//! documented contract. What R3 adds: the *trust* axis now decides visibility
//! and rank. B starts untrusted (min_trust hides the node); once A endorses B,
//! the node surfaces and its score reflects B's propagated trust.

use chrono::NaiveDate;
use origin_memory::{sign_node, Evidence, Memory, MemoryNode, MemoryStore, ZoomQuery};

const SEED_A: [u8; 32] = [42u8; 32];
const SEED_B: [u8; 32] = [99u8; 32];

fn fresh_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("origin-memory-r3-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn node(id: &str, topic: &str) -> MemoryNode {
    let md = format!(
        "---\ntitle: {id}\ntime: 2004-06-01\ntopic: [{topic}]\nevidence: documented\n---\n{topic} fact.\n"
    );
    MemoryNode::from_markdown(id, &md).expect("node parses")
}

/// Memory owned by A with one A-signed node and one B-signed node injected
/// directly into the store (simulating federation).
fn two_agent_memory(dir: &std::path::Path) {
    {
        let mut mem = Memory::open(dir, &SEED_A, "agent-a").expect("open A");
        mem.add(node("a-node", "geo")).expect("add A node");
    }
    {
        // Agent B signs its own node and writes it into the shared store.
        let bundle_b = origin_memory::sign::derive_bundle(&SEED_B, "agent-b");
        let store = MemoryStore::open(dir).expect("store open");
        let sig_b = sign_node(&node("b-node", "geo"), &bundle_b);
        store
            .save(&node("b-node", "geo"), &sig_b)
            .expect("save B node");
    }
}

#[test]
fn min_trust_hides_unendorsed_signer() {
    let dir = fresh_dir("min-trust");
    two_agent_memory(&dir);

    let mem = Memory::open(&dir, &SEED_A, "agent-a").expect("reopen A");
    // B's node is indexed but its foreign signature can't verify against
    // A's bundle — documented contract, never silently dropped.
    assert!(mem.tampered().contains(&"b-node".to_string()));

    let q = ZoomQuery {
        time: None,
        topics: None,
        evidence: None,
        tier: None,
        min_trust: Some(0.5),
        trust_domain: Some("memory-write".into()),
    };
    let ids = mem.zoom(&q);
    assert!(
        ids.contains(&"a-node".to_string()),
        "self-signed node passes"
    );
    assert!(
        !ids.contains(&"b-node".to_string()),
        "unendorsed signer's node must be hidden by min_trust"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn endorsement_reveals_signer_node() {
    let dir = fresh_dir("endorse-reveal");
    two_agent_memory(&dir);

    let mut mem = Memory::open(&dir, &SEED_A, "agent-a").expect("reopen A");
    let bundle_b = origin_memory::sign::derive_bundle(&SEED_B, "agent-b");
    let fp_b = hex::encode(bundle_b.ed25519_pk().as_bytes());
    mem.endorse(&fp_b, "memory-write", 0.9);

    let q = ZoomQuery {
        time: None,
        topics: None,
        evidence: None,
        tier: None,
        min_trust: Some(0.3),
        trust_domain: Some("memory-write".into()),
    };
    let ids = mem.zoom(&q);
    assert!(ids.contains(&"a-node".to_string()));
    assert!(
        ids.contains(&"b-node".to_string()),
        "endorsed signer's node must surface once trust clears min_trust"
    );

    // And the endorsement persists: a fresh open still reveals B's node.
    drop(mem);
    let mem2 = Memory::open(&dir, &SEED_A, "agent-a").expect("third open");
    assert!(mem2.zoom(&q).contains(&"b-node".to_string()));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zoom_scored_carries_signer_trust_dimension() {
    let dir = fresh_dir("scored-dim");
    two_agent_memory(&dir);

    let mem = Memory::open(&dir, &SEED_A, "agent-a").expect("reopen A");
    let q = ZoomQuery::default();
    let scored = mem.zoom_scored(&q);
    assert_eq!(scored.len(), 2, "both nodes scored");

    let a = scored.iter().find(|r| r.id == "a-node").unwrap();
    let b = scored.iter().find(|r| r.id == "b-node").unwrap();

    let a_trust = a.signer_trust.expect("signer_trust present");
    let b_trust = b.signer_trust.expect("signer_trust present");
    assert!(a_trust >= 0.99, "self-signer trust is max: {a_trust}");
    assert!(b_trust < 0.1, "unendorsed signer trust is ~0: {b_trust}");
    // Trust participates in the score: same evidence/tier/topic/time, so the
    // trusted node must rank above the untrusted one.
    assert!(a.score > b.score, "trusted node ranks first");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn single_agent_zoom_unchanged_by_trust_axis() {
    // Single-agent regression: every node is self-signed (trust 1.0), so the
    // trust axis is a constant — min_trust keeps everything and rankings are
    // unchanged relative to the pre-R3 behavior.
    let dir = fresh_dir("single-agent");
    {
        let mut mem = Memory::open(&dir, &SEED_A, "agent-a").expect("open");
        mem.add(node("solo", "geo")).expect("add");
    }
    let mem = Memory::open(&dir, &SEED_A, "agent-a").expect("reopen");

    let q = ZoomQuery {
        time: Some((NaiveDate::from_ymd_opt(2004, 6, 1).unwrap(), 365)),
        topics: Some(vec!["geo".into()]),
        evidence: Some(Evidence::Documented),
        tier: None,
        min_trust: Some(0.99),
        trust_domain: None, // defaults to memory-write
    };
    assert_eq!(mem.zoom(&q), vec!["solo".to_string()]);

    let scored = mem.zoom_scored(&q);
    assert_eq!(scored.len(), 1);
    assert!(scored[0].signer_trust.unwrap() >= 0.99);

    let _ = std::fs::remove_dir_all(&dir);
}
