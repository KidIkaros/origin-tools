// SPDX-License-Identifier: Apache-2.0

//! Gap-closure tests: atomic writes, per-layer MMR, multi-axis zoom.

use chrono::NaiveDate;
use origin_crypto_sdk::tier::MemoryTier;
use origin_memory::axis::ZoomQuery;
use origin_memory::layer::LayerMmr;
use origin_memory::memory::Memory;
use origin_memory::node::{Evidence, MemoryNode};

const SEED: [u8; 32] = [0x42u8; 32];

const MD_2004: &str = r#"---
title: Event 2004
time: 2004-03-11
topic: [geopolitics, finance]
evidence: documented
---
A documented event in 2004.
"#;

const MD_2024: &str = r#"---
title: Event 2024
time: 2024-03-11
topic: [geopolitics]
evidence: assertion
---
An assertion in 2024.
"#;

#[test]
fn atomic_write_persists_markdown() {
    // Gap 1: .md writes go through origin_common::io::atomic_write, so the
    // canonical file is always fully present (never a half-written temp).
    let dir = std::env::temp_dir().join(format!("origin-memory-atomic-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");
    let n = MemoryNode::from_markdown("event-2004", MD_2004).unwrap();
    mem.add(n).expect("add");
    let md = std::fs::read_to_string(dir.join("event-2004.md")).expect("md file exists");
    assert!(md.contains("A documented event in 2004."));
    // No stray temp files left behind.
    let temps: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
        .collect();
    assert!(temps.is_empty(), "leftover temp files: {:?}", temps);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn layer_mmr_proves_membership() {
    // Gap 2: a layer commits to its members with a single root; membership of
    // any leaf is provable without trusting the host.
    let n1 = MemoryNode::from_markdown("event-2004", MD_2004).unwrap();
    let n2 = MemoryNode::from_markdown("event-2024", MD_2024).unwrap();

    let mut layer = LayerMmr::new("topic:geopolitics");
    layer.append(&n1);
    layer.append(&n2);
    assert_eq!(layer.len(), 2);

    let root = layer.root();
    let proof = layer.prove("event-2004").expect("proof exists");
    assert!(layer.verify(&proof), "member verifies against layer root");
    assert_eq!(
        proof.leaf_hash,
        hex::encode(*origin_crypto_sdk::blake3::hash(n1.to_markdown().as_bytes()).as_bytes())
    );

    // Tampering: a different node is NOT a member.
    let intruder = MemoryNode::from_markdown(
        "intruder",
        "---\ntitle: X\ntime: 2000-01-01\ntopic: [x]\nevidence: fiction\n---\nNope.\n",
    )
    .unwrap();
    assert!(layer.prove("intruder").is_none());

    // A proof for n1 must fail against a layer that never contained it.
    let mut other = LayerMmr::new("topic:other");
    other.append(&intruder);
    assert!(
        !other.verify(&proof),
        "proof from one layer fails another's root"
    );
    let _ = root;
}

#[test]
fn multi_axis_zoom_intersects_axes() {
    // Gap 3: zoom projects onto multiple orthogonal axes and intersects them.
    let dir = std::env::temp_dir().join(format!("origin-memory-zoom-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");
    mem.add(MemoryNode::from_markdown("event-2004", MD_2004).unwrap())
        .expect("add 1");
    mem.add(MemoryNode::from_markdown("event-2024", MD_2024).unwrap())
        .expect("add 2");

    // "documented geopolitics facts around 2004" — time ∩ topic ∩ evidence.
    let q = ZoomQuery {
        time: Some((NaiveDate::from_ymd_opt(2004, 1, 1).unwrap(), 365)),
        topics: Some(vec!["geopolitics".to_string()]),
        evidence: Some(Evidence::Documented),
        tier: None,
    };
    let got = mem.zoom(&q);
    assert_eq!(got, vec!["event-2004".to_string()]);

    // Same topic but ask for assertion evidence -> only event-2024 (which is in 2024).
    let q2 = ZoomQuery {
        time: Some((NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(), 365)),
        topics: Some(vec!["geopolitics".to_string()]),
        evidence: Some(Evidence::Assertion),
        tier: None,
    };
    assert_eq!(mem.zoom(&q2), vec!["event-2024".to_string()]);

    // Tier axis alone: Sovereign (documented) node.
    let q3 = ZoomQuery {
        time: None,
        topics: None,
        evidence: None,
        tier: Some(MemoryTier::Sovereign),
    };
    assert!(mem.zoom(&q3).contains(&"event-2004".to_string()));

    // Unconstrained query returns everything.
    let q4 = ZoomQuery::default();
    assert_eq!(mem.zoom(&q4).len(), 2);

    // M2: a clean load reports no tampered nodes.
    drop(mem);
    let mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("reopen");
    assert!(mem.tampered().is_empty(), "clean store reports no tamper");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_evidence_field_is_rejected() {
    // M3: a node without an `evidence` field must fail to parse, not silently
    // degrade to Assertion (lower trust) in a provenance system.
    let bad = "---\ntitle: X\ntime: 2000-01-01\ntopic: [x]\n---\nNo evidence field.\n";
    assert!(MemoryNode::from_markdown("bad", bad).is_err());
    // An unrecognized evidence label still parses (falls back to Assertion),
    // but a missing field is a hard error.
    let unknown =
        "---\ntitle: Y\ntime: 2000-01-01\ntopic: [x]\nevidence: gibberish\n---\nWeird label.\n";
    assert!(MemoryNode::from_markdown("weird", unknown).is_ok());
}
