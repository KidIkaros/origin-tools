// SPDX-License-Identifier: Apache-2.0

//! Proves a coarse summary layer is provable end-to-end, including after reload.

use chrono::NaiveDate;
use origin_crypto_sdk::tier::MemoryTier;
use origin_memory::axis::ZoomQuery;
use origin_memory::memory::Memory;
use origin_memory::node::{Evidence, MemoryNode};

const SEED: [u8; 32] = [0x42u8; 32];

const MD_A: &str = r#"---
title: Event A
time: 2004-03-11
topic: [geopolitics, finance]
evidence: documented
---
Documented event A in 2004.
"#;

const MD_B: &str = r#"---
title: Event B
time: 2004-05-02
topic: [geopolitics]
evidence: documented
---
Documented event B in 2004.
"#;

#[test]
fn summary_layer_is_provable_after_reload() {
    let dir = std::env::temp_dir().join(format!("origin-memory-summary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    // Session 1: add leaves, summarize them into a coarse wing.
    let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");
    let node_a = MemoryNode::from_markdown("event-a", MD_A).unwrap();
    let node_b = MemoryNode::from_markdown("event-b", MD_B).unwrap();
    mem.add(node_a.clone()).expect("add a");
    mem.add(node_b.clone()).expect("add b");

    mem.summarize(
        "summary-2004",
        "geopolitics",
        NaiveDate::from_ymd_opt(2004, 1, 1).unwrap(),
        &[node_a, node_b],
    )
    .expect("summarize");

    // Before reload: the summary's layer proves membership of both leaves.
    assert!(mem.verify_layer("summary-2004", "event-a"));
    assert!(mem.verify_layer("summary-2004", "event-b"));
    assert!(
        !mem.verify_layer("summary-2004", "event-c"),
        "absent leaf not proven"
    );

    // Reload — summary node + layer root must survive from the cold store.
    drop(mem);
    let mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("reopen");

    // The summary node is present and verifiable (signature survives reload).
    assert!(
        mem.verify("summary-2004"),
        "summary signature survives reload"
    );
    // The layer is still provable after reload.
    assert!(
        mem.verify_layer("summary-2004", "event-a"),
        "layer proof survives reload"
    );
    assert!(
        mem.verify_layer("summary-2004", "event-b"),
        "layer proof survives reload"
    );

    // Zoom still surfaces the summary wing and its leaves.
    let q = ZoomQuery {
        time: Some((NaiveDate::from_ymd_opt(2004, 1, 1).unwrap(), 365)),
        topics: Some(vec!["geopolitics".to_string()]),
        evidence: Some(Evidence::Documented),
        tier: None,
        min_trust: None,
        trust_domain: None,
    };
    let mut got = mem.zoom(&q);
    got.sort();
    // The zoom filters on Documented evidence, so the summary (Evidence::Summary)
    // is correctly excluded — it's reached via verify_layer, not this zoom.
    assert_eq!(got, vec!["event-a".to_string(), "event-b".to_string()]);

    // Tier axis still works on the summary (Standard tier).
    let q_tier = ZoomQuery {
        time: None,
        topics: None,
        evidence: None,
        tier: Some(MemoryTier::Standard),
        min_trust: None,
        trust_domain: None,
    };
    assert!(mem.zoom(&q_tier).contains(&"summary-2004".to_string()));

    let _ = std::fs::remove_dir_all(&dir);
}
