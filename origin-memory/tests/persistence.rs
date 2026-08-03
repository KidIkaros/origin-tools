// SPDX-License-Identifier: Apache-2.0

//! Persistence test: prove memory survives restart + temporal zoom works on disk.

use chrono::NaiveDate;
use origin_memory::index::MemoryIndex;
use origin_memory::node::MemoryNode;
use origin_memory::persist::MemoryStore;
use origin_memory::sign::derive_bundle;

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
fn memory_survives_restart() {
    let dir = std::env::temp_dir().join(format!("origin-memory-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    // Session 1: write two nodes to disk.
    let bundle = derive_bundle(&SEED, "origin-memory-test");
    let store = MemoryStore::open(&dir).expect("open store");
    let n1 = MemoryNode::from_markdown("event-2004", MD_2004).unwrap();
    let n2 = MemoryNode::from_markdown("event-2024", MD_2024).unwrap();
    let sig1 = origin_memory::sign::sign_node(&n1, &bundle);
    let sig2 = origin_memory::sign::sign_node(&n2, &bundle);
    store.save(&n1, &sig1).expect("save 1");
    store.save(&n2, &sig2).expect("save 2");

    // Both markdown files exist on disk (canonical cold store).
    assert!(dir.join("event-2004.md").exists());
    assert!(dir.join("event-2024.md").exists());

    // Session 2: reopen — memory is intact without re-parsing files.
    let store2 = MemoryStore::open(&dir).expect("reopen store");
    let loaded = store2.load_all().expect("load_all");
    assert_eq!(loaded.len(), 2, "both nodes reloaded from index");

    // Temporal zoom on disk: +/– 1 year around 2004 hits only event-2004.
    let zoom = store2
        .zoom_time(NaiveDate::from_ymd_opt(2004, 1, 1).unwrap(), 365)
        .expect("zoom");
    assert_eq!(zoom, vec!["event-2004".to_string()]);

    // Zoom around 2024 hits only event-2024.
    let zoom2 = store2
        .zoom_time(NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(), 365)
        .expect("zoom2");
    assert_eq!(zoom2, vec!["event-2024".to_string()]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn coarse_summary_node_persists() {
    let dir = std::env::temp_dir().join(format!("origin-memory-summary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let bundle = derive_bundle(&SEED, "origin-memory-test");
    let store = MemoryStore::open(&dir).expect("open");
    let n1 = MemoryNode::from_markdown("event-2004", MD_2004).unwrap();
    let sig1 = origin_memory::sign::sign_node(&n1, &bundle);
    store.save(&n1, &sig1).expect("save");

    // Build a coarse summary node pointing at the leaf — the star-chart zoom.
    store
        .save_summary(
            "summary-geopolitics",
            "geopolitics",
            NaiveDate::from_ymd_opt(2004, 1, 1).unwrap(),
            &[n1],
            &bundle,
        )
        .expect("save summary");

    let loaded = store.load_all().expect("load");
    assert_eq!(loaded.len(), 2);
    // The summary node is retrievable and links to its leaf.
    let summary = loaded
        .iter()
        .find(|(n, _)| n.id == "summary-geopolitics")
        .expect("summary present");
    assert!(summary.0.links.contains("event-2004"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tier_maps_from_evidence_and_round_trips() {
    // Evidence axis → shared Origin MemoryTier (DRY with origin-secrets/origin-pass).
    assert_eq!(
        origin_memory::node::Evidence::Documented.tier(),
        origin_crypto_sdk::tier::MemoryTier::Sovereign
    );
    assert_eq!(
        origin_memory::node::Evidence::Assertion.tier(),
        origin_crypto_sdk::tier::MemoryTier::Standard
    );
    assert_eq!(
        origin_memory::node::Evidence::Fiction.tier(),
        origin_crypto_sdk::tier::MemoryTier::Nano
    );

    // The tier is written to the canonical markdown and survives a round-trip.
    let n = MemoryNode::from_markdown("ev-1", MD_2004).unwrap();
    let md = n.to_markdown();
    assert!(md.contains(&format!("tier: {}", n.tier.label())));

    // And the provenance Stamp (origin-provenance) fingerprints the content.
    let stamp = n.stamp();
    assert!(
        stamp.verify_content(md.as_bytes()),
        "stamp matches canonical bytes"
    );

    // Store + reload: tier persists through SQLite.
    let dir = std::env::temp_dir().join(format!("origin-memory-tier-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let bundle = derive_bundle(&SEED, "origin-memory-test");
    let store = MemoryStore::open(&dir).expect("open");
    let sig = origin_memory::sign::sign_node(&n, &bundle);
    store.save(&n, &sig).expect("save");
    let loaded = store.load_all().expect("load");
    assert_eq!(loaded[0].0.tier, n.tier);
    let _ = std::fs::remove_dir_all(&dir);
}

#[allow(dead_code)]
fn _unused_index_keeps_dep() {
    let _ = MemoryIndex::new(&SEED, "x");
}
