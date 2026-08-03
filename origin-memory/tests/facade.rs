// SPDX-License-Identifier: Apache-2.0

//! Facade test: `Memory` unifies hot index + cold store behind one object.

use chrono::NaiveDate;
use origin_crypto_sdk::tier::MemoryTier;
use origin_memory::memory::Memory;
use origin_memory::node::MemoryNode;

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
fn memory_facade_unifies_hot_and_cold() {
    let dir = std::env::temp_dir().join(format!("origin-memory-facade-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    // Session 1: open facade, add via the unified API.
    let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");
    let n1 = MemoryNode::from_markdown("event-2004", MD_2004).unwrap();
    let n2 = MemoryNode::from_markdown("event-2024", MD_2024).unwrap();
    mem.add(n1).expect("add 1");
    mem.add(n2).expect("add 2");

    // Hot zoom works immediately (no reload needed).
    let hot = mem.zoom_time(NaiveDate::from_ymd_opt(2004, 1, 1).unwrap(), 365);
    assert_eq!(hot, vec!["event-2004".to_string()]);

    // Trust-filtered zoom: only documented facts in window.
    let doc = mem.zoom_documented(NaiveDate::from_ymd_opt(2004, 1, 1).unwrap(), 365);
    assert_eq!(doc, vec!["event-2004".to_string()]);

    // Tier axis: Sovereign (documented) node present.
    let sovereign = mem.by_tier(MemoryTier::Sovereign);
    assert!(sovereign.contains(&"event-2004".to_string()));

    // Session 2: reopen — hot index hydrated from cold store, verify passes.
    let mem2 = Memory::open(&dir, &SEED, "origin-memory-test").expect("reopen");
    assert_eq!(mem2.len(), 2);
    assert!(mem2.verify("event-2004"));
    assert!(mem2.verify_all().all_sound(), "no tampering after reload");

    // Zoom still works after reload, with no hot-cache seeding by caller.
    let reloaded = mem2.zoom_time(NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(), 365);
    assert_eq!(reloaded, vec!["event-2024".to_string()]);

    let _ = std::fs::remove_dir_all(&dir);
}
