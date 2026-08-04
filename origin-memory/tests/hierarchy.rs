// SPDX-License-Identifier: Apache-2.0

//! P1: recursive coarse hierarchy — summaries of summaries, each level provable.

use chrono::NaiveDate;
use origin_memory::{Memory, MemoryNode};

const SEED: [u8; 32] = [42u8; 32];

fn doc(id: &str, title: &str, day: u32, topic: &str) -> MemoryNode {
    let md = format!(
        "---\ntitle: {}\ntime: 2004-06-{:02}\ntopic: [{}]\nevidence: documented\n---\n{}.\n",
        title, day, topic, title
    );
    MemoryNode::from_markdown(id, &md).unwrap()
}

#[test]
fn recursive_hierarchy_is_provable_at_every_level() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");

    // Level 0: 4 leaf nodes across two wings.
    let leaves_a = vec![
        doc("leaf-a1", "Alpha one", 1, "alpha"),
        doc("leaf-a2", "Alpha two", 2, "alpha"),
    ];
    let leaves_b = vec![
        doc("leaf-b1", "Bravo one", 3, "bravo"),
        doc("leaf-b2", "Bravo two", 4, "bravo"),
    ];
    for n in leaves_a.iter().chain(leaves_b.iter()) {
        mem.add(n.clone()).expect("add leaf");
    }

    // Level 1: two wing summaries.
    mem.summarize(
        "sum-alpha",
        "alpha",
        NaiveDate::from_ymd_opt(2004, 6, 1).unwrap(),
        &leaves_a,
    )
    .expect("summarize alpha");
    mem.summarize(
        "sum-bravo",
        "bravo",
        NaiveDate::from_ymd_opt(2004, 6, 3).unwrap(),
        &leaves_b,
    )
    .expect("summarize bravo");

    // Level 2: a root summary over the two wing summaries.
    let wing_summaries = vec![
        mem.node("sum-alpha").unwrap().clone(),
        mem.node("sum-bravo").unwrap().clone(),
    ];
    mem.summarize(
        "sum-root",
        "all",
        NaiveDate::from_ymd_opt(2004, 6, 2).unwrap(),
        &wing_summaries,
    )
    .expect("summarize root");

    // (1) Depth is 3: root → wing summaries → leaves.
    assert_eq!(mem.depth("sum-root"), 3, "three-level hierarchy");
    assert_eq!(mem.depth("sum-alpha"), 2, "wing summary is depth 2");
    assert_eq!(mem.depth("leaf-a1"), 1, "leaf is depth 1");

    // (2) Levels walk: root has 2 children (wing summaries), each wing has 2 leaves.
    let levels = mem.levels("sum-root");
    assert_eq!(levels.len(), 3, "three levels");
    assert!(levels[0].contains(&"sum-root".to_string()));
    assert!(levels[1].contains(&"sum-alpha".to_string()));
    assert!(levels[1].contains(&"sum-bravo".to_string()));
    assert!(levels[2].contains(&"leaf-a1".to_string()));

    // (3) Membership is provable at level 1 (leaf → wing summary).
    assert!(
        mem.verify_layer("sum-alpha", "leaf-a1"),
        "leaf proves in wing summary"
    );
    assert!(
        mem.verify_layer("sum-bravo", "leaf-b2"),
        "leaf proves in wing summary"
    );

    // (4) Membership is provable at level 2 (wing summary → root summary).
    assert!(
        mem.verify_layer("sum-root", "sum-alpha"),
        "wing summary proves in root"
    );
    assert!(
        mem.verify_layer("sum-root", "sum-bravo"),
        "wing summary proves in root"
    );

    // (5) Cross-level proof fails: a leaf is NOT a direct member of the root
    // summary (it's a member of a wing, which is a member of the root).
    assert!(
        !mem.verify_layer("sum-root", "leaf-a1"),
        "leaf is not direct child of root"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn recursive_hierarchy_survives_reload() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p1-reload-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    // Build the same 3-level hierarchy.
    let leaves_a = vec![
        doc("leaf-a1", "Alpha one", 1, "alpha"),
        doc("leaf-a2", "Alpha two", 2, "alpha"),
    ];
    let leaves_b = vec![
        doc("leaf-b1", "Bravo one", 3, "bravo"),
        doc("leaf-b2", "Bravo two", 4, "bravo"),
    ];
    {
        let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");
        for n in leaves_a.iter().chain(leaves_b.iter()) {
            mem.add(n.clone()).expect("add leaf");
        }
        mem.summarize(
            "sum-alpha",
            "alpha",
            NaiveDate::from_ymd_opt(2004, 6, 1).unwrap(),
            &leaves_a,
        )
        .expect("summarize alpha");
        mem.summarize(
            "sum-bravo",
            "bravo",
            NaiveDate::from_ymd_opt(2004, 6, 3).unwrap(),
            &leaves_b,
        )
        .expect("summarize bravo");
        let wing_summaries = vec![
            mem.node("sum-alpha").unwrap().clone(),
            mem.node("sum-bravo").unwrap().clone(),
        ];
        mem.summarize(
            "sum-root",
            "all",
            NaiveDate::from_ymd_opt(2004, 6, 2).unwrap(),
            &wing_summaries,
        )
        .expect("summarize root");
    }

    // Reload and verify all proofs still hold.
    let mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("reopen");
    assert_eq!(mem.depth("sum-root"), 3, "depth preserved after reload");
    assert!(
        mem.verify_layer("sum-alpha", "leaf-a1"),
        "L1 proof holds after reload"
    );
    assert!(
        mem.verify_layer("sum-root", "sum-alpha"),
        "L2 proof holds after reload"
    );
    assert!(mem.verify_all().all_sound(), "no tampering after reload");

    let _ = std::fs::remove_dir_all(&dir);
}
