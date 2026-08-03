// SPDX-License-Identifier: Apache-2.0

//! P6: query surface + visualization — tree and star-chart render views.

use chrono::NaiveDate;
use origin_memory::{Memory, MemoryNode};

const SEED: [u8; 32] = [42u8; 32];

#[test]
fn render_tree_shows_hierarchy() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p6-tree-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");

    let leaves_a = vec![
        MemoryNode::from_markdown("leaf-a1", "---\ntitle: Alpha one\ntime: 2004-06-01\ntopic: [alpha]\nevidence: documented\n---\nOne.\n").unwrap(),
        MemoryNode::from_markdown("leaf-a2", "---\ntitle: Alpha two\ntime: 2004-06-02\ntopic: [alpha]\nevidence: documented\n---\nTwo.\n").unwrap(),
    ];
    for n in &leaves_a {
        mem.add(n.clone()).expect("add");
    }
    mem.summarize(
        "sum-alpha",
        "alpha",
        NaiveDate::from_ymd_opt(2004, 6, 1).unwrap(),
        &leaves_a,
    )
    .expect("summarize");

    let tree = mem.render_tree("sum-alpha");
    assert!(tree.contains("Alpha one"), "leaf title shown");
    assert!(tree.contains("Doc"), "evidence badge shown");
    assert!(tree.contains("alpha"), "topic shown");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn render_star_chart_groups_by_wing() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p6-star-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");

    mem.add(MemoryNode::from_markdown("n1", "---\ntitle: One\ntime: 2004-06-01\ntopic: [geopolitics]\nevidence: documented\n---\nOne.\n").unwrap()).expect("add");
    mem.add(
        MemoryNode::from_markdown(
            "n2",
            "---\ntitle: Two\ntime: 2004-06-15\ntopic: [tech]\nevidence: assertion\n---\nTwo.\n",
        )
        .unwrap(),
    )
    .expect("add");

    let chart = mem.render_star_chart();
    assert!(chart.contains("Star Chart"), "title shown");
    assert!(chart.contains("geopolitics"), "wing shown");
    assert!(chart.contains("tech"), "second wing shown");
    assert!(chart.contains("Doc"), "evidence badge in chart");
    assert!(chart.contains("Asrt"), "assertion badge in chart");
    assert!(chart.contains("2004-06-01"), "date shown");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn render_excludes_revoked() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p6-rev-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");

    mem.add(
        MemoryNode::from_markdown(
            "keep",
            "---\ntitle: Keep\ntime: 2004-06-01\ntopic: [x]\nevidence: documented\n---\nKeep.\n",
        )
        .unwrap(),
    )
    .expect("add");
    mem.add(
        MemoryNode::from_markdown(
            "drop",
            "---\ntitle: Drop\ntime: 2004-06-02\ntopic: [x]\nevidence: documented\n---\nDrop.\n",
        )
        .unwrap(),
    )
    .expect("add");
    mem.revoke("drop", "superseded").expect("revoke");

    let chart = mem.render_star_chart();
    assert!(chart.contains("keep"), "kept node in chart");
    assert!(!chart.contains("drop"), "revoked node excluded from chart");

    let _ = std::fs::remove_dir_all(&dir);
}
