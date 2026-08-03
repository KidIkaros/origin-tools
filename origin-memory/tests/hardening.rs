// SPDX-License-Identifier: Apache-2.0

//! P7: hardening & perf — verify_layer scales and the layer-root cache holds.

use chrono::NaiveDate;
use origin_memory::{Memory, MemoryNode};

const SEED: [u8; 32] = [42u8; 32];

#[test]
fn verify_layer_scales_to_many_leaves() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p7-scale-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");

    // 50 leaves across a wing.
    let mut leaves = Vec::new();
    for i in 0..50 {
        let id = format!("leaf-{:03}", i);
        let day = 1 + (i % 28);
        let node = MemoryNode::from_markdown(
            &id,
            &format!(
                "---\ntitle: L{}\ntime: 2004-06-{:02}\ntopic: [bulk]\nevidence: documented\n---\nLeaf {}.\n",
                i, day, i
            ),
        )
        .unwrap();
        mem.add(node.clone()).expect("add");
        leaves.push(node);
    }

    mem.summarize(
        "sum-bulk",
        "bulk",
        NaiveDate::from_ymd_opt(2004, 6, 15).unwrap(),
        &leaves,
    )
    .expect("summarize");

    // Every leaf proves in the layer.
    let start = std::time::Instant::now();
    for i in 0..50 {
        let id = format!("leaf-{:03}", i);
        assert!(mem.verify_layer("sum-bulk", &id), "leaf {} proves", i);
    }
    let elapsed = start.elapsed();
    // 50 proofs (each rebuilds the 50-leaf MMR in debug) — generous bound for
    // debug builds; release is ~10x faster.
    assert!(
        elapsed.as_millis() < 500,
        "verify_layer too slow: {}ms",
        elapsed.as_millis()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn layer_root_cache_persists_across_reload() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p7-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let node = MemoryNode::from_markdown(
        "a",
        "---\ntitle: A\ntime: 2004-06-01\ntopic: [x]\nevidence: documented\n---\nA.\n",
    )
    .unwrap();
    {
        let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");
        mem.add(node.clone()).expect("add");
        mem.summarize(
            "s",
            "x",
            NaiveDate::from_ymd_opt(2004, 6, 1).unwrap(),
            &[node],
        )
        .expect("summarize");
        assert!(mem.verify_layer("s", "a"), "pre-reload proof");
    }

    // After reload the cache is cold, but the stored root loads and verifies.
    let mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("reopen");
    assert!(
        mem.verify_layer("s", "a"),
        "post-reload proof uses stored root"
    );
    // Second call hits the cache (no hex decode).
    assert!(mem.verify_layer("s", "a"), "cached proof after first call");

    let _ = std::fs::remove_dir_all(&dir);
}
