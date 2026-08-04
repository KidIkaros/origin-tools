// SPDX-License-Identifier: Apache-2.0

//! P2: semantic zoom scoring — ranked results, not just filtered.

use chrono::NaiveDate;
use origin_memory::{Memory, MemoryNode, ZoomQuery};

const SEED: [u8; 32] = [42u8; 32];

#[test]
fn scored_zoom_ranks_by_relevance() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");

    // Three documented nodes at different temporal distances from center.
    // doc-near is 1 day from center, doc-mid is 10 days, doc-far is 30 days.
    let _ = mem.add(MemoryNode::from_markdown(
        "doc-near",
        "---\ntitle: Near\ntime: 2004-06-02\ntopic: [alpha]\nevidence: documented\n---\nNear event.\n",
    ).unwrap());
    let _ = mem.add(MemoryNode::from_markdown(
        "doc-mid",
        "---\ntitle: Mid\ntime: 2004-06-11\ntopic: [alpha]\nevidence: documented\n---\nMid event.\n",
    ).unwrap());
    let _ = mem.add(MemoryNode::from_markdown(
        "doc-far",
        "---\ntitle: Far\ntime: 2004-07-01\ntopic: [alpha]\nevidence: documented\n---\nFar event.\n",
    ).unwrap());

    // An assertion node — same topic/time as doc-near, but lower evidence weight.
    let _ = mem.add(MemoryNode::from_markdown(
        "assertion-near",
        "---\ntitle: Assert Near\ntime: 2004-06-02\ntopic: [alpha]\nevidence: assertion\n---\nNear assertion.\n",
    ).unwrap());

    let q = ZoomQuery {
        time: Some((NaiveDate::from_ymd_opt(2004, 6, 1).unwrap(), 60)),
        topics: Some(vec!["alpha".into()]),
        evidence: None,
        tier: None,
        min_trust: None,
        trust_domain: None,
    };

    let scored = mem.zoom_scored(&q);
    assert_eq!(scored.len(), 4, "all four nodes in window");

    // (1) Results are sorted descending by score.
    for w in scored.windows(2) {
        assert!(
            w[0].score >= w[1].score,
            "sorted descending: {} vs {}",
            w[0].score,
            w[1].score
        );
    }

    // (2) doc-near outranks doc-mid outranks doc-far (temporal proximity).
    let near = scored.iter().find(|r| r.id == "doc-near").unwrap();
    let mid = scored.iter().find(|r| r.id == "doc-mid").unwrap();
    let far = scored.iter().find(|r| r.id == "doc-far").unwrap();
    assert!(near.score > mid.score, "near > mid");
    assert!(mid.score > far.score, "mid > far");

    // (3) doc-near outranks assertion-near despite same time — evidence weight.
    let assertion = scored.iter().find(|r| r.id == "assertion-near").unwrap();
    assert!(
        near.score > assertion.score,
        "documented > assertion at same time"
    );

    // (4) Score breakdown is populated for specified axes.
    assert!(near.temporal.is_some(), "temporal is scored");
    assert!(near.topic_overlap.is_some(), "topic overlap is scored");
    assert!(near.evidence_weight.is_some(), "evidence is scored");

    // (5) The top result is doc-near (closest + highest evidence).
    assert_eq!(scored[0].id, "doc-near", "top-ranked is doc-near");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scored_zoom_excludes_revoked() {
    let dir = std::env::temp_dir().join(format!("origin-memory-p2-revoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut mem = Memory::open(&dir, &SEED, "origin-memory-test").expect("open");

    let _ = mem.add(
        MemoryNode::from_markdown(
            "doc-a",
            "---\ntitle: A\ntime: 2004-06-01\ntopic: [x]\nevidence: documented\n---\nA.\n",
        )
        .unwrap(),
    );
    let _ = mem.add(
        MemoryNode::from_markdown(
            "doc-b",
            "---\ntitle: B\ntime: 2004-06-02\ntopic: [x]\nevidence: documented\n---\nB.\n",
        )
        .unwrap(),
    );

    mem.revoke("doc-a", "superseded").expect("revoke");

    let q = ZoomQuery {
        time: Some((NaiveDate::from_ymd_opt(2004, 6, 1).unwrap(), 30)),
        topics: Some(vec!["x".into()]),
        evidence: None,
        tier: None,
        min_trust: None,
        trust_domain: None,
    };
    let scored = mem.zoom_scored(&q);
    assert_eq!(scored.len(), 1, "revoked node excluded from scored results");
    assert_eq!(scored[0].id, "doc-b");

    let _ = std::fs::remove_dir_all(&dir);
}
