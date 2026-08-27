// SPDX-License-Identifier: Apache-2.0

//! Cross-tool integration tests (design §10): origin-vcs data verified through
//! the suite's other tools.
//!
//! 1. origin-provenance: a `Manifest` scan of the working tree stamps each
//!    file with SHA3-256; every blob origin-vcs committed must decrypt to
//!    bytes with that exact hash (the encrypted store round-trips the exact
//!    content the suite independently fingerprints).
//! 2. origin-proof: origin-vcs commit ids append cleanly into origin-proof's
//!    BLAKE3 MMR and every membership proof verifies against the root — the
//!    suite's receipt machinery accepts vcs history.

use std::path::Path;

use origin_vcs::cli::{Cli, Commands};
use origin_vcs::commands::dispatch;
use origin_vcs::store::Store;

const SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

macro_rules! ok {
    ($cli:expr) => {
        dispatch(Cli { command: $cli }).unwrap()
    };
}

static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Fixture {
    _guard: std::sync::MutexGuard<'static, ()>,
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let guard = CWD_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::TempDir::new().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        Fixture { _guard: guard, dir }
    }
    fn store(&self) -> String {
        self.dir.path().join(".origin-vcs").display().to_string()
    }
}

fn init(fix: &Fixture) {
    ok!(Commands::Init(origin_vcs::cli::InitArgs {
        store: Some(fix.store()),
        branch: "main".into(),
        force: false,
        encrypt: "identity".into(),
        tier: "nano".into(),
        seed: Some(SEED.to_string()),
        identity: false,
        passphrase_file: None,
    }));
}

fn add(fix: &Fixture, paths: Vec<&str>) {
    ok!(Commands::Add(origin_vcs::cli::AddArgs {
        paths: paths.into_iter().map(|s| s.to_string()).collect(),
        store: Some(fix.store()),
        identity: false,
        seed: Some(SEED.to_string()),
        passphrase_file: None,
        stream: false,
        chunk_size: 65536,
    }));
}

fn commit(fix: &Fixture, msg: &str) {
    ok!(Commands::Commit(origin_vcs::cli::CommitArgs {
        message: msg.to_string(),
        author: None,
        date: None,
        seed: Some(SEED.to_string()),
        identity: false,
        passphrase_file: None,
        store: Some(fix.store()),
        all: false,
        amend: false,
    }));
}

fn write(root: &Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, data).unwrap();
}

fn open_store(fix: &Fixture) -> Store {
    let ks = origin_vcs::crypto::resolve_keysource(false, Some(SEED), None).unwrap();
    let mut s = Store::open(Path::new(&fix.store()), ks.storage_key().unwrap()).unwrap();
    s.load_meta().unwrap();
    s
}

/// Every blob in the committed tree must hash to the exact SHA3-256 stamp
/// origin-provenance independently computes for the same file on disk.
#[test]
fn provenance_manifest_cross_checks_committed_blobs() {
    let fix = Fixture::new();
    init(&fix);
    write(fix.dir.path(), "a.txt", b"alpha content");
    write(fix.dir.path(), "sub/b.txt", b"beta content");
    add(&fix, vec!["a.txt", "sub"]);
    commit(&fix, "cross-tool commit");

    // Independent fingerprint of the working tree via origin-provenance.
    let manifest = origin_provenance::manifest::Manifest::scan(fix.dir.path()).unwrap();
    assert!(manifest.entries.contains_key("a.txt"));
    assert!(manifest.entries.contains_key("sub/b.txt"));

    // origin-vcs store: every committed blob must match the provenance stamp.
    let store = open_store(&fix);
    let head = store.meta().branches["main"];
    let commit_rec = store.read_commit(&head).unwrap();
    let tree = store.read_tree(&commit_rec.tree).unwrap();
    assert_eq!(tree.entries.len(), 2);

    for (rel, entry) in &tree.entries {
        let stamp = manifest
            .entries
            .get(rel)
            .unwrap_or_else(|| panic!("provenance missing {rel}"));
        let blob = store.read_blob(&entry.id).unwrap();
        let hash = hex::encode(origin_crypto_sdk::sha3_256(&blob.data));
        assert_eq!(
            stamp.content_hash, hash,
            "committed blob for {rel} does not match provenance stamp"
        );
        assert_eq!(stamp.size as usize, blob.data.len());
    }

    // Round-trip through the working tree: provenance verify stays clean.
    let results = manifest.verify(fix.dir.path()).unwrap();
    let (ok, modified, missing, added) = origin_provenance::manifest::Manifest::summarize(&results);
    assert_eq!(ok, 2);
    assert_eq!(modified, 0);
    assert_eq!(missing, 0);
    assert_eq!(added, 0);
}

/// origin-vcs commit ids append into origin-proof's MMR; every membership
/// proof verifies against the root.
#[test]
fn origin_proof_mmr_accepts_vcs_commit_ids() {
    let fix = Fixture::new();
    init(&fix);
    write(fix.dir.path(), "x.txt", b"one");
    add(&fix, vec!["x.txt"]);
    commit(&fix, "c1");
    write(fix.dir.path(), "x.txt", b"two");
    add(&fix, vec!["x.txt"]);
    commit(&fix, "c2");
    write(fix.dir.path(), "y.txt", b"three");
    add(&fix, vec!["y.txt"]);
    commit(&fix, "c3");

    let store = open_store(&fix);
    let log = store.commit_log().unwrap();
    assert_eq!(log.len(), 3);

    // Append each vcs commit id into origin-proof's MMR (leaf = blake3(id)).
    let mut mmr = origin_proof::mmr::MmrState::new();
    for id in &log {
        mmr.append_hash(*origin_crypto_sdk::blake3::hash(id).as_bytes());
    }
    let root = mmr.root();
    assert_ne!(root, [0u8; 32]);

    // Every leaf's proof verifies against the root.
    for i in 0..log.len() {
        let proof = mmr.prove(i as u64).unwrap();
        assert!(
            mmr.verify_proof(&proof, &root),
            "origin-proof membership failed for commit {i}"
        );
    }

    // origin-vcs's own MMR root still replays from the explicit log.
    let own_root = store.recompute_mmr_root_from_log().unwrap();
    assert_ne!(own_root, [0u8; 32]);
}
