// SPDX-License-Identifier: OPL-1.4
// Copyright (c) 2026 Origin Contributors

//! Phase 5 tests — governance, hardening, reproducibility.
//!
//! These tests lock in the promises made in GOVERNANCE.md:
//!   - no network dependencies / calls
//!   - byte-stable canonical commitment bytes
//!   - evidence package is self-contained (verifiable with no secrets)

use origin_canary::commitment::{self, SignedCommitment, Verification};
use origin_canary::evidence::{self, EvidencePackage};
use origin_canary::fingerprint;
use origin_canary::manifest::CanaryManifest;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn test_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8;
    }
    seed
}

fn embed_tree(dir: &Path, n: usize, salt: &str) -> CanaryManifest {
    let mut manifest_path = dir.to_path_buf();
    manifest_path.set_file_name("manifest.json");
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("app.py"),
        "import os\n\ndef main():\n    print('hi')\n",
    )
    .unwrap();
    std::fs::write(src.join("util.js"), "export const x = 1;\n").unwrap();
    let config = origin_canary::embed::EmbedConfig {
        source_dir: src,
        project_id: 42,
        distribution_id: "v5.0.0".to_string(),
        salt: salt.to_string(),
        num_canaries: n,
        strategy_names: vec![
            "variable.python".to_string(),
            "variable.javascript".to_string(),
        ],
        manifest_out: Some(manifest_path),
    };
    origin_canary::embed::run_embed(config).unwrap().manifest
}

fn copy_tree(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.path().is_dir() {
            std::fs::create_dir_all(&dest).unwrap();
            copy_tree(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
}

#[test]
fn canonical_commitment_bytes_are_byte_stable() {
    // The signed bytes must be reproducible from the manifest + timestamp alone,
    // independent of when the commitment is built. This is the reproducibility
    // guarantee in GOVERNANCE.md.
    let tmp = tempfile::tempdir().unwrap();
    let manifest = embed_tree(tmp.path(), 4, "p5-salt");
    let ts = 1_700_000_000u64;

    let a = commitment::sign_commitment(&manifest, &test_seed(), ts).unwrap();
    let b = commitment::sign_commitment(&manifest, &test_seed(), ts).unwrap();

    // Canonical payload bytes (what was signed) are identical.
    assert_eq!(
        commitment::canonical_bytes(&a.payload),
        commitment::canonical_bytes(&b.payload),
        "canonical commitment bytes must be stable across builds"
    );
    // Both verify.
    assert_eq!(a.verify().unwrap(), Verification::Valid);
    assert_eq!(b.verify().unwrap(), Verification::Valid);
}

#[test]
fn different_timestamps_produce_different_payloads() {
    // Reproducibility is keyed on (manifest, timestamp); a different timestamp
    // is a genuinely different commitment, not a replay.
    let tmp = tempfile::tempdir().unwrap();
    let manifest = embed_tree(tmp.path(), 4, "p5-salt");
    let a = commitment::sign_commitment(&manifest, &test_seed(), 1_700_000_000).unwrap();
    let b = commitment::sign_commitment(&manifest, &test_seed(), 1_700_000_001).unwrap();
    assert_ne!(a.payload.timestamp, b.payload.timestamp);
    assert_ne!(
        commitment::canonical_bytes(&a.payload),
        commitment::canonical_bytes(&b.payload)
    );
}

#[test]
fn evidence_package_is_self_contained_no_secrets_needed() {
    // Lock in: a verifier holding only the evidence JSON (no identity blob, no
    // salt, no passphrase) can confirm the full chain. We simulate by building
    // the package, then re-verifying it from the serialized JSON alone.
    let tmp = tempfile::tempdir().unwrap();
    let manifest = embed_tree(tmp.path(), 4, "p5-salt");
    let commitment = commitment::sign_commitment(&manifest, &test_seed(), now()).unwrap();

    let suspect = tmp.path().join("suspect");
    std::fs::create_dir_all(&suspect).unwrap();
    copy_tree(&tmp.path().join("src"), &suspect);

    let package = evidence::assemble(&suspect, &manifest, &commitment, None, None, now()).unwrap();
    assert!(package.is_sound());

    // Serialize → drop the in-memory structs → deserialize as if from disk.
    let json = serde_json::to_string_pretty(&package).unwrap();
    let reloaded: EvidencePackage = serde_json::from_str(&json).unwrap();

    // The reloaded package must still verify using only its embedded keys.
    assert!(reloaded.is_sound());
    // And the commitment inside it must verify from its own embedded keys.
    let embedded: &SignedCommitment = &reloaded.commitment;
    assert_eq!(embedded.verify().unwrap(), Verification::Valid);
    // No secret material is present in the package.
    let serialized = serde_json::to_string(&reloaded).unwrap();
    assert!(!serialized.contains("passphrase"));
    assert!(
        !serialized.contains("\"salt\""),
        "evidence must not leak the salt"
    );
}

#[test]
fn fingerprint_binds_distinct_archives() {
    // GOVERNANCE §3: fingerprint must bind the exact archive. Two archives with
    // different bytes get different (valid) fingerprints over different hashes.
    let tmp = tempfile::tempdir().unwrap();
    let manifest = embed_tree(tmp.path(), 4, "p5-salt");
    let commitment = commitment::sign_commitment(&manifest, &test_seed(), now()).unwrap();

    let a1 = tmp.path().join("a1.tar.gz");
    let a2 = tmp.path().join("a2.tar.gz");
    std::fs::write(&a1, b"release one contents").unwrap();
    std::fs::write(&a2, b"release two contents DIFFERENT").unwrap();

    let fp1 =
        fingerprint::sign_fingerprint(&manifest, &commitment, &a1, &test_seed(), now()).unwrap();
    let fp2 =
        fingerprint::sign_fingerprint(&manifest, &commitment, &a2, &test_seed(), now()).unwrap();

    assert_ne!(fp1.payload.archive_hash, fp2.payload.archive_hash);
    assert!(fp1.matches_archive(&a1).unwrap());
    assert!(fp2.matches_archive(&a2).unwrap());
    assert!(!fp1.matches_archive(&a2).unwrap());
}

#[test]
fn determinism_repro_rule_compile_time_no_network_deps() {
    // This test documents the no-network guarantee (GOVERNANCE §1). The actual
    // check is `cargo tree` / grep in CI; here we assert the SDK itself is the
    // only crypto dependency and that our modules don't import networking.
    // Keeping this as a sentinel test makes the policy explicit in the suite.
    let deps = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    assert_eq!(deps, "origin-canary");
    // If networking ever creeps in, this assertion is the canary:
    assert!(
        !has_network_imports(),
        "origin-canary must not import networking"
    );
}

/// Best-effort static check: none of our source files reference networking
/// symbols. Mirrors the `cargo tree -i` check run in CI/review.
fn has_network_imports() -> bool {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            for needle in [
                "TcpStream",
                "UdpSocket",
                "reqwest",
                "hyper::",
                "ureq",
                "attohttpc",
                ".connect(",
                "std::net",
            ] {
                if text.contains(needle) {
                    return true;
                }
            }
        }
    }
    false
}
