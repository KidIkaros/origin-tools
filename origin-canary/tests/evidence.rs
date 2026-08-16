// SPDX-License-Identifier: OPL-1.4
// Copyright (c) 2026 Origin Contributors

//! Phase 4 tests — evidence packages + CI gate.

use origin_canary::commitment::{self, Verification};
use origin_canary::evidence::{self, EvidencePackage};
use origin_canary::fingerprint;
use origin_canary::manifest::CanaryManifest;
use std::path::{Path, PathBuf};
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

/// Embed canaries into a fresh source tree → manifest.
fn embed_tree(dir: &Path, n: usize, salt: &str) -> CanaryManifest {
    let mut manifest_path = dir.to_path_buf();
    manifest_path.set_file_name("manifest.json");
    // NOTE: run_embed writes into the tree itself; use distinct dirs.
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("app.py"),
        "import os\n\ndef main():\n    print('hi')\n",
    )
    .unwrap();
    std::fs::write(src.join("util.js"), "export const x = 1;\n").unwrap();

    let config = origin_canary::embed::EmbedConfig {
        source_dir: src.clone(),
        project_id: 42,
        distribution_id: "v4.0.0".to_string(),
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

/// Copy a tree (preserving embedded canaries) for the "suspect" copy.
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

fn build_chain(dir: &Path, salt: &str) -> (CanaryManifest, commitment::SignedCommitment) {
    let manifest = embed_tree(dir, 4, salt);
    let commitment = commitment::sign_commitment(&manifest, &test_seed(), now()).unwrap();
    (manifest, commitment)
}

#[test]
fn evidence_assembles_and_is_sound() {
    let tmp = tempfile::tempdir().unwrap();
    let (manifest, commitment) = build_chain(tmp.path(), "e2e-salt");
    // Suspect copy = the tree itself (full copy scenario).
    let suspect = tmp.path().join("suspect");
    std::fs::create_dir_all(&suspect).unwrap();
    copy_tree(&tmp.path().join("src"), &suspect);

    let package = evidence::assemble(&suspect, &manifest, &commitment, None, None, now()).unwrap();
    assert!(!package.matches.is_empty());
    assert!(package.is_sound());
    // Every check passes.
    assert!(package.all_checks().iter().all(|(_, ok)| *ok));
}

#[test]
fn evidence_survives_json_roundtrip_and_stays_sound() {
    let tmp = tempfile::tempdir().unwrap();
    let (manifest, commitment) = build_chain(tmp.path(), "e2e-salt");
    let suspect = tmp.path().join("suspect");
    std::fs::create_dir_all(&suspect).unwrap();
    copy_tree(&tmp.path().join("src"), &suspect);

    let package = evidence::assemble(&suspect, &manifest, &commitment, None, None, now()).unwrap();
    let json = serde_json::to_string_pretty(&package).unwrap();
    let reloaded: EvidencePackage = serde_json::from_str(&json).unwrap();
    assert!(reloaded.is_sound());
    assert_eq!(reloaded.matches.len(), package.matches.len());
    assert_eq!(reloaded.merkle_root, package.merkle_root);
}

#[test]
fn partial_copy_still_proves_derivation() {
    let tmp = tempfile::tempdir().unwrap();
    let (manifest, commitment) = build_chain(tmp.path(), "e2e-salt");
    // Partial copy: only a subdirectory containing at least one canary.
    let suspect = tmp.path().join("stolen");
    std::fs::create_dir_all(&suspect).unwrap();
    copy_tree(&tmp.path().join("src"), &suspect);
    // Delete one file to force a partial set.
    let files: Vec<PathBuf> = std::fs::read_dir(&suspect)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    if files.len() > 1 {
        std::fs::remove_file(files[0].strip_prefix(&suspect).map(|_| &files[0]).unwrap()).unwrap();
    }

    let package = evidence::assemble(&suspect, &manifest, &commitment, None, None, now()).unwrap();
    // Partial: fewer matches than tokens, but each is independently provable.
    assert!(package.matches.len() < manifest.token_count);
    assert!(package.is_sound());
}

#[test]
fn clean_tree_yields_empty_but_valid_package() {
    let tmp = tempfile::tempdir().unwrap();
    let (manifest, commitment) = build_chain(tmp.path(), "e2e-salt");
    let clean = tmp.path().join("clean");
    std::fs::create_dir_all(&clean).unwrap();
    std::fs::write(clean.join("other.py"), "print('clean')\n").unwrap();

    // Clean tree → 0 matches. Package assembles; is_sound() is FALSE because
    // the merkle-proofs check requires ≥1 match (an empty evidence package
    // proves nothing). Assembly itself must not error.
    let package = evidence::assemble(&clean, &manifest, &commitment, None, None, now()).unwrap();
    assert!(package.matches.is_empty());
    assert!(!package.is_sound());
}

#[test]
fn tampered_commitment_is_rejected_at_assembly() {
    let tmp = tempfile::tempdir().unwrap();
    let (manifest, mut commitment) = build_chain(tmp.path(), "e2e-salt");
    let suspect = tmp.path().join("suspect");
    std::fs::create_dir_all(&suspect).unwrap();
    copy_tree(&tmp.path().join("src"), &suspect);

    commitment.payload.token_count += 1;
    let err = evidence::assemble(&suspect, &manifest, &commitment, None, None, now()).unwrap_err();
    assert!(err.contains("commitment is invalid"), "got: {err}");
}

#[test]
fn mismatched_manifest_root_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut manifest, commitment) = build_chain(tmp.path(), "e2e-salt");
    let suspect = tmp.path().join("suspect");
    std::fs::create_dir_all(&suspect).unwrap();
    copy_tree(&tmp.path().join("src"), &suspect);

    manifest.merkle_root = Some("00".repeat(32));
    let err = evidence::assemble(&suspect, &manifest, &commitment, None, None, now()).unwrap_err();
    assert!(err.contains("does not match manifest"), "got: {err}");
}

#[test]
fn foreign_fingerprint_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let (manifest, commitment) = build_chain(tmp.path(), "e2e-salt");
    let suspect = tmp.path().join("suspect");
    std::fs::create_dir_all(&suspect).unwrap();
    copy_tree(&tmp.path().join("src"), &suspect);

    // Fingerprint for a DIFFERENT archive: valid signatures, wrong binding.
    let other_dir = tmp.path().join("other");
    std::fs::create_dir_all(&other_dir).unwrap();
    let (other_manifest, other_commitment) = build_chain(&other_dir, "foreign-salt");
    let other_archive = other_dir.join("other.tar.gz");
    std::fs::write(&other_archive, b"different archive bytes").unwrap();
    let other_fp = fingerprint::sign_fingerprint(
        &other_manifest,
        &other_commitment,
        &other_archive,
        &test_seed(),
        now(),
    )
    .unwrap();

    let err = evidence::assemble(
        &suspect,
        &manifest,
        &commitment,
        Some(&other_fp),
        None,
        now(),
    )
    .unwrap_err();
    assert!(
        err.contains("commitment_digest does not match"),
        "got: {err}"
    );
}

#[test]
fn ledger_containment_is_recorded() {
    let tmp = tempfile::tempdir().unwrap();
    let (manifest, commitment) = build_chain(tmp.path(), "e2e-salt");
    let suspect = tmp.path().join("suspect");
    std::fs::create_dir_all(&suspect).unwrap();
    copy_tree(&tmp.path().join("src"), &suspect);

    let archive = tmp.path().join("release.tar.gz");
    std::fs::write(&archive, b"archive bytes").unwrap();
    let fp = fingerprint::sign_fingerprint(&manifest, &commitment, &archive, &test_seed(), now())
        .unwrap();
    let ledger = tmp.path().join("ledger.jsonl");
    fingerprint::publish(&ledger, &fp).unwrap();

    let package = evidence::assemble(
        &suspect,
        &manifest,
        &commitment,
        Some(&fp),
        Some(&ledger),
        now(),
    )
    .unwrap();
    assert_eq!(package.ledger_index, Some(0));
    assert!(package.is_sound());
    // The ledger check is present and passing.
    let names: Vec<String> = package
        .all_checks()
        .iter()
        .map(|(n, _)| n.clone())
        .collect();
    assert!(names.iter().any(|n| n.contains("ledger")));
}

#[test]
fn fingerprint_not_in_ledger_is_a_hard_error() {
    let tmp = tempfile::tempdir().unwrap();
    let (manifest, commitment) = build_chain(tmp.path(), "e2e-salt");
    let suspect = tmp.path().join("suspect");
    std::fs::create_dir_all(&suspect).unwrap();
    copy_tree(&tmp.path().join("src"), &suspect);

    let archive = tmp.path().join("release.tar.gz");
    std::fs::write(&archive, b"archive bytes").unwrap();
    let fp = fingerprint::sign_fingerprint(&manifest, &commitment, &archive, &test_seed(), now())
        .unwrap();
    // Ledger exists but does NOT contain this fingerprint.
    let ledger = tmp.path().join("ledger.jsonl");
    fingerprint::publish(&ledger, &fp).unwrap();
    let fp2_archive = tmp.path().join("release2.tar.gz");
    std::fs::write(&fp2_archive, b"different bytes entirely").unwrap();
    let fp2 =
        fingerprint::sign_fingerprint(&manifest, &commitment, &fp2_archive, &test_seed(), now())
            .unwrap();

    let err = evidence::assemble(
        &suspect,
        &manifest,
        &commitment,
        Some(&fp2),
        Some(&ledger),
        now(),
    )
    .unwrap_err();
    assert!(err.contains("not found in ledger"), "got: {err}");
}
