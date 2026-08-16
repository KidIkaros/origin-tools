// SPDX-License-Identifier: OPL-1.4
//
// Copyright (c) 2026 Origin Contributors

//! Integration tests — full embed → verify round-trips on real temp trees,
//! plus edge cases the CLI can hit.

use origin_canary::embed::{run_embed, EmbedConfig};
use origin_canary::manifest::CanaryManifest;
use origin_canary::verify::verify_source;
use std::fs;
use std::path::Path;

// ── Fixtures ───────────────────────────────────────────────────────────────

/// A small multi-language project (the "creator's" tree).
fn write_sample_project(root: &Path) {
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();

    fs::write(
        src.join("app.py"),
        "#!/usr/bin/env python3\nimport os\nimport sys\n\ndef main():\n    print(\"hello\")\n\ndef helper():\n    return 1\n\nif __name__ == \"__main__\":\n    main()\n",
    )
    .unwrap();

    fs::write(
        src.join("util.js"),
        "export function greet(name) {\n  return `hello ${name}`;\n}\n",
    )
    .unwrap();

    fs::write(src.join("lib.rs"), "pub fn answer() -> u32 {\n    42\n}\n").unwrap();
}

fn base_config(dir: &Path, n: usize) -> EmbedConfig {
    EmbedConfig {
        source_dir: dir.to_path_buf(),
        project_id: 7,
        distribution_id: "v1.0.0".to_string(),
        salt: "a1b2c3d4e5f6".to_string(),
        num_canaries: n,
        manifest_out: None,
        strategy_names: vec![
            "variable.python".to_string(),
            "variable.javascript".to_string(),
            "watermark".to_string(),
            "deadcode.python".to_string(),
        ],
    }
}

// ── Round-trips ────────────────────────────────────────────────────────────

#[test]
fn embed_verify_roundtrip_all_tokens_found() {
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());

    let result = run_embed(base_config(tmp.path(), 6)).unwrap();
    assert_eq!(result.manifest.token_count, 6);
    assert_eq!(result.modified_files.len(), 6);

    // Every token's secret must be found by verify on the same tree.
    let matches = verify_source(tmp.path(), &result.manifest);
    let found_ids: std::collections::BTreeSet<usize> = matches.iter().map(|m| m.token_id).collect();
    let expected_ids: std::collections::BTreeSet<usize> = (0..6).collect();
    assert_eq!(found_ids, expected_ids, "all 6 tokens must be found");

    // Manifest sanity.
    assert!(result
        .merkle_root
        .starts_with(|c: char| c.is_ascii_hexdigit()));
    assert_eq!(result.merkle_root.len(), 64);
    for token in &result.manifest.canary_tokens {
        assert!(
            !token.target_file.is_empty(),
            "embedded tokens must record target_file"
        );
        assert!(
            token.line_number >= 1,
            "line_number must be recorded (1-indexed)"
        );
        assert!(
            token.merkle_leaf.is_some(),
            "every token must carry its merkle leaf"
        );
        assert!(
            !token.merkle_proof.is_empty(),
            "every token must carry a proof"
        );
    }
}

#[test]
fn embedding_is_deterministic_same_seed_same_result() {
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    write_sample_project(tmp_a.path());
    write_sample_project(tmp_b.path());

    let result_a = run_embed(base_config(tmp_a.path(), 6)).unwrap();
    let result_b = run_embed(base_config(tmp_b.path(), 6)).unwrap();

    // Identical inputs → identical secrets, roots, and file placement.
    assert_eq!(result_a.merkle_root, result_b.merkle_root);
    assert_eq!(
        result_a
            .manifest
            .canary_tokens
            .iter()
            .map(|t| t.secret.clone())
            .collect::<Vec<_>>(),
        result_b
            .manifest
            .canary_tokens
            .iter()
            .map(|t| t.secret.clone())
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        result_a
            .manifest
            .canary_tokens
            .iter()
            .map(|t| t.target_file.clone())
            .collect::<Vec<_>>(),
        result_b
            .manifest
            .canary_tokens
            .iter()
            .map(|t| t.target_file.clone())
            .collect::<Vec<_>>(),
    );
}

#[test]
fn different_salt_different_tokens() {
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    write_sample_project(tmp_a.path());
    write_sample_project(tmp_b.path());

    let cfg_a = base_config(tmp_a.path(), 3);
    let mut cfg_b = base_config(tmp_b.path(), 3);
    cfg_b.salt = "00ff00ff00ff".to_string();

    let a = run_embed(cfg_a).unwrap();
    let b = run_embed(cfg_b).unwrap();

    assert_ne!(a.merkle_root, b.merkle_root);
}

#[test]
fn verify_finds_canary_in_partial_copy() {
    // Realistic infringement scenario: only part of the tree is copied.
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());
    let manifest = run_embed(base_config(tmp.path(), 6)).unwrap().manifest;

    // Suspect tree: only the Python files, renamed directory.
    let suspect = tempfile::tempdir().unwrap();
    let suspect_src = suspect.path().join("stolen");
    fs::create_dir_all(&suspect_src).unwrap();
    fs::copy(tmp.path().join("src/app.py"), suspect_src.join("app.py")).unwrap();

    let matches = verify_source(suspect.path(), &manifest);
    assert!(
        !matches.is_empty(),
        "python canaries must survive a partial copy with renamed dir"
    );
    assert!(matches.iter().all(|m| m.file_path.starts_with("stolen/")));
}

#[test]
fn verify_clean_tree_finds_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());
    let manifest = run_embed(base_config(tmp.path(), 6)).unwrap().manifest;

    let clean = tempfile::tempdir().unwrap();
    fs::write(clean.path().join("main.py"), "print(\"clean\")\n").unwrap();

    assert!(verify_source(clean.path(), &manifest).is_empty());
}

#[test]
fn manifest_json_roundtrip_preserves_everything() {
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());
    let manifest = run_embed(base_config(tmp.path(), 5)).unwrap().manifest;

    let json = serde_json::to_string_pretty(&manifest).unwrap();
    let back: CanaryManifest = serde_json::from_str(&json).unwrap();

    assert_eq!(back.project_id, manifest.project_id);
    assert_eq!(back.merkle_root, manifest.merkle_root);
    assert_eq!(back.token_count, manifest.token_count);
    assert_eq!(back.len(), manifest.len());
    for (a, b) in back.canary_tokens.iter().zip(manifest.canary_tokens.iter()) {
        assert_eq!(a.secret, b.secret);
        assert_eq!(a.merkle_leaf, b.merkle_leaf);
        assert_eq!(a.merkle_proof, b.merkle_proof);
        assert_eq!(a.target_file, b.target_file);
    }
}

// ── Merkle invariants (via manifest) ────────────────────────────────────────

#[test]
fn every_merkle_proof_reconstructs_the_root() {
    for count in [2usize, 3, 5, 7, 9] {
        let tmp = tempfile::tempdir().unwrap();
        write_sample_project(tmp.path());

        let manifest = run_embed(base_config(tmp.path(), count)).unwrap().manifest;

        // Replay every proof leaf→root and check it lands on the manifest root.
        // NOTE: leaf position = the token's index in canary_tokens, NOT its
        // token_id (unembedded tokens are filtered from the manifest, so ids
        // may be non-contiguous).
        for (leaf_pos, token) in manifest.canary_tokens.iter().enumerate() {
            let leaf = token.merkle_leaf.clone().unwrap();
            let mut current = leaf;
            let mut idx = leaf_pos;
            for sibling in &token.merkle_proof {
                let (left, right) = if idx % 2 == 0 {
                    (current.clone(), sibling.clone())
                } else {
                    (sibling.clone(), current.clone())
                };
                let combined = [hex::decode(&left).unwrap(), hex::decode(&right).unwrap()].concat();
                current = hex::encode(origin_crypto_sdk::blake3::hash(&combined).as_bytes());
                idx /= 2;
            }
            assert_eq!(
                current,
                manifest.merkle_root.clone().unwrap(),
                "proof for token {} ({} leaves) must reconstruct root",
                token.token_id,
                count
            );
        }
    }
}

// ── Edge cases ─────────────────────────────────────────────────────────────

#[test]
fn embed_missing_source_dir_is_clean_error() {
    let mut cfg = base_config(Path::new("/nonexistent/canary/definitely"), 3);
    cfg.source_dir = Path::new("/nonexistent/canary/definitely").to_path_buf();
    let err = run_embed(cfg).unwrap_err();
    assert!(err.contains("does not exist"), "got: {err}");
}

#[test]
fn embed_zero_canaries_is_clean_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());
    let err = run_embed(base_config(tmp.path(), 0)).unwrap_err();
    assert!(err.contains("num_canaries"), "got: {err}");
}

#[test]
fn embed_unknown_strategy_is_clean_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());
    let mut cfg = base_config(tmp.path(), 3);
    cfg.strategy_names = vec!["variable.haskell".to_string()];
    let err = run_embed(cfg).unwrap_err();
    assert!(err.contains("unknown strategy"), "got: {err}");
}

#[test]
fn embed_empty_strategy_list_is_clean_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());
    let mut cfg = base_config(tmp.path(), 3);
    cfg.strategy_names = vec![];
    let err = run_embed(cfg).unwrap_err();
    assert!(err.contains("at least one strategy"), "got: {err}");
}

#[test]
fn embed_wrong_language_strategy_warns_but_embeds_others() {
    // Ask for solidity + python strategies on a py/js/rs project. Solidity
    // tokens can't embed (no .sol files), so only 3 python tokens land.
    // With honest coverage, requesting more than can be placed is a clear
    // error rather than a silent shortfall.
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());
    let mut cfg = base_config(tmp.path(), 6);
    cfg.strategy_names = vec![
        "variable.solidity".to_string(),
        "variable.python".to_string(),
    ];
    let err = run_embed(cfg).unwrap_err();
    assert!(
        err.contains("only embedded 3 of 6 requested tokens"),
        "got: {err}"
    );
    // And a correctly-sized request on a fresh tree embeds exactly the
    // python-embeddable tokens (the errored run above already mutated tmp,
    // so use a clean dir here to avoid cross-contamination).
    let tmp2 = tempfile::tempdir().unwrap();
    write_sample_project(tmp2.path());
    let mut cfg2 = base_config(tmp2.path(), 3);
    cfg2.strategy_names = vec!["variable.python".to_string()];
    let result = run_embed(cfg2).unwrap();
    assert_eq!(result.manifest.token_count, 3, "only python tokens embed");
    let matches = verify_source(tmp2.path(), &result.manifest);
    assert_eq!(matches.len(), 3);
}

#[test]
fn embed_wrong_language_strategy_is_clean_error_when_nothing_embeds() {
    // Solidity-only strategy on a py/js/rs project: nothing can embed,
    // so run_embed must fail cleanly instead of building an empty Merkle.
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());
    let mut cfg = base_config(tmp.path(), 2);
    cfg.strategy_names = vec!["variable.solidity".to_string()];
    let err = run_embed(cfg).unwrap_err();
    assert!(
        err.contains("only embedded 0 of 2 requested tokens")
            || err.contains("no canary tokens were embedded"),
        "got: {err}"
    );
}

#[test]
fn excluded_directories_are_never_embedded_nor_verified() {
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());

    // Canaries only land in known embeddable files; also plant a decoy in
    // node_modules that verify must ignore (excluded dir).
    let nm = tmp.path().join("node_modules");
    fs::create_dir_all(&nm).unwrap();
    fs::write(nm.join("decoy.js"), "const decoy = 1;\n").unwrap();

    let result = run_embed(base_config(tmp.path(), 6)).unwrap();
    assert!(
        result
            .manifest
            .canary_tokens
            .iter()
            .all(|t| !t.target_file.starts_with("node_modules/")),
        "no canary may be embedded into excluded dirs"
    );

    // Plant a REAL secret inside node_modules: verify must not match it there.
    let victim = result.manifest.canary_tokens[0].secret.clone();
    fs::write(nm.join("planted.js"), format!("const x = \"{victim}\";\n")).unwrap();
    // The same secret still exists legitimately in src/ — matches must only
    // come from non-excluded locations.
    let matches = verify_source(tmp.path(), &result.manifest);
    assert!(matches
        .iter()
        .all(|m| !m.file_path.contains("node_modules")));
}

#[test]
fn very_large_files_are_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    // One huge python file (600KB > 500KB limit).
    let big = "x = 1\n".repeat(120_000);
    fs::write(src.join("big.py"), &big).unwrap();
    // And one normal python file so embedding can succeed.
    fs::write(src.join("ok.py"), "import os\n\ndef main():\n    pass\n").unwrap();

    let mut cfg = base_config(tmp.path(), 4);
    // Python-only tree: cycle python strategies only.
    cfg.strategy_names = vec!["variable.python".to_string()];

    let result = run_embed(cfg).unwrap();
    assert!(
        result
            .manifest
            .canary_tokens
            .iter()
            .all(|t| t.target_file == "src/ok.py"),
        "all canaries must land in the small file, never the 600KB one"
    );
    assert_eq!(result.modified_files.len(), 4);
}

#[test]
fn truncated_lines_never_panic_on_multibyte_content() {
    // A suspect file with multibyte UTF-8 where the old byte-slicing
    // truncate would panic mid-character.
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());
    let manifest = run_embed(base_config(tmp.path(), 3)).unwrap().manifest;

    let suspect = tempfile::tempdir().unwrap();
    let ssrc = suspect.path().join("src");
    fs::create_dir_all(&ssrc).unwrap();
    // Secret at line START (after short prefix): truncation must keep it.
    let secret = &manifest.canary_tokens[0].secret;
    let pad = "🦀rust🦀crab🦀".repeat(30);
    fs::write(ssrc.join("evil.py"), format!("{secret} // {pad}\n")).unwrap();

    let matches = verify_source(suspect.path(), &manifest);
    assert_eq!(matches.len(), 1);
    assert!(matches[0].line_content.contains(secret));
}

#[test]
fn trailing_newline_is_preserved_after_embed() {
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());

    let before: Vec<bool> = ["src/app.py", "src/util.js", "src/lib.rs"]
        .iter()
        .map(|f| fs::read(tmp.path().join(f)).unwrap().ends_with(b"\n"))
        .collect::<Vec<_>>();
    assert!(before.iter().all(|b| *b), "fixture files end with newline");

    run_embed(base_config(tmp.path(), 6)).unwrap();

    for f in ["src/app.py", "src/util.js", "src/lib.rs"] {
        let content = fs::read(tmp.path().join(f)).unwrap();
        assert!(
            content.ends_with(b"\n"),
            "{f} must keep its trailing newline after embedding"
        );
    }
}

#[test]
fn embed_tree_with_no_supported_files_errors_cleanly() {
    // A tree with only non-text/binary files — nothing embeddable anywhere.
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("img.png"),
        [0x89u8, 0x50, 0x4E, 0x47, 0x0D, 0x0A],
    )
    .unwrap();
    fs::write(tmp.path().join("data.bin"), vec![0u8; 16]).unwrap();

    let err = run_embed(base_config(tmp.path(), 3)).unwrap_err();
    assert!(
        err.contains("only embedded 0 of 3 requested tokens")
            || err.contains("no canary tokens were embedded"),
        "got: {err}"
    );
}

// dead-code strategy embeds inside an existing function; ensure the file
// still parses as valid Python after embedding.
#[test]
fn python_still_parses_after_deadcode_embed() {
    let tmp = tempfile::tempdir().unwrap();
    write_sample_project(tmp.path());
    let mut cfg = base_config(tmp.path(), 2);
    cfg.strategy_names = vec!["deadcode.python".to_string()];

    run_embed(cfg).unwrap();

    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg("import ast,sys; ast.parse(open(sys.argv[1]).read())")
        .arg(tmp.path().join("src/app.py"))
        .status()
        .unwrap();
    assert!(out.success(), "embedded python must still parse");
}
