//! Product workflow coverage: readiness, handoff, preflight, and diagnostics.

use clap::Parser;
use origin_secrets::cli::Cli;
use origin_secrets::dispatch;
use std::path::{Path, PathBuf};

fn cli(vault: &Path, passphrase: Option<&Path>, args: &[&str]) -> Cli {
    let mut full = vec!["origin-secrets", "-V", vault.to_str().unwrap()];
    if let Some(path) = passphrase {
        full.push("-p");
        full.push(path.to_str().unwrap());
    }
    full.extend_from_slice(args);
    Cli::parse_from(full)
}

fn passphrase(dir: &Path) -> PathBuf {
    let path = dir.join("passphrase.txt");
    std::fs::write(&path, "correct horse battery staple\n").unwrap();
    path
}

#[test]
fn product_workflow_covers_first_run_handoff_preflight_and_support() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    let password = passphrase(dir.path());
    let handoff = dir.path().join("alice.handoff.json");
    let diagnostic = dir.path().join("diagnostic.json");

    assert!(dispatch(cli(&vault, None, &["status"])).is_ok());
    assert!(dispatch(cli(&vault, None, &["diagnose"])).is_ok());
    assert!(dispatch(cli(&vault, Some(&password), &["init", "--tier", "nano"])).is_ok());
    assert!(dispatch(cli(&vault, Some(&password), &["--json", "status"])).is_ok());
    assert!(dispatch(cli(
        &vault,
        Some(&password),
        &[
            "shard",
            "--label",
            "master",
            "--threshold",
            "2",
            "--shares",
            "3"
        ]
    ))
    .is_ok());
    assert!(dispatch(cli(&vault, Some(&password), &["status"])).is_ok());

    let exported = dir.path().join("alice-share.json");
    assert!(dispatch(cli(
        &vault,
        Some(&password),
        &[
            "export-share",
            "--share",
            "1",
            "--out",
            exported.to_str().unwrap(),
            "--recipient",
            "alice",
        ]
    ))
    .is_ok());
    assert!(dispatch(cli(
        &vault,
        Some(&password),
        &[
            "handoff",
            "--share",
            exported.to_str().unwrap(),
            "--out",
            handoff.to_str().unwrap(),
            "--recipient",
            "alice",
        ]
    ))
    .is_ok());
    let mismatch = dir.path().join("mismatch.handoff.json");
    let mismatch_result = dispatch(cli(
        &vault,
        Some(&password),
        &[
            "handoff",
            "--share",
            exported.to_str().unwrap(),
            "--out",
            mismatch.to_str().unwrap(),
            "--recipient",
            "bob",
        ],
    ));
    assert!(matches!(
        mismatch_result,
        Err(origin_secrets::Error::CryptoError(_))
    ));
    let manifest = std::fs::read_to_string(&handoff).unwrap();
    assert!(manifest.contains("custodian-handoff"));
    assert!(!manifest.contains("share_data"));

    let share_one = dir.path().join("shares/share_001.json");
    let share_two = dir.path().join("shares/share_002.json");
    assert!(dispatch(cli(
        &vault,
        Some(&password),
        &[
            "recover",
            share_one.to_str().unwrap(),
            share_two.to_str().unwrap(),
            "--preflight",
            "--json",
        ]
    ))
    .is_ok());
    assert!(dispatch(cli(
        &vault,
        Some(&password),
        &["recover", "missing-share.json", "--preflight"],
    ))
    .is_ok());
    assert!(dispatch(cli(&vault, None, &["--json", "diagnose"])).is_ok());
    assert!(dispatch(cli(
        &vault,
        Some(&password),
        &["diagnose", "--out", diagnostic.to_str().unwrap()]
    ))
    .is_ok());
    assert!(std::fs::read_to_string(diagnostic)
        .unwrap()
        .contains("origin-secrets"));
}

#[test]
fn product_workflow_rejects_existing_diagnostic_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    let out = dir.path().join("diagnostic.json");
    std::fs::write(&out, "existing").unwrap();

    let result = dispatch(cli(
        &vault,
        None,
        &["diagnose", "--out", out.to_str().unwrap()],
    ));
    assert!(matches!(
        result,
        Err(origin_secrets::Error::FileAlreadyExists(_))
    ));
}
