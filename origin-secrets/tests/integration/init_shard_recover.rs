//! Integration test: full lifecycle init -> shard -> export -> recover -> verify.
//!
//! Drives the public `dispatch` API exactly as the CLI binary would, using
//! temp directories so tests don't touch `~/.origin`.

use origin_secrets::cli::Cli;
use origin_secrets::dispatch;
use clap::Parser;
use std::path::Path;

/// Build a `Cli` invoking `origin-secrets -V <vault> <subcommand...>`.
fn cli(vault: &std::path::Path, args: &[&str]) -> Cli {
    let mut full = vec!["origin-secrets", "-V"];
    full.push(vault.to_str().unwrap());
    full.extend_from_slice(args);
    Cli::parse_from(full)
}

#[test]
fn lifecycle_init_shard_export_recover_verify() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    let shares_dir = dir.path().join("shares");
    std::fs::create_dir_all(&shares_dir).unwrap();
    let out = dir.path().join("seed.recovered");

    // init (standard tier)
    let r = dispatch(cli(
        &vault,
        &["init", "--tier", "standard", "--no-prompt"],
    ));
    assert!(r.is_ok(), "init failed: {:?}", r);
    assert!(vault.exists());

    // shard 3-of-5
    let r = dispatch(cli(
        &vault,
        &[
            "shard",
            "--key",
            "master",
            "--threshold",
            "3",
            "--shares",
            "5",
        ],
    ));
    assert!(r.is_ok(), "shard failed: {:?}", r);
    for i in 1..=5u8 {
        assert!(shares_dir
            .join(format!("share_{:03}.json", i))
            .exists());
    }

    // export share 1 (no recipient)
    let export_out = dir.path().join("share1.exported.json");
    let r = dispatch(cli(
        &vault,
        &[
            "export-share",
            "--share",
            "1",
            "-o",
            export_out.to_str().unwrap(),
        ],
    ));
    assert!(r.is_ok(), "export failed: {:?}", r);
    assert!(export_out.exists());

    // recover from shares 1,2,3 -> out file
    let s1 = shares_dir.join("share_001.json");
    let s2 = shares_dir.join("share_002.json");
    let s3 = shares_dir.join("share_003.json");
    let r = dispatch(cli(
        &vault,
        &[
            "recover",
            s1.to_str().unwrap(),
            s2.to_str().unwrap(),
            s3.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ],
    ));
    assert!(r.is_ok(), "recover failed: {:?}", r);
    assert!(out.exists());
    let recovered = std::fs::read_to_string(&out).unwrap();
    assert_eq!(recovered.len(), 64); // 32 bytes hex

    // verify the vault (integrity + audit log)
    let r = dispatch(cli(&vault, &["verify", "--vault-path", vault.to_str().unwrap()]));
    assert!(r.is_ok(), "verify failed: {:?}", r);
}

#[test]
fn lifecycle_audit_export_soc2() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    let soc2 = dir.path().join("soc2.json");

    dispatch(cli(
        &vault,
        &["init", "--tier", "standard", "--no-prompt"],
    ))
    .unwrap();
    dispatch(cli(
        &vault,
        &["shard", "--key", "master", "--threshold", "2", "--shares", "3"],
    ))
    .unwrap();

    let r = dispatch(cli(
        &vault,
        &["audit", "--export-soc2", soc2.to_str().unwrap()],
    ));
    assert!(r.is_ok(), "audit soc2 failed: {:?}", r);
    let evidence: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&soc2).unwrap()).unwrap();
    assert!(evidence.get("entries").is_some());
}
