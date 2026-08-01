//! Integration test: compliance evidence export (SOC2, PCI-DSS, HIPAA).

use origin_secrets::cli::Cli;
use origin_secrets::dispatch;
use clap::Parser;
use std::path::Path;

fn cli(vault: &Path, args: &[&str]) -> Cli {
    let mut full = vec!["origin-secrets", "-V"];
    full.push(vault.to_str().unwrap());
    full.extend_from_slice(args);
    Cli::parse_from(full)
}

fn init_and_shard(vault: &Path) {
    dispatch(cli(vault, &["init", "--tier", "standard", "--no-prompt"])).unwrap();
    dispatch(cli(
        vault,
        &["shard", "--key", "master", "--threshold", "2", "--shares", "3"],
    ))
    .unwrap();
}

fn export_and_check(vault: &Path, flag: &str, path: &Path) {
    let r = dispatch(cli(vault, &["audit", flag, path.to_str().unwrap()]));
    assert!(r.is_ok(), "{} export failed: {:?}", flag, r);
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(
        json.get("entries").is_some(),
        "{} export missing 'entries'",
        flag
    );
    assert!(
        json.get("entry_count").is_some(),
        "{} export missing 'entry_count'",
        flag
    );
}

#[test]
fn export_soc2_valid() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init_and_shard(&vault);
    export_and_check(&vault, "--export-soc2", &dir.path().join("soc2.json"));
}

#[test]
fn export_pcidss_valid() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init_and_shard(&vault);
    export_and_check(&vault, "--export-pcidss", &dir.path().join("pci.json"));
}

#[test]
fn export_hipaa_valid() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("secrets.vault");
    init_and_shard(&vault);
    export_and_check(&vault, "--export-hipaa", &dir.path().join("hipaa.json"));
}
