// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-secrets` as a foundational dependency.
//!
//! Threshold secrets management through the crate's public dispatcher
//! (`origin_secrets::dispatch`): init a vault → shard the master key
//! (3-of-5) → export shares → verify → recover from a 3-share subset
//! → rotate the passphrase. Also drives the typed crypto surface
//! (`EncryptedVault` / `VaultData`) directly.
//!
//! Run with: `cargo run -p origin-secrets --example dogfood`

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use clap::Parser;
use origin_secrets::crypto::{decrypt_vault_data, encrypt_vault_data, VaultData};
use origin_secrets::{dispatch, Cli};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join("origin-dogfood-secrets");
    let dir = base.join(format!(
        "{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn dispatch_vault(_vault: &Path, args: &[&str]) -> Result<(), origin_secrets::Error> {
    let cli = Cli::parse_from(args);
    dispatch(cli)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = scratch("run");
    let vault = dir.join("secrets.vault");
    let vault_s = vault.to_str().unwrap().to_string();

    let pw = dir.join("pw.txt");
    std::fs::write(&pw, "dogfood-secrets-pass\n")?;
    let pw = pw.to_str().unwrap().to_string();

    // ── init: encrypted vault (Argon2id-sealed) ──────────────────────
    dispatch_vault(
        &vault,
        &[
            "origin-secrets",
            &format!("--vault={vault_s}"),
            &format!("--passphrase-file={pw}"),
            "init",
            "--tier=nano",
        ],
    )
    .map_err(|e| e.to_string())?;
    assert!(vault.exists(), "vault file created");
    println!("✓ init → encrypted vault");

    // ── shard: K-of-N split of the master key (3-of-5) ───────────────
    dispatch_vault(
        &vault,
        &[
            "origin-secrets",
            &format!("--vault={vault_s}"),
            &format!("--passphrase-file={pw}"),
            "shard",
            "--label=master",
            "--threshold=3",
            "--shares=5",
        ],
    )
    .map_err(|e| e.to_string())?;
    let shares_dir = dir.join("shares");
    let share_count = std::fs::read_dir(&shares_dir)
        .map_err(|e| format!("shares dir: {e}"))?
        .count();
    assert_eq!(share_count, 5, "5 share files written");
    println!("✓ shard → {share_count} shares (threshold 3)");

    // ── export shares + verify one ───────────────────────────────────
    let mut share_paths = Vec::new();
    for n in 1..=3u8 {
        let out = dir.join(format!("share{n}.json"));
        dispatch_vault(
            &vault,
            &[
                "origin-secrets",
                &format!("--vault={vault_s}"),
                &format!("--passphrase-file={pw}"),
                "export-share",
                &format!("--share={n}"),
                &format!("--out={}", out.display()),
                "--recipient=ops-team",
            ],
        )
        .map_err(|e| e.to_string())?;
        share_paths.push(out);
    }
    dispatch_vault(
        &vault,
        &[
            "origin-secrets",
            &format!("--vault={vault_s}"),
            &format!("--passphrase-file={pw}"),
            "verify",
            &format!("--share={}", share_paths[0].display()),
        ],
    )
    .map_err(|e| e.to_string())?;
    println!("✓ export-share ×3 + verify");

    // ── list-keys / list-shares / audit ──────────────────────────────
    dispatch_vault(
        &vault,
        &[
            "origin-secrets",
            &format!("--vault={vault_s}"),
            &format!("--passphrase-file={pw}"),
            "list-keys",
        ],
    )
    .map_err(|e| e.to_string())?;
    dispatch_vault(
        &vault,
        &[
            "origin-secrets",
            &format!("--vault={vault_s}"),
            &format!("--passphrase-file={pw}"),
            "list-shares",
        ],
    )
    .map_err(|e| e.to_string())?;
    dispatch_vault(
        &vault,
        &[
            "origin-secrets",
            &format!("--vault={vault_s}"),
            &format!("--passphrase-file={pw}"),
            "audit",
            "--show-all-logs",
        ],
    )
    .map_err(|e| e.to_string())?;
    println!("✓ list-keys / list-shares / audit");

    // ── recover: any 3 of the 5 shares reconstruct the seed ──────────
    let recovered = dir.join("recovered.hex");
    dispatch_vault(
        &vault,
        &[
            "origin-secrets",
            &format!("--vault={vault_s}"),
            &format!("--passphrase-file={pw}"),
            "recover",
            &format!("{}", share_paths[0].display()),
            &format!("{}", share_paths[1].display()),
            &format!("{}", share_paths[2].display()),
            &format!("--out={}", recovered.display()),
        ],
    )
    .map_err(|e| e.to_string())?;
    let recovered_seed = std::fs::read_to_string(&recovered)?;
    assert_eq!(recovered_seed.trim().len(), 64, "32-byte seed as hex");
    println!("✓ recover from a 3-share subset → 32-byte seed");

    // ── rotate-passphrase ────────────────────────────────────────────
    let pw2 = dir.join("pw2.txt");
    std::fs::write(&pw2, "new-secrets-pass\n")?;
    dispatch_vault(
        &vault,
        &[
            "origin-secrets",
            &format!("--vault={vault_s}"),
            &format!("--passphrase-file={pw}"),
            "rotate-passphrase",
            &format!("--new-passphrase-file={}", pw2.display()),
        ],
    )
    .map_err(|e| e.to_string())?;
    dispatch_vault(
        &vault,
        &[
            "origin-secrets",
            &format!("--vault={vault_s}"),
            &format!("--passphrase-file={}", pw2.display()),
            "status",
        ],
    )
    .map_err(|e| e.to_string())?;
    println!("✓ rotate-passphrase (new passphrase unlocks status)");

    // ── typed crypto surface: EncryptedVault / VaultData ─────────────
    let mut data = VaultData::new();
    data.master_seed = [0x42u8; 32];
    data.keys.insert("deploy-key".to_string(), vec![1, 2, 3]);
    let key = [0x24u8; 32];
    let salt = [0x11u8; 16];
    let nonce = [0x22u8; 24];
    let enc = encrypt_vault_data(
        &data,
        &key,
        salt,
        nonce,
        origin_secrets::vault::MemoryTier::Nano,
    )
    .map_err(|e| e.to_string())?;
    let dec = decrypt_vault_data(&enc, &key).map_err(|e| e.to_string())?;
    assert_eq!(dec.master_seed, data.master_seed);
    assert_eq!(dec.keys.get("deploy-key"), Some(&vec![1, 2, 3]));
    println!("✓ typed EncryptedVault / VaultData round-trip");

    println!("\norigin-secrets dogfood OK — usable as a foundational dependency");
    Ok(())
}
