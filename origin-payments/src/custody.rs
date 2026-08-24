// SPDX-License-Identifier: Apache-2.0

//! K-of-N key custody via `origin-secrets` (design §3, P7).
//!
//! `keys-backup` initializes an origin-secrets threshold vault under the
//! payments root and shards its master seed K-of-N — the operator's
//! break-glass custody for the payments keying material. `keys-recover`
//! reconstructs the seed from ≥ K shares. The heavy lifting (Argon2id
//! vault, Reed-Solomon shares, hybrid signatures, audit) is origin-secrets
//! itself; this module is the wiring.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::store::PaymentStore;

/// Run `origin-secrets init` + `shard` for the payments custody vault.
pub fn backup(store: &PaymentStore, passphrase: &str, shards: u8, threshold: u8) -> Result<()> {
    if threshold == 0 || threshold > shards {
        return Err(Error::StoreCorrupted {
            details: format!("invalid threshold {threshold} for {shards} shares"),
        });
    }
    let keys_dir = store.root().join("keys");
    std::fs::create_dir_all(&keys_dir).map_err(|e| Error::IoError {
        details: format!("creating {}: {e}", keys_dir.display()),
    })?;
    let vault = keys_dir.join("secrets.vault");
    if vault.exists() {
        return Err(Error::AlreadyInitialized(vault));
    }

    // origin-secrets resolves passphrases from a file / stdin / TTY; pass
    // the in-memory passphrase via a 0600 temp file beside the vault.
    let pw_path = keys_dir.join(".custody.pw");
    std::fs::write(&pw_path, passphrase).map_err(|e| Error::IoError {
        details: format!("writing {}: {e}", pw_path.display()),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&pw_path, std::fs::Permissions::from_mode(0o600));
    }

    let dispatch = |command: origin_secrets::cli::Commands| -> Result<()> {
        let cli = origin_secrets::cli::Cli {
            vault: vault.clone(),
            passphrase_file: Some(pw_path.clone()),
            prompt: false,
            json: false,
            command,
        };
        origin_secrets::dispatch(cli).map_err(|e| Error::CustodyError {
            details: e.to_string(),
        })
    };

    let result = (|| -> Result<()> {
        dispatch(origin_secrets::cli::Commands::Init(
            origin_secrets::cli::InitArgs {
                tier: "nano".to_string(),
            },
        ))?;
        dispatch(origin_secrets::cli::Commands::Shard(
            origin_secrets::cli::ShardArgs {
                key: "payments".to_string(),
                threshold,
                shares: shards,
                force: false,
                expires: None,
            },
        ))?;
        Ok(())
    })();

    let _ = std::fs::remove_file(&pw_path);
    result
}

/// Recover the custody seed from ≥ K share files into `out`.
///
/// Shares are encrypted at rest (origin-secrets P3.3), so recovery needs
/// the vault passphrase; it is passed the same way as `backup` — a 0600
/// temp file beside the vault — and removed afterwards.
pub fn recover(
    store: &PaymentStore,
    shares: &[PathBuf],
    out: &Path,
    passphrase: &str,
) -> Result<()> {
    let keys_dir = store.root().join("keys");
    let pw_path = keys_dir.join(".custody.pw");
    std::fs::write(&pw_path, passphrase).map_err(|e| Error::IoError {
        details: format!("writing {}: {e}", pw_path.display()),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&pw_path, std::fs::Permissions::from_mode(0o600));
    }

    let cli = origin_secrets::cli::Cli {
        vault: keys_dir.join("secrets.vault"),
        passphrase_file: Some(pw_path.clone()),
        prompt: false,
        json: false,
        command: origin_secrets::cli::Commands::Recover(origin_secrets::cli::RecoverArgs {
            shares: shares.to_vec(),
            out: Some(out.to_path_buf()),
            vault_out: None,
            source_vault: None,
            tier: "nano".to_string(),
            preflight: false,
            force: false,
        }),
    };
    let result = origin_secrets::dispatch(cli).map_err(|e| Error::CustodyError {
        details: e.to_string(),
    });
    let _ = std::fs::remove_file(&pw_path);
    result?;
    Ok(())
}
