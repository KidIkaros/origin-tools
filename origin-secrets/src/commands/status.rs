//! Product-facing vault readiness and next-action summary.

use crate::cli::StatusArgs;
use crate::error::Error;
use crate::vault_handle::VaultHandle;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct StatusResponse {
    ok: bool,
    command: &'static str,
    vault: String,
    initialized: bool,
    tier: Option<String>,
    fingerprint: Option<String>,
    audit_entries: usize,
    shares_dir: String,
    share_files: usize,
    usable_shares: usize,
    invalid_share_files: usize,
    threshold: Option<u8>,
    total_shares: Option<u8>,
    revoked_shares: usize,
    next_action: &'static str,
}

/// Show non-secret product readiness information for a vault.
///
/// A missing vault is intentionally useful without a passphrase: it gives a
/// first-time operator a safe next step. An existing vault must be decrypted so
/// status never guesses at its tier, fingerprint, audit, or share state.
pub fn cmd_status(
    _args: StatusArgs,
    vault_path: &Path,
    passphrase: Option<&str>,
    json: bool,
) -> Result<(), Error> {
    let shares_dir = vault_path
        .parent()
        .map(|p| p.join("shares"))
        .unwrap_or_else(|| Path::new("shares").to_path_buf());

    if !vault_path.exists() {
        let response = StatusResponse {
            ok: true,
            command: "status",
            vault: vault_path.display().to_string(),
            initialized: false,
            tier: None,
            fingerprint: None,
            audit_entries: 0,
            shares_dir: shares_dir.display().to_string(),
            share_files: 0,
            usable_shares: 0,
            invalid_share_files: 0,
            threshold: None,
            total_shares: None,
            revoked_shares: 0,
            next_action: "Initialize a vault with `origin-secrets init`.",
        };
        return render(response, json);
    }

    let passphrase = passphrase.ok_or(Error::PassphraseRequired)?;
    let handle = VaultHandle::open(vault_path, passphrase)?;
    let data = handle.data();

    let mut share_files = 0usize;
    let mut usable_shares = 0usize;
    let mut invalid_share_files = 0usize;
    let mut threshold = None;
    let mut total_shares = None;

    if shares_dir.is_dir() {
        for entry in std::fs::read_dir(&shares_dir)
            .map_err(|e| Error::IoError(format!("read shares directory: {e}")))?
        {
            let entry = entry.map_err(|e| Error::IoError(format!("read share entry: {e}")))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            share_files += 1;
            match crate::commands::share_io::read_share_file(&path, Some(vault_path), passphrase) {
                Ok(share) => {
                    threshold = threshold.or(Some(share.threshold));
                    total_shares = total_shares.or(Some(share.total_shares));
                    usable_shares += 1;
                }
                Err(_) => invalid_share_files += 1,
            }
        }
    }

    let next_action = match (threshold, usable_shares) {
        (None, _) => "Create a K-of-N share set with `origin-secrets shard`.",
        (Some(required), usable) if usable < required as usize => {
            "Collect more valid custodian shares before recovery."
        }
        _ => "Share set is ready for verification, handoff, or recovery.",
    };

    let response = StatusResponse {
        ok: true,
        command: "status",
        vault: vault_path.display().to_string(),
        initialized: true,
        tier: Some(handle.tier.to_string()),
        fingerprint: Some(handle.fingerprint.clone()),
        audit_entries: data.audit_log.len(),
        shares_dir: shares_dir.display().to_string(),
        share_files,
        usable_shares,
        invalid_share_files,
        threshold,
        total_shares,
        revoked_shares: data.revoked_shares.len(),
        next_action,
    };
    render(response, json)
}

fn render(response: StatusResponse, json: bool) -> Result<(), Error> {
    if json {
        crate::commands::output::print_json(&response, "status")?;
    } else {
        println!("Vault: {}", response.vault);
        if !response.initialized {
            println!(
                "{}: not initialized",
                crate::commands::output::style("Status", crate::commands::output::Style::Warning)
            );
            println!(
                "{}: {}",
                crate::commands::output::style("Next", crate::commands::output::Style::Plain),
                response.next_action
            );
            return Ok(());
        }
        println!(
            "{}: ready",
            crate::commands::output::style("Status", crate::commands::output::Style::Success)
        );
        println!("Tier: {}", response.tier.as_deref().unwrap_or("unknown"));
        println!(
            "Fingerprint: {}",
            response.fingerprint.as_deref().unwrap_or("unknown")
        );
        println!("Audit entries: {}", response.audit_entries);
        println!(
            "Shares: {}/{} usable ({} files, {} unavailable)",
            response.usable_shares,
            response
                .threshold
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".to_string()),
            response.share_files,
            response.invalid_share_files
        );
        println!(
            "{}: {}",
            crate::commands::output::style("Next", crate::commands::output::Style::Plain),
            response.next_action
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn status_missing_vault_is_actionable_without_passphrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secrets.vault");
        let result = cmd_status(StatusArgs {}, &path, None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn status_existing_vault_requires_passphrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secrets.vault");
        std::fs::write(&path, "not-a-vault").unwrap();
        let result = cmd_status(StatusArgs {}, &path, None, false);
        assert!(matches!(result, Err(Error::PassphraseRequired)));
    }
}
