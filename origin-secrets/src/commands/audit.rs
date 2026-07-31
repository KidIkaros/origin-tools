//! Audit command — inspect and export the vault audit log.

use crate::audit::{AuditEntry, ComplianceFormat, Operation};
use crate::cli::AuditArgs;
use crate::crypto::{decrypt_vault_data, derive_vault_key, EncryptedVault};
use crate::error::Error;
use crate::vault::Vault;
use std::path::Path;

/// Inspect and export the vault audit log.
///
/// With no flags, prints a summary of the audit log. With `show_all_logs` or
/// `show_recovery_log`, prints the matching entries as JSON. Filters
/// (`filter_key`, `filter_user`, `filter_start`, `filter_end`) narrow the set.
/// Compliance exports (`export_soc2` / `export_pcidss` / `export_hipaa`) write
/// the filtered entries as a JSON evidence file tagged with the framework.
pub fn cmd_audit(args: AuditArgs, vault_path: &Path, passphrase: &str) -> Result<(), Error> {
    let entries = load_audit_log(vault_path, passphrase)?;

    let filtered = filter_entries(entries, &args);

    // Compliance exports take precedence when present.
    if let Some(path) = &args.export_soc2 {
        return export_compliance(&filtered, ComplianceFormat::SOC2, path);
    }
    if let Some(path) = &args.export_pcidss {
        return export_compliance(
            &filtered,
            ComplianceFormat::PciDss {
                version: "4.0".to_string(),
            },
            path,
        );
    }
    if let Some(path) = &args.export_hipaa {
        return export_compliance(
            &filtered,
            ComplianceFormat::Hipaa {
                section: "164.312".to_string(),
            },
            path,
        );
    }

    // Display modes.
    if args.show_recovery_log {
        let recovery: Vec<AuditEntry> = filtered
            .iter()
            .filter(|e| matches!(e.operation, Operation::Recover { .. }))
            .cloned()
            .collect();
        print_entries(&recovery);
        return Ok(());
    }

    if args.show_all_logs {
        print_entries(&filtered);
        return Ok(());
    }

    // Default: summary.
    println!("Audit log: {} entries.", filtered.len());
    for e in &filtered {
        println!(
            "  [{}] {:?} key={} operator={} ts={}",
            e.entry_id, e.operation, e.key_id, e.operator, e.timestamp
        );
    }
    Ok(())
}

/// Decrypt the vault and return its audit log.
fn load_audit_log(vault_path: &Path, passphrase: &str) -> Result<Vec<AuditEntry>, Error> {
    let raw = std::fs::read_to_string(vault_path)
        .map_err(|_| Error::VaultNotFound(vault_path.to_path_buf()))?;
    let vault: Vault =
        serde_json::from_str(&raw).map_err(|e| Error::VaultCorrupted(e.to_string()))?;

    let key = derive_vault_key(passphrase.as_bytes(), &vault.salt, vault.tier)?;
    let encrypted = EncryptedVault {
        version: vault.version,
        created_at: vault.created_at.clone(),
        tier: vault.tier,
        fingerprint: vault.fingerprint.clone(),
        salt: vault.salt,
        nonce: vault.nonce,
        ciphertext: vault.ciphertext.clone(),
    };
    let vault_data = decrypt_vault_data(&encrypted, &key)?;
    Ok(vault_data.audit_log)
}

/// Apply the optional filters.
fn filter_entries(entries: Vec<AuditEntry>, args: &AuditArgs) -> Vec<AuditEntry> {
    entries
        .into_iter()
        .filter(|e| {
            if let Some(key) = &args.filter_key {
                if !e.key_id.contains(key) {
                    return false;
                }
            }
            if let Some(user) = &args.filter_user {
                if !e.operator.contains(user) {
                    return false;
                }
            }
            if let Some(start) = &args.filter_start {
                if &e.timestamp < start {
                    return false;
                }
            }
            if let Some(end) = &args.filter_end {
                if &e.timestamp > end {
                    return false;
                }
            }
            true
        })
        .collect()
}

/// Print entries as pretty JSON.
fn print_entries(entries: &[AuditEntry]) {
    let json = serde_json::to_string_pretty(entries).unwrap_or_else(|_| "[]".to_string());
    println!("{}", json);
}

/// Write filtered entries as a compliance evidence file.
fn export_compliance(
    entries: &[AuditEntry],
    format: ComplianceFormat,
    path: &Path,
) -> Result<(), Error> {
    let evidence = serde_json::json!({
        "format": format,
        "entry_count": entries.len(),
        "entries": entries,
    });
    let serialized = serde_json::to_string_pretty(&evidence).map_err(|e| Error::IoError(e.to_string()))?;
    std::fs::write(path, serialized).map_err(|e| Error::IoError(e.to_string()))?;
    println!(
        "Exported {} audit entries as {:?} evidence to {}.",
        entries.len(),
        format,
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ShardArgs;
    use crate::commands::shard::cmd_shard;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_vault(dir: &std::path::Path) -> (PathBuf, String) {
        use crate::crypto::encrypt_vault_data;
        use crate::vault::{MemoryTier, Vault};

        let passphrase = "audit-passphrase";
        let salt = [11u8; 16];
        let nonce = [12u8; 24];
        let tier = MemoryTier::Standard;
        let key = derive_vault_key(passphrase.as_bytes(), &salt, tier).unwrap();
        let mut vd = crate::crypto::VaultData::new();
        vd.master_seed = [5u8; 32];
        let enc = encrypt_vault_data(&vd, &key, salt, nonce, tier).unwrap();
        let vault = Vault {
            version: enc.version,
            created_at: enc.created_at.clone(),
            tier: enc.tier,
            fingerprint: enc.fingerprint.clone(),
            salt: enc.salt,
            nonce: enc.nonce,
            ciphertext: enc.ciphertext,
        };
        let path = dir.join("secrets.vault");
        std::fs::write(&path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();
        (path, passphrase.to_string())
    }

    #[test]
    fn test_audit_summary_lists_entries() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase) = make_vault(dir.path());
        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
        };
        cmd_shard(args, &vault_path, &passphrase).unwrap();

        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: false,
            filter_key: None,
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: None,
            export_pcidss: None,
            export_hipaa: None,
        };
        let result = cmd_audit(audit_args, &vault_path, &passphrase);
        assert!(result.is_ok());
    }

    #[test]
    fn test_audit_show_all_logs() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase) = make_vault(dir.path());
        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
        };
        cmd_shard(args, &vault_path, &passphrase).unwrap();

        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: true,
            filter_key: None,
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: None,
            export_pcidss: None,
            export_hipaa: None,
        };
        let result = cmd_audit(audit_args, &vault_path, &passphrase);
        assert!(result.is_ok());
    }

    #[test]
    fn test_audit_export_soc2() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase) = make_vault(dir.path());
        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
        };
        cmd_shard(args, &vault_path, &passphrase).unwrap();

        let out = dir.path().join("soc2.json");
        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: false,
            filter_key: None,
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: Some(out.clone()),
            export_pcidss: None,
            export_hipaa: None,
        };
        cmd_audit(audit_args, &vault_path, &passphrase).unwrap();

        let written = std::fs::read_to_string(&out).unwrap();
        assert!(written.contains("SOC2"));
        assert!(written.contains("entry_count"));
    }

    #[test]
    fn test_audit_export_hipaa() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase) = make_vault(dir.path());
        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
        };
        cmd_shard(args, &vault_path, &passphrase).unwrap();

        let out = dir.path().join("hipaa.json");
        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: false,
            filter_key: None,
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: None,
            export_pcidss: None,
            export_hipaa: Some(out.clone()),
        };
        cmd_audit(audit_args, &vault_path, &passphrase).unwrap();

        let written = std::fs::read_to_string(&out).unwrap();
        assert!(written.contains("Hipaa"));
    }

    #[test]
    fn test_audit_filter_by_key() {
        let dir = tempdir().unwrap();
        let (vault_path, passphrase) = make_vault(dir.path());
        let args = ShardArgs {
            key: "master".to_string(),
            threshold: 2,
            shares: 3,
        };
        cmd_shard(args, &vault_path, &passphrase).unwrap();

        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: true,
            filter_key: Some("master".to_string()),
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: None,
            export_pcidss: None,
            export_hipaa: None,
        };
        // Should still succeed and not panic.
        let result = cmd_audit(audit_args, &vault_path, &passphrase);
        assert!(result.is_ok());
    }

    #[test]
    fn test_audit_missing_vault() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.vault");
        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: false,
            filter_key: None,
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: None,
            export_pcidss: None,
            export_hipaa: None,
        };
        let result = cmd_audit(audit_args, &missing, "x");
        assert!(matches!(result, Err(Error::VaultNotFound(_))));
    }
}
