//! Audit command — inspect and export the vault audit log.

use crate::audit::{AuditEntry, ComplianceFormat, Operation};
use crate::cli::AuditArgs;
use crate::error::Error;
use crate::vault_handle::VaultHandle;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct AuditFailuresResponse {
    ok: bool,
    command: &'static str,
    failures: Vec<crate::observability::FailureRecord>,
}

#[derive(Debug, Serialize)]
struct AuditSummaryResponse {
    ok: bool,
    command: &'static str,
    entry_count: usize,
}

#[derive(Debug, Serialize)]
struct AuditEntriesResponse {
    ok: bool,
    command: &'static str,
    mode: &'static str,
    entry_count: usize,
    entries: Vec<AuditEntry>,
}

#[derive(Debug, Serialize)]
struct AuditExportResponse {
    ok: bool,
    command: &'static str,
    export: ComplianceFormat,
    entry_count: usize,
    path: String,
}

fn print_json<T: Serialize>(value: &T) -> Result<(), Error> {
    crate::commands::output::print_json(value, "audit")
}

/// Inspect and export the vault audit log.
///
/// With no flags, prints a summary of the audit log. With `show_all_logs` or
/// `show_recovery_log`, prints the matching entries as JSON. Filters
/// (`filter_key`, `filter_user`, `filter_start`, `filter_end`) narrow the set.
/// Compliance exports (`export_soc2` / `export_pcidss` / `export_hipaa`) write
/// the filtered entries as a JSON evidence file tagged with the framework.
pub fn cmd_audit(
    args: AuditArgs,
    vault_path: &Path,
    passphrase: &str,
    json: bool,
) -> Result<(), Error> {
    // Failure journal is vault-independent — handle it first so it works even
    // when the vault is missing or the passphrase is wrong.
    if args.show_failures {
        let failures = crate::observability::read_failures();
        if json {
            print_json(&AuditFailuresResponse {
                ok: true,
                command: "audit",
                failures,
            })?;
        } else {
            if failures.is_empty() {
                println!("No recorded failures.");
            } else {
                for f in &failures {
                    println!(
                        "[{}] {} {:?} ({}): {}",
                        f.timestamp, f.code, f.severity, f.command, f.message
                    );
                }
            }
        }
        return Ok(());
    }

    let entries = load_audit_log(vault_path, passphrase)?;

    let filtered = filter_entries(entries, &args);

    // Count how many compliance exports were requested; only one is honored.
    let requested: Vec<&str> = [
        args.export_soc2.as_ref().map(|_| "soc2"),
        args.export_pcidss.as_ref().map(|_| "pcidss"),
        args.export_hipaa.as_ref().map(|_| "hipaa"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if requested.len() > 1 {
        return Err(Error::ComplianceExportFailed {
            framework: requested.join("+"),
            details: "only one compliance export may be requested per invocation".to_string(),
        });
    }

    // Compliance exports take precedence when present.
    if let Some(path) = &args.export_soc2 {
        return export_compliance(&filtered, ComplianceFormat::SOC2, path, json, args.force);
    }
    if let Some(path) = &args.export_pcidss {
        return export_compliance(
            &filtered,
            ComplianceFormat::PciDss {
                version: "4.0".to_string(),
            },
            path,
            json,
            args.force,
        );
    }
    if let Some(path) = &args.export_hipaa {
        return export_compliance(
            &filtered,
            ComplianceFormat::Hipaa {
                section: "164.312".to_string(),
            },
            path,
            json,
            args.force,
        );
    }

    // Display modes.
    if args.show_recovery_log {
        if args.show_all_logs {
            eprintln!("Warning: --show-all-logs is ignored because --show-recovery-log was given.");
        }
        if any_filter_set(&args) {
            eprintln!("Warning: audit filters are ignored with --show-failures/--show-recovery-log display modes.");
        }
        let recovery: Vec<AuditEntry> = filtered
            .iter()
            .filter(|e| matches!(e.operation, Operation::Recover { .. }))
            .cloned()
            .collect();
        print_entries(&recovery, json, "recovery_log")?;
        return Ok(());
    }

    if args.show_all_logs {
        if any_filter_set(&args) {
            eprintln!("Warning: audit filters are ignored with --show-recovery-log/--show-all-logs display modes.");
        }
        print_entries(&filtered, json, "all_logs")?;
        return Ok(());
    }

    // Default: summary.
    if json {
        print_json(&AuditSummaryResponse {
            ok: true,
            command: "audit",
            entry_count: filtered.len(),
        })?;
    } else {
        println!("Audit log: {} entries.", filtered.len());
        for e in &filtered {
            println!(
                "  [{}] {:?} key={} operator={} ts={}",
                e.entry_id, e.operation, e.key_id, e.operator, e.timestamp
            );
        }
    }
    Ok(())
}

/// Decrypt the vault and return its audit log.
fn load_audit_log(vault_path: &Path, passphrase: &str) -> Result<Vec<AuditEntry>, Error> {
    let handle = VaultHandle::open(vault_path, passphrase)?;
    Ok(handle.data().audit_log.clone())
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

/// Print entries — human-readable list or pretty JSON depending on `json`.
fn print_entries(entries: &[AuditEntry], json: bool, mode: &'static str) -> Result<(), Error> {
    if json {
        print_json(&AuditEntriesResponse {
            ok: true,
            command: "audit",
            mode,
            entry_count: entries.len(),
            entries: entries.to_vec(),
        })?;
    } else {
        println!("Audit log: {} entries.", entries.len());
        for e in entries {
            println!(
                "  [{}] {:?} key={} operator={} ts={}",
                e.entry_id, e.operation, e.key_id, e.operator, e.timestamp
            );
        }
    }
    Ok(())
}

/// Write filtered entries as a compliance evidence file.
fn export_compliance(
    entries: &[AuditEntry],
    format: ComplianceFormat,
    path: &Path,
    json: bool,
    force: bool,
) -> Result<(), Error> {
    // Refuse to clobber an existing evidence file unless --force is given.
    if !force && path.exists() {
        return Err(Error::FileAlreadyExists(path.to_path_buf()));
    }
    let evidence = serde_json::json!({
        "format": format,
        "entry_count": entries.len(),
        "entries": entries,
    });
    let serialized =
        serde_json::to_string_pretty(&evidence).map_err(|e| Error::IoError(e.to_string()))?;
    crate::vault_handle::atomic_write(path, serialized.as_bytes())?;
    if json {
        print_json(&AuditExportResponse {
            ok: true,
            command: "audit",
            export: format,
            entry_count: entries.len(),
            path: path.display().to_string(),
        })?;
    } else {
        println!(
            "Exported {} audit entries as {:?} evidence to {}.",
            entries.len(),
            format,
            path.display()
        );
    }
    Ok(())
}

/// True if any audit filter flag is set.
fn any_filter_set(args: &AuditArgs) -> bool {
    args.filter_key.is_some()
        || args.filter_user.is_some()
        || args.filter_start.is_some()
        || args.filter_end.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ShardArgs;
    use crate::commands::shard::cmd_shard;
    use crate::crypto::derive_vault_key;
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
            ciphertext: enc.ciphertext.clone(),
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
            force: false,
            expires: None,
        };
        cmd_shard(args, &vault_path, &passphrase, false).unwrap();

        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: false,
            show_failures: false,
            filter_key: None,
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: None,
            export_pcidss: None,
            export_hipaa: None,
            force: false,
        };
        let result = cmd_audit(audit_args, &vault_path, &passphrase, false);
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
            force: false,
            expires: None,
        };
        cmd_shard(args, &vault_path, &passphrase, false).unwrap();

        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: true,
            show_failures: false,
            filter_key: None,
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: None,
            export_pcidss: None,
            export_hipaa: None,
            force: false,
        };
        let result = cmd_audit(audit_args, &vault_path, &passphrase, false);
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
            force: false,
            expires: None,
        };
        cmd_shard(args, &vault_path, &passphrase, false).unwrap();

        let out = dir.path().join("soc2.json");
        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: false,
            show_failures: false,
            filter_key: None,
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: Some(out.clone()),
            export_pcidss: None,
            export_hipaa: None,
            force: false,
        };
        cmd_audit(audit_args, &vault_path, &passphrase, false).unwrap();

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
            force: false,
            expires: None,
        };
        cmd_shard(args, &vault_path, &passphrase, false).unwrap();

        let out = dir.path().join("hipaa.json");
        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: false,
            show_failures: false,
            filter_key: None,
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: None,
            export_pcidss: None,
            export_hipaa: Some(out.clone()),
            force: false,
        };
        cmd_audit(audit_args, &vault_path, &passphrase, false).unwrap();

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
            force: false,
            expires: None,
        };
        cmd_shard(args, &vault_path, &passphrase, false).unwrap();

        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: true,
            show_failures: false,
            filter_key: Some("master".to_string()),
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: None,
            export_pcidss: None,
            export_hipaa: None,
            force: false,
        };
        // Should still succeed and not panic.
        let result = cmd_audit(audit_args, &vault_path, &passphrase, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_audit_missing_vault() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.vault");
        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: false,
            show_failures: false,
            filter_key: None,
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: None,
            export_pcidss: None,
            export_hipaa: None,
            force: false,
        };
        let result = cmd_audit(audit_args, &missing, "x", false);
        assert!(matches!(result, Err(Error::VaultNotFound(_))));
    }

    #[test]
    fn test_audit_show_failures_reads_journal() {
        // show_failures must work even with a missing vault (vault-independent).
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.vault");
        let audit_args = AuditArgs {
            show_recovery_log: false,
            show_all_logs: false,
            show_failures: true,
            filter_key: None,
            filter_user: None,
            filter_start: None,
            filter_end: None,
            export_soc2: None,
            export_pcidss: None,
            export_hipaa: None,
            force: false,
        };
        let result = cmd_audit(audit_args, &missing, "x", false);
        assert!(result.is_ok());
    }
}
