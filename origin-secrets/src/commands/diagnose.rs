//! Secret-free support diagnostics for the CLI product.

use crate::cli::DiagnoseArgs;
use crate::error::Error;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct DiagnosticBundle {
    schema_version: u8,
    product: &'static str,
    version: &'static str,
    os: &'static str,
    arch: &'static str,
    vault_path: String,
    vault_exists: bool,
    vault_bytes: Option<u64>,
    vault_readable: bool,
    shares_dir: String,
    shares_dir_exists: bool,
    share_file_count: usize,
    failure_count: usize,
    notes: Vec<&'static str>,
}

/// Collect support information without opening or decrypting a vault.
pub fn cmd_diagnose(args: DiagnoseArgs, vault_path: &Path, json: bool) -> Result<(), Error> {
    let shares_dir = vault_path
        .parent()
        .map(|p| p.join("shares"))
        .unwrap_or_else(|| Path::new("shares").to_path_buf());
    let vault_metadata = std::fs::metadata(vault_path).ok();
    let vault_exists = vault_metadata.is_some();
    let vault_readable = std::fs::File::open(vault_path).is_ok();
    let share_file_count = if shares_dir.is_dir() {
        std::fs::read_dir(&shares_dir)
            .map_err(|e| Error::IoError(format!("read shares directory: {e}")))?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().and_then(|s| s.to_str()) == Some("json"))
            .count()
    } else {
        0
    };
    let failures = crate::observability::read_failures();
    let mut notes = Vec::new();
    if !vault_exists {
        notes.push("vault file is not present");
    }
    if vault_exists && !vault_readable {
        notes.push("vault file could not be opened; check permissions");
    }
    if !shares_dir.is_dir() {
        notes.push("shares directory is not present");
    }
    if !failures.is_empty() {
        notes.push("failure journal contains recorded failures");
    }

    let bundle = DiagnosticBundle {
        schema_version: 1,
        product: "origin-secrets",
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        vault_path: redact_home(vault_path),
        vault_exists,
        vault_bytes: vault_metadata.map(|m| m.len()),
        vault_readable,
        shares_dir: redact_home(&shares_dir),
        shares_dir_exists: shares_dir.is_dir(),
        share_file_count,
        failure_count: failures.len(),
        notes,
    };

    let wrote_file = args.out.is_some();
    if let Some(out) = args.out {
        if !args.force && out.exists() {
            return Err(Error::FileAlreadyExists(out));
        }
        let serialized = serde_json::to_string_pretty(&bundle)
            .map_err(|e| Error::IoError(format!("serialize diagnostic bundle: {e}")))?;
        crate::vault_handle::atomic_write(&out, serialized.as_bytes())?;
        if !json {
            println!("Diagnostic bundle written to: {}", out.display());
        }
    }

    if json {
        crate::commands::output::print_json(&bundle, "diagnose")?;
    } else if !wrote_file {
        println!("origin-secrets {}", bundle.version);
        println!("Vault present: {}", bundle.vault_exists);
        println!("Vault readable: {}", bundle.vault_readable);
        println!("Share files: {}", bundle.share_file_count);
        println!("Recorded failures: {}", bundle.failure_count);
        for note in &bundle.notes {
            println!("Note: {note}");
        }
    }
    Ok(())
}

fn redact_home(path: &Path) -> String {
    let value = path.display().to_string();
    if let Ok(home) = std::env::var("HOME") {
        if let Some(rest) = value.strip_prefix(&home) {
            return format!("$HOME{rest}");
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn diagnose_missing_vault_is_secret_free_and_actionable() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("secrets.vault");
        let args = DiagnoseArgs {
            out: None,
            force: false,
        };
        assert!(cmd_diagnose(args, &vault, false).is_ok());
    }
}
