//! Failure observability — a lightweight, unencrypted failure journal.
//!
//! The vault's audit log records *successful* operations, but a failure often
//! happens *before* a vault is available (e.g. `PassphraseRequired`,
//! `VaultNotFound`) or is precisely the event we most need to see later
//! (tamper, signature failure). Those failures currently die in stderr and are
//! invisible post-hoc. This module appends every failure as a JSON line to
//! `~/.origin/failures.log` (best-effort) so failures are queryable via
//! `origin-secrets audit --show-failures`.

use crate::error::{Error, Severity};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A single recorded failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureRecord {
    pub timestamp: String,
    pub code: String,
    pub severity: Severity,
    pub command: String,
    pub message: String,
}

/// Path to the failure journal under the origin home.
fn journal_path() -> PathBuf {
    let home = std::env::var("ORIGIN_HOME").unwrap_or_else(|_| {
        format!(
            "{}/.origin",
            std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
        )
    });
    PathBuf::from(home).join("failures.log")
}

/// Record a failure to the journal (best-effort; write errors are ignored so
/// failure logging can never crash the main flow).
pub fn record_failure(err: &Error, command: &str) {
    let record = FailureRecord {
        timestamp: chrono_timestamp(),
        code: err.code().to_string(),
        severity: err.severity(),
        command: command.to_string(),
        message: err.to_string(),
    };
    if let Ok(json) = serde_json::to_string(&record) {
        let line = format!("{}\n", json);
        let path = journal_path();
        // Ensure the parent directory exists; otherwise the journal is silently
        // inoperative on a fresh install (the file create() does not mkdir parents).
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
    }
}

/// Read and parse the failure journal (empty vec if absent/unreadable).
pub fn read_failures() -> Vec<FailureRecord> {
    let path = journal_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    raw.lines()
        .filter_map(|l| serde_json::from_str::<FailureRecord>(l).ok())
        .collect()
}

/// ISO-8601-ish timestamp without external time crates.
fn chrono_timestamp() -> String {
    // std::time::SystemTime -> seconds since epoch, formatted as UTC datetime.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Format as YYYY-MM-DDTHH:MM:SSZ (UTC-naive; sufficient for triage).
    let (y, mo, d, h, mi, s) = epoch_to_ymd_hms(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
}

/// Public helper: current UTC timestamp as a correctly leap-year-handled
/// ISO-8601 string. Reused by other commands (e.g. export) so there is a
/// single source of truth for calendar conversion.
pub fn epoch_to_ymd_hms_now() -> String {
    chrono_timestamp()
}

/// Convert Unix seconds to a calendar breakdown (UTC, proleptic Gregorian).
fn epoch_to_ymd_hms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = secs / 86400;
    let rem = secs % 86400;
    let h = (rem / 3600) as u32;
    let mi = ((rem % 3600) / 60) as u32;
    let s = (rem % 60) as u32;

    // Days since 1970-01-01 -> YMD (handles leap years).
    let mut y = 1970u32;
    let mut d = days as i64;
    loop {
        let leap = if y.is_multiple_of(4) && !y.is_multiple_of(100) || y.is_multiple_of(400) {
            366
        } else {
            365
        };
        if d < leap as i64 {
            break;
        }
        d -= leap as i64;
        y += 1;
    }
    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = y.is_multiple_of(4) && !y.is_multiple_of(100) || y.is_multiple_of(400);
    let mut mo = 1u32;
    let mut rem_d = d as u32;
    for (i, md) in month_days.iter().enumerate() {
        let mut dim = *md;
        if i == 1 && leap {
            dim = 29;
        }
        if rem_d < dim {
            mo = (i + 1) as u32;
            break;
        }
        rem_d -= dim;
    }
    (y, mo, rem_d + 1, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn test_failure_record_serializes() {
        let e = Error::PassphraseRequired;
        let r = FailureRecord {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            code: e.code().to_string(),
            severity: e.severity(),
            command: "init".to_string(),
            message: e.to_string(),
        };
        assert_eq!(r.code, "PASSPHRASE_REQUIRED");
        assert_eq!(r.severity, Severity::Warn);
        let json = serde_json::to_string(&r).unwrap();
        let back: FailureRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.code, "PASSPHRASE_REQUIRED");
    }

    #[test]
    fn test_epoch_to_ymd_hms_known() {
        // 2026-01-01T00:00:00Z ≈ 1767225600 (proleptic; test only the shape).
        let (y, mo, d, h, mi, s) = epoch_to_ymd_hms(1767225600);
        assert_eq!((h, mi, s), (0, 0, 0));
        assert_eq!((y, mo, d), (2026, 1, 1));
    }
}
