// SPDX-License-Identifier: Apache-2.0

//! Landlock privilege drop (spec REV 3 §5.5, NetWatch pattern).
//!
//! The relay parses hostile traffic; after its listener is bound and its
//! state loaded, it needs nothing but read/write access to its home
//! directory. `restrict_to_home` drops into a Landlock domain that
//! allows ONLY the home dir — a parser hole cannot exfiltrate or trash
//! anything else on the host.
//!
//! Best-effort by design: on kernels without Landlock (or without the
//! targeted ABI) this returns `NotEnforced` and the caller logs a
//! warning and continues. Hard-failing would make the relay undeployable
//! on hosts without the LSM.
//!
//! **Provenance:** fresh implementation after NetWatch's Landlock-drop
//! rationale (spec §5.5); no code carried over.
//!
//! ## Semantics
//!
//! * Enforcement is per-thread and inherited by descendants: call this
//!   on the thread that keeps serving. Landlock can never be lifted once
//!   applied, so call it AFTER bind + state load.
//! * The socket survives the drop: an already-bound TCP listener is not
//!   a filesystem object.
//! * Atomic persistence (eviction set) works: temp file + rename stay
//!   inside the allowed home dir.

use std::fs::File;
use std::path::Path;

use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};

use crate::error::{NetworkError, Result};

/// Outcome of a sandbox attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxStatus {
    /// Landlock domain enforced: only the allow-listed paths reachable.
    Enforced,
    /// Not enforced (no kernel support, ABI mismatch, ...). Diagnostic
    /// reason included; the caller decides whether to continue.
    NotEnforced(String),
}

/// Targeted Landlock ABI. V3 (kernel ≥ 6.2) covers every filesystem
/// right the relay needs, including `TRUNCATE` for atomic rewrites.
/// Older kernels simply report `NotEnforced` instead of failing.
const SANDBOX_ABI: ABI = ABI::V3;

/// Restrict the calling thread (and descendants) to read/write access
/// under `home` only. Returns `NotEnforced` — not an error — when the
/// kernel cannot apply the ruleset.
///
/// Errors are reserved for genuinely broken setups (e.g. `home` does
/// not exist), which the caller should surface at startup.
pub fn restrict_to_home(home: &Path) -> Result<SandboxStatus> {
    // PathBeneath takes an fd (AsFd), not a path: open the home dir.
    // This doubles as the existence check — a missing home errors here.
    let home_fd = File::open(home)
        .map_err(|e| NetworkError::Transport(format!("sandbox home {}: {e}", home.display())))?;
    // BestEffort: unsupported features degrade to NotEnforced instead
    // of hard-erroring (e.g. kernels without the ABI, containers whose
    // seccomp profile blocks the landlock syscalls). ANY landlock error
    // also degrades — a broken sandbox is not worth failing startup.
    let access = AccessFs::from_all(SANDBOX_ABI);
    // Each landlock step has its own error type; erase to String and
    // degrade on any failure.
    let restriction = (|| -> std::result::Result<landlock::RestrictionStatus, String> {
        let created = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(access)
            .map_err(|e| e.to_string())?
            .create()
            .map_err(|e| e.to_string())?;
        let added = created
            .add_rules(std::iter::once(Ok::<_, landlock::RulesetError>(
                PathBeneath::new(home_fd, access),
            )))
            .map_err(|e| e.to_string())?;
        added.restrict_self().map_err(|e| e.to_string())
    })();
    Ok(map_status(restriction.map(|s| s.ruleset)))
}

/// Map a Landlock enforcement result to our status. Pure so the
/// degraded (kernel-without-Landlock) paths are unit-testable without
/// needing a Landlock-less host at integration time.
fn map_status(result: std::result::Result<RulesetStatus, String>) -> SandboxStatus {
    match result {
        Ok(RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced) => {
            SandboxStatus::Enforced
        }
        Ok(RulesetStatus::NotEnforced) => SandboxStatus::NotEnforced("ruleset NotEnforced".into()),
        Err(e) => SandboxStatus::NotEnforced(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonexistent_home_errors() {
        // A rule for a missing path is a broken setup, not degradation.
        let res = restrict_to_home(Path::new("/nonexistent/origin-relay-test-xyz"));
        assert!(res.is_err(), "expected error, got {res:?}");
    }

    /// Enforcement test runs on a dedicated OS thread: Landlock is
    /// per-thread, so the restriction dies with the thread and cannot
    /// poison sibling tests on the tokio worker pool.
    #[test]
    fn sandbox_enforced_or_degraded_in_child_thread() {
        // The outside dir must exist BEFORE the sandbox is applied:
        // creating it afterwards would fail (correctly) with EACCES.
        let outside = tempfile::tempdir().unwrap();
        let outside_path = outside.path().to_path_buf();

        let handle = std::thread::spawn(move || {
            let home = tempfile::tempdir().unwrap();
            let status = restrict_to_home(home.path()).unwrap();

            // Inside the allow-list: always fine.
            std::fs::write(home.path().join("ok.bin"), b"x").expect("home write");

            // Outside: must fail when enforced.
            let outside_write = std::fs::write(outside_path.join("denied.bin"), b"x");

            (status, outside_write.is_err())
        });
        let (status, outside_denied) = handle.join().unwrap();
        match status {
            SandboxStatus::Enforced => {
                assert!(
                    outside_denied,
                    "writes outside the sandbox home must be denied"
                );
            }
            SandboxStatus::NotEnforced(reason) => {
                // Degraded path (no kernel Landlock, blocked syscalls):
                // outside write succeeds, reason must be diagnostic.
                assert!(!reason.is_empty());
                assert!(!outside_denied, "no sandbox means writes must succeed");
            }
        }
    }

    #[test]
    fn map_status_degraded_arms() {
        // Exercises lines 97-100 without needing a Landlock-less host.
        assert_eq!(
            map_status(Ok(RulesetStatus::NotEnforced)),
            SandboxStatus::NotEnforced("ruleset NotEnforced".into())
        );
        assert_eq!(
            map_status(Err("seccomp blocked landlock".to_string())),
            SandboxStatus::NotEnforced("seccomp blocked landlock".to_string())
        );
        assert_eq!(
            map_status(Ok(RulesetStatus::FullyEnforced)),
            SandboxStatus::Enforced
        );
        assert_eq!(
            map_status(Ok(RulesetStatus::PartiallyEnforced)),
            SandboxStatus::Enforced
        );
    }

    #[test]
    fn sandbox_status_variants_distinct() {
        assert_ne!(
            SandboxStatus::Enforced,
            SandboxStatus::NotEnforced("x".into())
        );
        assert_eq!(
            SandboxStatus::NotEnforced("y".into()),
            SandboxStatus::NotEnforced("y".into())
        );
    }
}
