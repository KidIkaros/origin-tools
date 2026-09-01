// SPDX-License-Identifier: Apache-2.0

//! Bounded per-entry replay-nonce ledger for OCRA challenge-response
//! codes (`origin-pass code --ocra`).
//!
//! RFC 6287 §8.2 IC9: when a suite does not include a counter or
//! timestamp, a captured (challenge, response) pair can be replayed.
//! The ledger records the fingerprint (SHA3-256 over the challenge
//! bytes and counter) of every challenge used per vault entry, and
//! refuses to re-issue a response for an already-used challenge unless
//! the caller explicitly opts out (`--force`).
//!
//! The ledger is a JSON file living next to the vault
//! (`<vault>.ocra-ledger.json`). It is **not** a security boundary —
//! it is a convenience guard that catches accidental replay (the same
//! challenge typed twice, or a script loop reusing a challenge). A
//! motivated attacker with the ledger can delete it; the vault itself
//! remains the source of truth.
//!
//! The ledger is bounded: each entry keeps only the most recent
//! [`MAX_USES_PER_ENTRY`] fingerprints.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// How many recent challenge uses to remember per entry.
pub const MAX_USES_PER_ENTRY: usize = 64;

/// Ledger wire format version.
const LEDGER_VERSION: u32 = 1;

/// One recorded use of a challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeUse {
    /// SHA3-256 fingerprint (hex) of `challenge_bytes ‖ counter(BE)`.
    pub fp: String,
    /// Unix seconds when the code was issued.
    pub used_at: i64,
}

/// On-disk ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcraLedger {
    pub version: u32,
    /// entry name → most recent uses (newest last).
    pub entries: BTreeMap<String, Vec<ChallengeUse>>,
}

impl Default for OcraLedger {
    fn default() -> Self {
        Self {
            version: LEDGER_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

/// Ledger file path for a given vault path: `<vault>.ocra-ledger.json`.
pub fn ledger_path(vault_path: &Path) -> std::path::PathBuf {
    let mut name = vault_path.as_os_str().to_owned();
    name.push(".ocra-ledger.json");
    std::path::PathBuf::from(name)
}

/// Fingerprint of a challenge use: `SHA3-256(challenge ‖ counter BE)`.
pub fn challenge_fingerprint(challenge: &[u8], counter: u64) -> String {
    let mut input = Vec::with_capacity(challenge.len() + 8);
    input.extend_from_slice(challenge);
    input.extend_from_slice(&counter.to_be_bytes());
    hex::encode(origin_crypto_sdk::sha3_256(&input))
}

/// Load the ledger for `vault_path`. A missing file is an empty ledger;
/// a corrupt file is an error (surfaced rather than silently reset —
/// the user may want to know their replay history was lost).
pub fn load_ledger(vault_path: &Path) -> Result<OcraLedger, String> {
    let path = ledger_path(vault_path);
    if !path.exists() {
        return Ok(OcraLedger::default());
    }
    let raw = std::fs::read(&path)
        .map_err(|e| format!("cannot read OCRA ledger {}: {e}", path.display()))?;
    let ledger: OcraLedger = serde_json::from_slice(&raw)
        .map_err(|e| format!("OCRA ledger {} is corrupt: {e}", path.display()))?;
    if ledger.version != LEDGER_VERSION {
        return Err(format!(
            "OCRA ledger {} has unknown version {} (expected {LEDGER_VERSION})",
            path.display(),
            ledger.version
        ));
    }
    Ok(ledger)
}

/// Record a challenge use. Returns `Ok(true)` if this was a **replay**
/// (fingerprint already present) and the ledger was **not** modified;
/// `Ok(false)` if the use was recorded. When `force` is true a replay is
/// still recorded (newest occurrence wins) and `Ok(true)` is returned
/// so callers can emit a warning.
pub fn record_use(
    vault_path: &Path,
    entry: &str,
    fp: &str,
    used_at: i64,
    force: bool,
) -> Result<bool, String> {
    let mut ledger = load_ledger(vault_path)?;
    let uses = ledger.entries.entry(entry.to_string()).or_default();

    let is_replay = uses.iter().any(|u| u.fp == fp);
    if is_replay && !force {
        return Ok(true);
    }

    uses.push(ChallengeUse {
        fp: fp.to_string(),
        used_at,
    });
    while uses.len() > MAX_USES_PER_ENTRY {
        uses.remove(0);
    }

    let json = serde_json::to_vec_pretty(&ledger)
        .map_err(|e| format!("OCRA ledger serialize failed: {e}"))?;
    origin_common::io::atomic_write(&ledger_path(vault_path), &json)?;
    Ok(is_replay)
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_vault_path() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("test.vault");
        // Persist a marker so the vault path is a real file (not required
        // by the ledger, but keeps the fixture honest).
        std::fs::write(&vault, b"OVLT").unwrap();
        (dir, vault)
    }

    #[test]
    fn first_use_recorded_second_is_replay() {
        let (_dir, vault) = temp_vault_path();
        let fp = challenge_fingerprint(b"00000000", 0);
        assert!(!record_use(&vault, "bank", &fp, 1, false).unwrap());
        assert!(record_use(&vault, "bank", &fp, 2, false).unwrap());
    }

    #[test]
    fn distinct_challenges_are_not_replays() {
        let (_dir, vault) = temp_vault_path();
        let fp1 = challenge_fingerprint(b"00000000", 0);
        let fp2 = challenge_fingerprint(b"11111111", 0);
        assert!(!record_use(&vault, "bank", &fp1, 1, false).unwrap());
        assert!(!record_use(&vault, "bank", &fp2, 2, false).unwrap());
        // Same challenge, different counter → different response → not a replay.
        let fp3 = challenge_fingerprint(b"00000000", 1);
        assert!(!record_use(&vault, "bank", &fp3, 3, false).unwrap());
    }

    #[test]
    fn force_records_replay() {
        let (_dir, vault) = temp_vault_path();
        let fp = challenge_fingerprint(b"00000000", 0);
        assert!(!record_use(&vault, "bank", &fp, 1, false).unwrap());
        let replay = record_use(&vault, "bank", &fp, 2, true).unwrap();
        assert!(replay, "force must still report the replay");
        // Ledger persisted both uses.
        let ledger = load_ledger(&vault).unwrap();
        assert_eq!(ledger.entries["bank"].len(), 2);
    }

    #[test]
    fn entries_are_per_name() {
        let (_dir, vault) = temp_vault_path();
        let fp = challenge_fingerprint(b"00000000", 0);
        assert!(!record_use(&vault, "bank-a", &fp, 1, false).unwrap());
        assert!(!record_use(&vault, "bank-b", &fp, 2, false).unwrap());
    }

    #[test]
    fn ledger_is_bounded() {
        let (_dir, vault) = temp_vault_path();
        for i in 0..(MAX_USES_PER_ENTRY + 20) {
            let fp = challenge_fingerprint(format!("{i:08}").as_bytes(), 0);
            assert!(!record_use(&vault, "bank", &fp, i as i64, false).unwrap());
        }
        let ledger = load_ledger(&vault).unwrap();
        assert_eq!(ledger.entries["bank"].len(), MAX_USES_PER_ENTRY);
    }

    #[test]
    fn corrupt_ledger_is_an_error_not_a_silent_reset() {
        let (_dir, vault) = temp_vault_path();
        let path = ledger_path(&vault);
        std::fs::write(&path, b"{not json").unwrap();
        let err = load_ledger(&vault).expect_err("corrupt ledger must error");
        assert!(err.contains("corrupt"));
    }
}
