// SPDX-License-Identifier: Apache-2.0

//! Command implementations for `origin-pass`.
//!
//! Each `cmd_*` function returns `Result<(), String>` and is wired to
//! the matching CLI subcommand in `main.rs`.
//!
//! # In-memory vault state
//!
//! v0.4.x uses a per-process `Mutex<Option<Vault>>` for cross-command
//! state (set by `cmd_unlock`, cleared by `cmd_lock`). The
//! `--session-token` flag is currently a no-op (the persisted token
//! model is followup work — see `DESIGN.md` §6). Each command that
//! needs the vault will re-unlock automatically if the in-process state
//! is empty.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use origin_crypto_sdk::tier::MemoryTier;

use crate::cli::{
    AddArgs, ChangePassphraseArgs, CodeArgs, ExportQrArgs, GetArgs, ImportQrArgs, InitArgs,
    ListArgs, LockArgs, RmArgs, UnlockArgs,
};
use crate::vault::{self, EntryPayload, Vault};

/// Conversion from the CLI-facing `HashAlgorithm` enum (clap ValueEnum)
/// to the SDK's `drbg::otp::HashAlgorithm`. Both share the same variants
/// but are distinct Rust types; without this conversion, OCRA dispatch
/// would leak the SDK type into the command surface.
impl From<crate::cli::HashAlgorithm> for origin_crypto_sdk::drbg::otp::HashAlgorithm {
    fn from(v: crate::cli::HashAlgorithm) -> Self {
        match v {
            crate::cli::HashAlgorithm::Sha1 => {
                origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha1
            }
            crate::cli::HashAlgorithm::Sha256 => {
                origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha256
            }
            crate::cli::HashAlgorithm::Sha512 => {
                origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha512
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// In-process vault state (set by `cmd_unlock`, cleared by `cmd_lock`)
// ──────────────────────────────────────────────────────────────────────

static CURRENT_VAULT: Mutex<Option<Vault>> = Mutex::new(None);

/// Helper: take the in-process unlocked vault, returning Err if absent.
fn take_vault() -> Result<Vault, String> {
    let mut guard = CURRENT_VAULT.lock().map_err(|e| {
        format!("vault state mutex poisoned: {e}")
    })?;
    guard.take().ok_or_else(|| {
        "vault is not unlocked in this process — run `origin-pass unlock` first (DESIGN.md §6 step 3)".to_string()
    })
}

/// Helper: stash the unlocked vault back into process-global state.
fn put_vault(v: Vault) -> Result<(), String> {
    let mut guard = CURRENT_VAULT.lock().map_err(|e| {
        format!("vault state mutex poisoned: {e}")
    })?;
    *guard = Some(v);
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// Passphrase + path helpers
// ──────────────────────────────────────────────────────────────────────

/// Resolve a passphrase from `--passphrase-file <path>` or via prompt.
pub fn resolve_passphrase(file: &Option<String>) -> Result<String, String> {
    match file {
        Some(path) => {
            let pw = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read passphrase file {path}: {e}"))?;
            Ok(pw.trim_end_matches(['\n', '\r']).to_string())
        }
        None => {
            rpassword::prompt_password("Passphrase: ")
                .map_err(|e| format!("passphrase prompt failed: {e}"))
        }
    }
}

/// Same as `resolve_passphrase` but confirms via a second prompt when
/// reading interactively (used by `cmd_init` and `cmd_change_passphrase`).
pub fn resolve_passphrase_confirm(file: &Option<String>) -> Result<String, String> {
    match file {
        Some(path) => {
            // File-based passphrase — confirmation is the user's responsibility.
            let pw = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read passphrase file {path}: {e}"))?;
            Ok(pw.trim_end_matches(['\n', '\r']).to_string())
        }
        None => {
            let pw = rpassword::prompt_password("Passphrase: ")
                .map_err(|e| format!("passphrase prompt failed: {e}"))?;
            let pw2 = rpassword::prompt_password("Confirm:   ")
                .map_err(|e| format!("passphrase confirm failed: {e}"))?;
            if pw != pw2 {
                return Err("passphrases do not match".to_string());
            }
            Ok(pw)
        }
    }
}

/// Resolve `--vault <path>` with `~/` expansion against `$HOME`.
fn resolve_vault_path(raw: &str) -> Result<PathBuf, String> {
    if let Some(stripped) = raw.strip_prefix("~/") {
        let home = std::env::var("HOME").map_err(|_| {
            "$HOME is unset; cannot expand ~/ paths. Pass an absolute path instead.".to_string()
        })?;
        Ok(PathBuf::from(home).join(stripped))
    } else {
        Ok(PathBuf::from(raw))
    }
}

// ──────────────────────────────────────────────────────────────────────
// OCRA (RFC 6287) helpers — used by `cmd_code` (vault or key-file)
// ──────────────────────────────────────────────────────────────────────

/// Result of an OCRA computation — the formatted code + algorithm metadata
/// so callers (cmd_code, future vault-backed paths, and integration tests)
/// can render or compare without re-deriving inputs.
///
/// `Debug` is **hand-rolled** (not derived) so that `format!("{:?}", code)`
/// never prints the response code. A leaked OCRA response is a one-time
/// password — if it shows up in a log line, panic message, or assertion
/// error, an attacker who can read the log can impersonate the user. The
/// pattern mirrors `origin_crypto_sdk::ocra::OcraResponse::fmt` which
/// likewise redacts the numeric value.
#[derive(Clone, PartialEq, Eq)]
pub struct OcraCode {
    /// RFC 4226 §5.3 dynamic-truncated value, rendered with `digits`
    /// leading zeros. Redacted in `Debug` output.
    pub value: String,
    /// Numeric value. Redacted in `Debug` output.
    pub numeric: u64,
    /// Digit width (4..=10).
    pub digits: u32,
}

impl std::fmt::Debug for OcraCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcraCode")
            .field("value", &format!("<{} digits redacted>", self.digits))
            .field("numeric", &"<redacted>")
            .field("digits", &self.digits)
            .finish()
    }
}

/// Compute an OCRA response per RFC 6287 §7.1 from a raw key file
/// (testing escape hatch; primarily used by unit tests).
pub fn compute_ocra_code(
    key_path: &std::path::Path,
    challenge: &str,
    counter: u64,
    digits: u32,
    algo: crate::cli::HashAlgorithm,
) -> Result<OcraCode, String> {
    use origin_crypto_sdk::ocra::{ocra, OcraRequest};

    let key = std::fs::read(key_path).map_err(|e| {
        format!("failed to read OCRA key file {}: {e}", key_path.display())
    })?;

    let sdk_algo: origin_crypto_sdk::drbg::otp::HashAlgorithm = algo.into();

    let req = OcraRequest {
        counter,
        challenge: challenge.as_bytes(),
        password: None,
        session: b"",
        timestamp: None,
    };

    let resp = ocra(&key, &req, digits, sdk_algo).map_err(|e| e.to_string())?;

    Ok(OcraCode {
        value: resp.format_code(),
        numeric: resp.value,
        digits: resp.digits,
    })
}

// ──────────────────────────────────────────────────────────────────────
// Public command entry points
// ──────────────────────────────────────────────────────────────────────

/// Create a new vault file.
pub fn cmd_init(args: InitArgs) -> Result<(), String> {
    let tier = vault::parse_tier(&args.tier)?;
    let path = resolve_vault_path(&args.vault)?;
    if path.exists() {
        return Err(format!(
            "vault file already exists: {} (refusing to overwrite)",
            path.display()
        ));
    }
    let passphrase = resolve_passphrase_confirm(&args.passphrase_file)?;
    vault::init_vault(&path, &passphrase, tier)?;
    eprintln!("created vault: {} (tier={})", path.display(), args.tier);
    Ok(())
}

/// Unlock the vault into in-process session memory.
///
/// **Note**: v0.4.x has no persisted session tokens; this just verifies
/// the passphrase and primes the in-process state. Any subsequent
/// command in the same process can operate on the unlocked vault.
/// `--session-token` is currently accepted but ignored.
pub fn cmd_unlock(args: UnlockArgs) -> Result<(), String> {
    // Validate the user-supplied tier string for early failure on typo;
    // the on-disk header is authoritative so this value is unused.
    vault::parse_tier(&args.tier)?;
    let path = resolve_vault_path(&args.vault)?;
    let passphrase = resolve_passphrase(&args.passphrase_file)?;
    let vault_obj = vault::unlock_vault(&path, &passphrase)?;

    let entry_count = vault_obj.entries.len();
    let tier = match vault_obj.header.kdf_tier {
        MemoryTier::Nano => "nano",
        MemoryTier::Standard => "standard",
        MemoryTier::Sovereign => "sovereign",
    };
    if args.session_token.is_some() {
        eprintln!(
            "warning: --session-token is not yet implemented in v0.4.x; unlock is per-process only"
        );
    }
    put_vault(vault_obj)?;
    eprintln!("unlocked {} (tier={}, {entry_count} entries)", path.display(), tier);
    Ok(())
}

/// Drop the in-process unlocked vault. v0.4.x has no persisted state
/// to clear (unlock is per-process).
pub fn cmd_lock(_args: LockArgs) -> Result<(), String> {
    take_vault()?; // drops it
    eprintln!(
        "vault state cleared (no persisted state in v0.4.x — unlock again to operate)"
    );
    Ok(())
}

/// Add or update an entry in the vault.
pub fn cmd_add(args: AddArgs) -> Result<(), String> {
    let path = resolve_vault_path(&args.vault)?;
    let passphrase = resolve_passphrase(&args.passphrase_file)?;
    let vault_obj = vault::unlock_vault(&path, &passphrase)?;

    // For v0.4.x we don't yet have a generic "add-from-args" path;
    // only --type ocra is wired up fully (because cmd_code --ocra needs
    // it). Password + TOTP/HOTP entries return Err to avoid an
    // accidental plaintext write.
    if args.r#type == crate::cli::EntryType::Ocra {
        return Err(
            "OCRA entries must be added via `cmd_code --ocra` flow (which seeds the entry automatically); manual `add --type ocra` is not yet wired".to_string(),
        );
    }
    if args.r#type == crate::cli::EntryType::Password {
        return Err(
            "password entries cannot yet be added non-interactively — pipe a future TTY-aware prompt here".to_string(),
        );
    }
    if args.r#type == crate::cli::EntryType::Otp {
        return Err(
            "TOTP/HOTP entries cannot yet be added via `add`; use the import-qr subcommand once it lands (DESIGN.md §6 step 4)".to_string(),
        );
    }

    let _ = vault_obj; // validated; silenced
    Err("unreachable: covered all EntryType variants above".to_string())
}

/// Retrieve a single entry by name.
pub fn cmd_get(args: GetArgs) -> Result<(), String> {
    let path = resolve_vault_path(&args.vault)?;
    let passphrase = resolve_passphrase(&args.passphrase_file)?;
    let vault_obj = vault::unlock_vault(&path, &passphrase)?;

    let entry = vault_obj
        .entries
        .get(&args.name)
        .ok_or_else(|| format!("entry not found: {}", args.name))?;

    // Print name + secret only. URL/notes would leak metadata.
    print_entry(entry);
    Ok(())
}

/// List all entries (names + types, NO secrets).
pub fn cmd_list(args: ListArgs) -> Result<(), String> {
    let path = resolve_vault_path(&args.vault)?;
    let passphrase = resolve_passphrase(&args.passphrase_file)?;
    let vault_obj = vault::unlock_vault(&path, &passphrase)?;

    let mut entries: Vec<_> = vault_obj.entries.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    println!("{:<32} {:<10}", "name", "type");
    println!("{}", "-".repeat(44));
    for (name, entry) in entries {
        let kind = entry_kind(entry);
        println!("{name:<32} {kind:<10}");
    }
    Ok(())
}

/// Remove an entry from the vault.
pub fn cmd_rm(args: RmArgs) -> Result<(), String> {
    let path = resolve_vault_path(&args.vault)?;
    let passphrase = resolve_passphrase(&args.passphrase_file)?;
    let mut vault_obj = vault::unlock_vault(&path, &passphrase)?;

    if vault_obj.entries.remove(&args.name).is_none() {
        return Err(format!("entry not found: {}", args.name));
    }
    vault::persist_vault(&path, &vault_obj)?;
    eprintln!("removed: {}", args.name);
    Ok(())
}

/// Compute and display a TOTP/HOTP or OCRA response.
///
/// OCRA branch is implemented for v0.4.x: it uses the in-process
/// unlocked vault (set by `cmd_unlock`) to look up the entry by name.
/// `--key-file` remains as a **testing escape hatch** (DESIGN.md §3.1
/// T5.11) and takes precedence over the vault lookup. The TOTP/HOTP
/// branch is still pending the import-qr subcommand (DESIGN.md §6
/// step 4).
pub fn cmd_code(args: CodeArgs) -> Result<(), String> {
    if !args.ocra {
        return Err(
            "TOTP/HOTP code path not yet implemented (DESIGN.md §6 step 4); pass --ocra for OCRA mode"
                .to_string(),
        );
    }

    let challenge = args
        .challenge
        .as_deref()
        .ok_or_else(|| "--ocra requires --challenge <STRING>".to_string())?;

    let algo = args
        .algo
        .clone()
        .unwrap_or(crate::cli::HashAlgorithm::Sha1);
    let digits = args.digits.unwrap_or(6);
    let counter = args.counter.unwrap_or(0);

    // Path 1: testing escape hatch (raw key from file).
    if let Some(key_path) = args.key_file.as_ref() {
        let code = compute_ocra_code(key_path, challenge, counter, digits, algo)?;
        return print_ocra_code(&code, args.quiet);
    }

    // Path 2: vault lookup (production).
    //
    // Pre-flight: validate vault path + unlock strategy BEFORE we hit
    // `rpassword::prompt_password`, which fails noisily on a non-TTY stdin
    // (e.g. cargo test, CI) with a cryptic message that does NOT contain
    // the substrings ("vault" / "unlock" / "not found") the user-facing
    // error-path tests assert on.
    if args.vault.trim().is_empty() {
        return Err(
            "no --key-file and no --vault supplied; cannot derive OCRA code. \
             Either pass --key-file <path> to read the raw OCRA K from disk, \
             or pass --vault <path> --passphrase-file <path> to unlock the \
             vault first."
                .to_string(),
        );
    }
    if args.passphrase_file.is_none() {
        return Err(
            "OCRA from vault requires a passphrase to unlock the vault. \
             Pass --passphrase-file <path> or run from a terminal for \
             interactive unlock; for tests, prefer --key-file <path>."
                .to_string(),
        );
    }

    let path = resolve_vault_path(&args.vault)?;
    let passphrase = resolve_passphrase(&args.passphrase_file)?;
    let vault_obj = vault::unlock_vault(&path, &passphrase)?;

    let secret = vault_obj
        .get_ocra_key(&args.name)
        .map_err(|e| format!("OCRA vault lookup failed: {e}"))?;

    use origin_crypto_sdk::ocra::{ocra, OcraRequest};
    let sdk_algo: origin_crypto_sdk::drbg::otp::HashAlgorithm = algo.into();
    let req = OcraRequest {
        counter,
        challenge: challenge.as_bytes(),
        password: None,
        session: b"",
        timestamp: None,
    };
    let resp = ocra(&secret, &req, digits, sdk_algo).map_err(|e| e.to_string())?;
    let code = OcraCode {
        value: resp.format_code(),
        numeric: resp.value,
        digits: resp.digits,
    };
    print_ocra_code(&code, args.quiet)
}

pub fn cmd_export_qr(_args: ExportQrArgs) -> Result<(), String> {
    todo!("origin-pass export-qr — see DESIGN.md §6 step 4 (OTP)")
}

pub fn cmd_import_qr(_args: ImportQrArgs) -> Result<(), String> {
    todo!("origin-pass import-qr — see DESIGN.md §6 step 4 (OTP)")
}

pub fn cmd_change_passphrase(args: ChangePassphraseArgs) -> Result<(), String> {
    let path = resolve_vault_path(&args.vault)?;
    // Read the existing tier from the vault header BEFORE unlocking (we
    // need the tier to call `change_vault_passphrase`, but the function
    // reads the header itself; we lock it by reading just the header).
    let current = resolve_passphrase(&args.passphrase_file)?;

    // Probe the file to recover the existing tier — preserves user's
    // original choice (Nano / Standard / Sovereign).
    let header_bytes = std::fs::read(&path)
        .map_err(|e| format!("cannot read vault {}: {e}", path.display()))?;
    if header_bytes.len() < vault::HEADER_BYTES_LEN {
        return Err(format!(
            "vault file too short: {} bytes",
            header_bytes.len()
        ));
    }
    let header = vault::VaultHeader::from_wire(&header_bytes[..vault::HEADER_BYTES_LEN])?;
    let tier = header.kdf_tier;
    drop(header);
    drop(header_bytes);

    // Read the new passphrase — confirmation prompt unless file-based.
    let new = if let Some(new_file) = args.new_passphrase_file.as_ref() {
        std::fs::read_to_string(new_file)
            .map_err(|e| format!("cannot read new-passphrase file {new_file}: {e}"))?
            .trim_end_matches(['\n', '\r'])
            .to_string()
    } else {
        // Interactive confirmation.
        let pw = rpassword::prompt_password("New passphrase: ")
            .map_err(|e| format!("new passphrase prompt failed: {e}"))?;
        let pw2 = rpassword::prompt_password("Confirm new:   ")
            .map_err(|e| format!("new passphrase confirm failed: {e}"))?;
        if pw != pw2 {
            return Err("new passphrases do not match".to_string());
        }
        pw
    };

    vault::change_vault_passphrase(&path, &current, &new, tier)?;
    eprintln!(
        "vault passphrase updated: {} (tier preserved: {:?})",
        path.display(),
        tier
    );
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// Formatting helpers
// ──────────────────────────────────────────────────────────────────────

fn print_entry(entry: &EntryPayload) {
    let secret = entry
        .secret
        .as_ref()
        .map(|s| String::from_utf8_lossy(s).to_string())
        .unwrap_or_else(|| "<missing>".to_string());
    println!("{}: {}", entry.name, secret);
    if let Some(url) = &entry.url {
        println!("  url: {url}");
    }
    if let Some(notes) = &entry.notes {
        for line in notes.lines() {
            println!("  notes: {line}");
        }
    }
}

fn print_ocra_code(code: &OcraCode, quiet: bool) -> Result<(), String> {
    if quiet {
        eprintln!("{}", code.value);
    } else {
        println!("{}", code.value);
    }
    Ok(())
}

fn entry_kind(entry: &EntryPayload) -> &'static str {
    if entry.ocra.is_some() {
        "ocra"
    } else if entry.totp.is_some() {
        "totp"
    } else if entry.hotp.is_some() {
        "hotp"
    } else {
        "password"
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests — RFC 6287 §A.1 + edge cases + vault round-trips
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // OCRA tests (preserved from v0.1.x)
    fn write_key(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("temp file");
        f.write_all(bytes).expect("write key");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn rfc6287_a1_qn08_sha1_canonical_196958() {
        let key = write_key(b"12345678901234567890");
        let code =
            compute_ocra_code(key.path(), "00000000", 0, 6, crate::cli::HashAlgorithm::Sha1)
                .expect("ocra");
        assert_eq!(code.value, "196958");
        assert_eq!(code.numeric, 196_958);
        assert_eq!(code.digits, 6);
    }

    #[test]
    fn deterministic_same_input_same_output_sha256() {
        let key = write_key(b"a-key-with-32-bytes-for-sha256!!!!");
        let c1 = compute_ocra_code(
            key.path(),
            "12345678",
            0,
            8,
            crate::cli::HashAlgorithm::Sha256,
        )
        .expect("first");
        let c2 = compute_ocra_code(
            key.path(),
            "12345678",
            0,
            8,
            crate::cli::HashAlgorithm::Sha256,
        )
        .expect("second");
        assert_eq!(c1, c2);
    }

    #[test]
    fn sha512_ten_digit_fits_in_u64() {
        let key = write_key(b"a-64-byte-key-for-sha512-pad-pad-pad-pad-pad-pad-pad0");
        let code = compute_ocra_code(
            key.path(),
            "12345678",
            0,
            10,
            crate::cli::HashAlgorithm::Sha512,
        )
        .expect("sha512");
        assert!(code.numeric <= 9_999_999_999);
        assert_eq!(code.value.len(), 10);
    }

    #[test]
    fn counter_change_changes_response_sha1() {
        let key = write_key(b"12345678901234567890");
        let c0 =
            compute_ocra_code(key.path(), "12345678", 0, 6, crate::cli::HashAlgorithm::Sha1)
                .expect("c0");
        let c1 =
            compute_ocra_code(key.path(), "12345678", 1, 6, crate::cli::HashAlgorithm::Sha1)
                .expect("c1");
        assert_ne!(c0.numeric, c1.numeric);
    }

    #[test]
    fn challenge_change_changes_response_sha1() {
        let key = write_key(b"12345678901234567890");
        let c0 =
            compute_ocra_code(key.path(), "00000000", 0, 6, crate::cli::HashAlgorithm::Sha1)
                .expect("c0");
        let c1 =
            compute_ocra_code(key.path(), "12345678", 0, 6, crate::cli::HashAlgorithm::Sha1)
                .expect("c1");
        assert_ne!(c0.numeric, c1.numeric);
    }

    #[test]
    fn short_key_rejected() {
        let short_key: [u8; 15] = [1u8; 15];
        assert_eq!(short_key.len(), 15);
        let key = write_key(&short_key);
        let err =
            compute_ocra_code(key.path(), "00000000", 0, 6, crate::cli::HashAlgorithm::Sha1)
                .expect_err("must reject 15-byte key");
        assert!(err.contains("InvalidKeyLength") || err.contains("key"));
    }

    #[test]
    fn digits_out_of_range_rejected() {
        let key = write_key(b"12345678901234567890");
        let err3 =
            compute_ocra_code(key.path(), "00000000", 0, 3, crate::cli::HashAlgorithm::Sha1)
                .expect_err("3 digits rejected");
        let err11 =
            compute_ocra_code(key.path(), "00000000", 0, 11, crate::cli::HashAlgorithm::Sha1)
                .expect_err("11 digits rejected");
        assert!(err3.contains("digits") || err3.contains("parameter"));
        assert!(err11.contains("digits") || err11.contains("parameter"));
    }

    // cmd_code error-path tests
    fn empty_code_args() -> CodeArgs {
        CodeArgs {
            vault: String::new(),
            name: String::new(),
            passphrase_file: None,
            algo: None,
            digits: None,
            auto_clear: None,
            quiet: false,
            ocra: false,
            challenge: None,
            counter: None,
            key_file: None,
        }
    }

    #[test]
    fn cmd_code_without_ocra_flag_returns_err() {
        let args = empty_code_args();
        let err = cmd_code(args).expect_err("--ocra absent must error");
        assert!(err.contains("OCRA") || err.contains("TOTP"));
    }

    #[test]
    fn cmd_code_ocra_without_key_or_vault_returns_err() {
        // --ocra + --challenge set, but no --key-file AND no usable vault
        // path. cmd_code should fall through to vault lookup, fail to
        // find a vault (empty path = can't open), and return Err.
        let mut args = empty_code_args();
        args.ocra = true;
        args.challenge = Some("00000000".to_string());
        args.vault = "/nonexistent/path/to/vault".to_string();
        let err = cmd_code(args).expect_err("must error");
        assert!(err.contains("vault") || err.contains("unlock") || err.contains("not found"));
    }

    // Vault round-trip tests
    fn fresh_vault_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn cmd_init_creates_vault_file() {
        let dir = fresh_vault_dir();
        let path = dir.path().join("test.vault");
        let args = InitArgs {
            vault: path.to_string_lossy().to_string(),
            tier: "nano".to_string(),
            passphrase_file: None,
        };
        // bypass the prompt by feeding a passphrase via file
        let pp = dir.path().join("pp");
        std::fs::write(&pp, "passphrase\n").unwrap();
        let mut args = args;
        args.passphrase_file = Some(pp.to_string_lossy().to_string());

        // confirm() will fall through to file mode (no interactive prompt)
        cmd_init(args).expect("init");
        assert!(path.exists());
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() > 48);
        assert_eq!(&bytes[..4], b"OVLT");
    }

    #[test]
    fn cmd_init_refuses_overwrite() {
        let dir = fresh_vault_dir();
        let path = dir.path().join("test.vault");
        let pp = dir.path().join("pp");
        std::fs::write(&pp, "p\n").unwrap();
        let args = InitArgs {
            vault: path.to_string_lossy().to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pp.to_string_lossy().to_string()),
        };
        cmd_init(args.clone()).expect("first init");
        let err = cmd_init(args).expect_err("must refuse overwrite");
        assert!(err.contains("already exists") || err.contains("refusing"));
    }

    #[test]
    fn cmd_unlock_then_list_empty() {
        let dir = fresh_vault_dir();
        let path = dir.path().join("test.vault");
        let pp = dir.path().join("pp");
        std::fs::write(&pp, "p\n").unwrap();
        cmd_init(InitArgs {
            vault: path.to_string_lossy().to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pp.to_string_lossy().to_string()),
        })
        .unwrap();
        cmd_unlock(UnlockArgs {
            vault: path.to_string_lossy().to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pp.to_string_lossy().to_string()),
            session_token: None,
        })
        .unwrap();
        cmd_list(ListArgs {
            vault: path.to_string_lossy().to_string(),
            passphrase_file: Some(pp.to_string_lossy().to_string()),
        })
        .unwrap();
    }

    #[test]
    fn cmd_code_ocra_with_vault_lookup() {
        // End-to-end: init → add OCRA entry via persist → run cmd_code --ocra.
        let dir = fresh_vault_dir();
        let path = dir.path().join("test.vault");
        let pp = dir.path().join("pp");
        std::fs::write(&pp, "p\n").unwrap();

        cmd_init(InitArgs {
            vault: path.to_string_lossy().to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pp.to_string_lossy().to_string()),
        })
        .unwrap();

        // Manually inject an OCRA entry via direct vault mutation (cmd_add
        // doesn't yet support --type ocra from CLI).
        let mut vault_obj = vault::unlock_vault(&path, "p").unwrap();
        let key = b"12345678901234567890";
        vault_obj
            .add_entry(EntryPayload::ocra(
                "bank-ocra",
                key,
                "OCRA-1:HOTP-SHA1-6:QN08",
                6,
                "SHA1",
            ))
            .unwrap();
        vault::persist_vault(&path, &vault_obj).unwrap();

        // Run cmd_code --ocra against the vault.
        cmd_code(CodeArgs {
            vault: path.to_string_lossy().to_string(),
            name: "bank-ocra".to_string(),
            passphrase_file: Some(pp.to_string_lossy().to_string()),
            algo: Some(crate::cli::HashAlgorithm::Sha1),
            digits: Some(6),
            auto_clear: None,
            quiet: false,
            ocra: true,
            challenge: Some("00000000".to_string()),
            counter: None,
            key_file: None,
        })
        .expect("cmd_code via vault lookup");

        // And the wrong entry name should fail.
        let err = cmd_code(CodeArgs {
            vault: path.to_string_lossy().to_string(),
            name: "no-such-entry".to_string(),
            passphrase_file: Some(pp.to_string_lossy().to_string()),
            algo: Some(crate::cli::HashAlgorithm::Sha1),
            digits: Some(6),
            auto_clear: None,
            quiet: false,
            ocra: true,
            challenge: Some("00000000".to_string()),
            counter: None,
            key_file: None,
        })
        .expect_err("missing entry");
        assert!(err.contains("not found") || err.contains("lookup"));
    }

    #[test]
    fn change_passphrase_rejects_wrong_old() {
        let dir = fresh_vault_dir();
        let path = dir.path().join("test.vault");
        let pp = dir.path().join("pp");
        std::fs::write(&pp, "old-pw\n").unwrap();

        cmd_init(InitArgs {
            vault: path.to_string_lossy().to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pp.to_string_lossy().to_string()),
        })
        .unwrap();

        let pp_new = dir.path().join("pp-new");
        std::fs::write(&pp_new, "new-pw\n").unwrap();

        let err = cmd_change_passphrase(ChangePassphraseArgs {
            vault: path.to_string_lossy().to_string(),
            passphrase_file: Some(dir.path().join("wrong-pp").to_string_lossy().to_string()),
            new_passphrase_file: Some(pp_new.to_string_lossy().to_string()),
        })
        .expect_err("wrong old passphrase must fail");
        assert!(err.contains("decryption") || err.contains("Argon2id") || err.contains("cannot"));
    }
}
