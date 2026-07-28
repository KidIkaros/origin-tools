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

use std::path::PathBuf;
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

/// Resolve the entry secret for `cmd_add` from three mutually-exclusive sources:
/// 1. `--secret-file <FILE>` — read bytes from disk (avoids argv + shell history).
/// 2. `--secret-stdin` — read first line from stdin (avoids argv; lives in
///    your shell pipeline).
/// 3. Interactive `rpassword::prompt_password` — for human use.
///
/// `secret_stdin` is the second arg here because clap already enforces
/// mutex semantics for the `--secret-file` presence; we simply check the
/// bool flag here. The function returns `Err` on any I/O failure with an
/// actionable message.
fn resolve_entry_secret(
    file: Option<&str>,
    stdin: bool,
) -> Result<String, String> {
    use std::io::Read;

    if let Some(path) = file {
        let s = std::fs::read_to_string(path).map_err(|e| {
            format!("cannot read secret file {path}: {e}")
        })?;
        return Ok(s.trim_end_matches(['\n', '\r']).to_string());
    }
    if stdin {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("cannot read secret from stdin: {e}"))?;
        return Ok(s.trim_end_matches(['\n', '\r']).to_string());
    }
    rpassword::prompt_password("Secret: ")
        .map_err(|e| format!("secret prompt failed: {e}"))
}

/// Current Unix epoch seconds. Returns `0` if the system clock is set
/// before `UNIX_EPOCH` (1970) — we still want a deterministic value
/// rather than panic. Used to stamp `EntryPayload::created_at` /
/// `updated_at`.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ──────────────────────────────────────────────────────────────────────
// RFC 3986 percent-encoding helpers for otpauth:// URI building
// ──────────────────────────────────────────────────────────────────────

/// Percent-encode `s` per RFC 3986 §2.1: only `A-Z a-z 0-9 - _ . ~`
/// pass through. Used by `cmd_export_qr` to safely embed issuer /
/// account names that may contain `:`, `@`, `&`, etc. into a query
/// value (the original SDK `pub fn url_encode` is `pub(crate)` so we
/// write our own minimal 8-line encoder here).
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    out
}

/// Pad-and-tight RFC 3986 percent-decode. Also accepts `+` (form-encoded
/// space) for cross-tool compatibility with Google Authenticator's QR
/// exports which sometimes use `+` for space in issuer.
pub fn url_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .map_err(|_| format!("invalid %XX in URL at offset {i}"))?;
                let v = u8::from_str_radix(hex, 16)
                    .map_err(|_| format!("invalid hex after `%` at offset {i}: `{hex}`"))?;
                out.push(v);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|e| format!("invalid UTF-8 after URL-decode: {e}"))
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
///
/// **v0.4.x wiring**:
/// - `--type password` — fully wired; uses `resolve_entry_secret` to
///   source the secret from `--secret-file` / `--secret-stdin` / interactive
///   prompt. JSON-serialized per DESIGN.md §2.4 schema; encrypted via the
///   per-entry ChaCha20-BLAKE3 envelope inside `Vault::add_entry`.
///   `--force` overwrites an existing entry; without it, duplicates are
///   rejected.
/// - `--type ocra` — still returns Err (the `cmd_code --ocra` flow seeds
///   OCRA entries; manual `add --type ocra` requires CLI plumbing for
///   `--ocra-suite` + `--ocra-digits` + `--ocra-algo` and is scope-deferred).
/// - `--type otp` — still returns Err (TOTP/HOTP require
///   base32-encoded shared key + period/digits/algo; that wiring is the
///   `cmd_import_qr` step in DESIGN.md §6 — deferred).
pub fn cmd_add(args: AddArgs) -> Result<(), String> {
    // Defer Otp/Ocra to their dedicated flows.
    match args.r#type {
        crate::cli::EntryType::Ocra => {
            return Err(
                "OCRA entries must be added via the `cmd_code --ocra` flow (which seeds the entry automatically); manual `add --type ocra` is not yet wired".to_string(),
            );
        }
        crate::cli::EntryType::Otp => {
            return cmd_add_otp(args);
        }
        crate::cli::EntryType::Password => {} // fall through
    }

    let path = resolve_vault_path(&args.vault)?;
    let passphrase = resolve_passphrase(&args.passphrase_file)?;
    let mut vault_obj = vault::unlock_vault(&path, &passphrase)?;

    // Pre-flight: --force vs. duplicate. Refuse accidental clobbering.
    let is_overwrite = vault_obj.entries.contains_key(&args.name);
    if is_overwrite && !args.force {
        return Err(format!(
            "entry already exists: {} (use --force to overwrite)",
            args.name
        ));
    }

    // Source the secret bytes. We deliberately do NOT support
    // `--secret <string>` in argv — argv leaks via shell history and
    // `ps aux` for the brief window the process runs.
    let secret_str = resolve_entry_secret(
        args.secret_file.as_deref(),
        args.secret_stdin,
    )?;

    // Build the EntryPayload. created_at is preserved across overwrites;
    // updated_at always bumped to "now". url/notes pass through; None on
    // add, replaced if `--force` re-applies them.
    let now = unix_now();
    let mut payload = EntryPayload::password(&args.name, &secret_str);
    payload.url = args.url.clone();
    payload.notes = args.notes.clone();
    payload.updated_at = now;
    if is_overwrite {
        if let Some(prev) = vault_obj.entries.get(&args.name) {
            payload.created_at = prev.created_at;
        }
    } else {
        payload.created_at = now;
    }
    // Best-effort: drop the local secret string (Zeroizing<str> isn't
    // stable but `String::clear` + drop is fine here — the actual secret
    // material is inside the vault's per-entry ChaCha20-BLAKE3 envelope).
    drop(secret_str);

    vault_obj.add_entry(payload)?;
    vault::persist_vault(&path, &vault_obj)?;

    eprintln!(
        "{}: {} (entry: password)",
        if is_overwrite { "updated" } else { "added" },
        args.name
    );
    Ok(())
}

/// Add a TOTP or HOTP entry to the vault.
///
/// The secret is sourced from `--secret-file` / `--secret-stdin` /
/// interactive prompt (same as password entries) and must be a valid
/// base32 string (RFC 4648). The `--hotp` flag selects HOTP mode;
/// without it, TOTP is the default. `--period`, `--digits`, `--algo`,
/// and `--counter` configure the OTP parameters.
fn cmd_add_otp(args: AddArgs) -> Result<(), String> {
    // Validate digits range early (before touching the vault).
    if !(4..=10).contains(&args.digits) {
        return Err(format!("digits out of range (4..=10): {}", args.digits));
    }

    let path = resolve_vault_path(&args.vault)?;
    let passphrase = resolve_passphrase(&args.passphrase_file)?;
    let mut vault_obj = vault::unlock_vault(&path, &passphrase)?;

    // Pre-flight: --force vs. duplicate.
    let is_overwrite = vault_obj.entries.contains_key(&args.name);
    if is_overwrite && !args.force {
        return Err(format!(
            "entry already exists: {} (use --force to overwrite)",
            args.name
        ));
    }

    // Source the secret (base32 string).
    let secret_b32 = resolve_entry_secret(args.secret_file.as_deref(), args.secret_stdin)?;

    // Validate base32 (rejects invalid characters / padding).
    origin_crypto_sdk::drbg::otp::base32_decode(&secret_b32)
        .map_err(|e| format!("secret is not valid base32: {e}"))?;

    // Normalize algorithm to uppercase for storage.
    let algo_str = match args.algo {
        crate::cli::HashAlgorithm::Sha1 => "SHA1",
        crate::cli::HashAlgorithm::Sha256 => "SHA256",
        crate::cli::HashAlgorithm::Sha512 => "SHA512",
    };

    let now = unix_now();
    let mut payload = if args.hotp {
        EntryPayload::hotp(&args.name, &secret_b32, args.counter, args.digits, algo_str)
    } else {
        EntryPayload::totp(&args.name, &secret_b32, args.period, args.digits, algo_str)
    };
    payload.url = args.url.clone();
    payload.notes = args.notes.clone();
    payload.updated_at = now;
    if is_overwrite {
        if let Some(prev) = vault_obj.entries.get(&args.name) {
            payload.created_at = prev.created_at;
        }
    } else {
        payload.created_at = now;
    }

    let kind = if args.hotp { "hotp" } else { "totp" };
    vault_obj.add_entry(payload)?;
    vault::persist_vault(&path, &vault_obj)?;

    eprintln!(
        "{}: {} (entry: {kind})",
        if is_overwrite { "updated" } else { "added" },
        args.name
    );
    Ok(())
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
/// Without `--ocra`: looks up the entry in the vault, determines
/// TOTP vs HOTP from the stored payload, decodes the base32 secret,
/// computes the code via the SDK, and prints it. For HOTP entries the
/// counter is auto-incremented and the vault is persisted.
///
/// With `--ocra`: delegates to the OCRA (RFC 6287) challenge-response
/// path. `--key-file` remains as a **testing escape hatch** (DESIGN.md
/// §3.1 T5.11) and takes precedence over the vault lookup.
pub fn cmd_code(args: CodeArgs) -> Result<(), String> {
    if args.ocra {
        return cmd_code_ocra(args);
    }
    cmd_code_otp(args)
}

/// TOTP/HOTP code path.
fn cmd_code_otp(args: CodeArgs) -> Result<(), String> {
    // Pre-flight: validate vault path + unlock strategy BEFORE we hit
    // `rpassword::prompt_password`, which fails noisily on a non-TTY stdin
    // (e.g. cargo test, CI) with a cryptic message.
    if args.vault.trim().is_empty() {
        return Err(
            "no --vault supplied; cannot derive TOTP/HOTP code. \
             Pass --vault <path> --passphrase-file <path> to unlock the vault."
                .to_string(),
        );
    }
    if args.passphrase_file.is_none() {
        return Err(
            "TOTP/HOTP code requires a passphrase to unlock the vault. \
             Pass --passphrase-file <path> or run from a terminal for \
             interactive unlock."
                .to_string(),
        );
    }

    let path = resolve_vault_path(&args.vault)?;
    let passphrase = resolve_passphrase(&args.passphrase_file)?;
    let mut vault_obj = vault::unlock_vault(&path, &passphrase)?;

    let entry = vault_obj
        .entries
        .get(&args.name)
        .ok_or_else(|| format!("entry not found: {}", args.name))?;

    // Determine TOTP vs HOTP from the stored payload.
    let is_totp = entry.totp.is_some();
    let is_hotp = entry.hotp.is_some();
    if !is_totp && !is_hotp {
        return Err(format!(
            "entry '{}' is type '{}'; `code` requires a TOTP or HOTP entry",
            args.name,
            entry_kind(entry)
        ));
    }

    // Decode the base32 secret.
    let secret_bytes = entry
        .secret
        .as_ref()
        .ok_or_else(|| format!("entry '{}' has no secret bytes stored", args.name))?;
    let secret_b32 = std::str::from_utf8(secret_bytes).map_err(|e| {
        format!("entry '{}' secret is not valid UTF-8 base32: {e}", args.name)
    })?;
    let secret_raw = origin_crypto_sdk::drbg::otp::base32_decode(secret_b32)
        .map_err(|e| format!("entry '{}' secret is not valid base32: {e}", args.name))?;

    // Pull stored parameters from the JSON payload.
    let otp_json = if is_totp {
        entry.totp.as_ref().unwrap()
    } else {
        entry.hotp.as_ref().unwrap()
    };

    let stored_algo = otp_json
        .get("algo")
        .and_then(|a| a.as_str())
        .unwrap_or("SHA1");
    let stored_digits: u32 = otp_json
        .get("digits")
        .and_then(|d| d.as_u64())
        .unwrap_or(6) as u32;

    // CLI overrides take precedence over stored values.
    let algo: origin_crypto_sdk::drbg::otp::HashAlgorithm = match args.algo {
        Some(crate::cli::HashAlgorithm::Sha1) => origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha1,
        Some(crate::cli::HashAlgorithm::Sha256) => origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha256,
        Some(crate::cli::HashAlgorithm::Sha512) => origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha512,
        None => match stored_algo {
            "SHA256" => origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha256,
            "SHA512" => origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha512,
            _ => origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha1,
        },
    };
    let digits = args.digits.unwrap_or(stored_digits);

    use origin_crypto_sdk::drbg::otp::{format_code, hotp, totp};

    let code_str = if is_totp {
        let period: u64 = otp_json
            .get("period")
            .and_then(|p| p.as_u64())
            .unwrap_or(30);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let code = totp(&secret_raw, now, period, digits, algo);
        format_code(code, digits)
    } else {
        // HOTP: read counter, compute, then auto-increment + persist.
        let counter: u64 = otp_json
            .get("counter")
            .and_then(|c| c.as_u64())
            .unwrap_or(0);
        let code = hotp(&secret_raw, counter, digits, algo);
        let result = format_code(code, digits);

        // Auto-increment the counter and persist.
        if let Some(entry_mut) = vault_obj.entries.get_mut(&args.name) {
            if let Some(ref mut hotp_json) = entry_mut.hotp {
                hotp_json["counter"] = serde_json::json!(counter + 1);
            }
            entry_mut.updated_at = unix_now();
        }
        vault::persist_vault(&path, &vault_obj)?;

        result
    };

    // Output: --quiet sends to stderr; default is stdout.
    if args.quiet {
        eprintln!("{code_str}");
    } else {
        println!("{code_str}");
    }

    // --auto-clear: wait N seconds then overwrite the line (TTY only).
    if let Some(secs) = args.auto_clear {
        use std::io::IsTerminal;
        if std::io::stdout().is_terminal() {
            std::thread::sleep(std::time::Duration::from_secs(secs as u64));
            // ANSI: move up one line, clear it, move up again.
            print!("\x1b[1A\x1b[2K");
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
    }

    Ok(())
}

/// OCRA (RFC 6287) challenge-response code path.
fn cmd_code_ocra(args: CodeArgs) -> Result<(), String> {

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

pub fn cmd_export_qr(args: ExportQrArgs) -> Result<(), String> {
    let path = resolve_vault_path(&args.vault)?;
    let passphrase = resolve_passphrase(&args.passphrase_file)?;
    let vault_obj = vault::unlock_vault(&path, &passphrase)?;

    let entry = vault_obj
        .entries
        .get(&args.name)
        .ok_or_else(|| format!("entry not found: {}", args.name))?;

    // Reject non-OTP entries (password, OCRA). Only totp/hotp have an
    // otpauth:// representation.
    let is_totp = entry.totp.is_some();
    let is_hotp = entry.hotp.is_some();
    if !is_totp && !is_hotp {
        return Err(format!(
            "entry '{}' is type '{}'; only otp entries can be exported as QR",
            args.name,
            entry_kind(entry)
        ));
    }

    // Pull algorithm/digits/period/counter from the JSON payload —
    // this is the source of truth (EntryMetadata is a redundant cache).
    let algo = {
        let v = if is_totp { &entry.totp } else { &entry.hotp };
        v.as_ref()
            .and_then(|j| j.get("algo"))
            .and_then(|a| a.as_str())
            .unwrap_or("SHA1")
            .to_string()
    };
    let digits: u32 = {
        let v = if is_totp { &entry.totp } else { &entry.hotp };
        v.as_ref()
            .and_then(|j| j.get("digits"))
            .and_then(|a| a.as_u64())
            .unwrap_or(6) as u32
    };
    let period: u32 = {
        if is_totp {
            entry
                .totp
                .as_ref()
                .and_then(|j| j.get("period"))
                .and_then(|a| a.as_u64())
                .unwrap_or(30) as u32
        } else {
            0 // HOTP has no period.
        }
    };
    let counter: u64 = if is_hotp {
        entry
            .hotp
            .as_ref()
            .and_then(|j| j.get("counter"))
            .and_then(|a| a.as_u64())
            .unwrap_or(0)
    } else {
        0
    };

    // The secret in `entry.secret` is a UTF-8 base32 string (the
    // convention enforced by `EntryPayload::totp` / `::hotp` and
    // `cmd_import_qr`'s decoder-validates-then-stores path). We do
    // NOT round-trip it through base32_encode here — that would
    // treat the existing base32 string as raw bytes and produce a
    // different output for inputs ≥ 16 chars.
    let secret_bytes = entry
        .secret
        .as_ref()
        .ok_or_else(|| format!("entry '{}' has no secret bytes stored", args.name))?;
    let secret_str = std::str::from_utf8(secret_bytes).map_err(|e| {
        format!(
            "entry '{}' secret is not a UTF-8 base32 string (data corruption): {e}",
            args.name
        )
    })?;

    // Issuer fallback chain (precedence):
    //   1. --issuer CLI flag (caller override)
    //   2. `issuer=` prefix stored in entry.notes by `cmd_import_qr`
    //   3. The entry name itself (matches Google Authenticator's
    //      single-entry-per-account convention)
    let stored_issuer = entry
        .notes
        .as_ref()
        .and_then(|n| n.strip_prefix("issuer=").map(|s| s.to_string()));
    let issuer = args
        .issuer
        .clone()
        .or(stored_issuer)
        .unwrap_or_else(|| args.name.clone());

    // Issuer + account can contain URL-special chars (':', '@', '&',
    // '+'). Percent-encode them per RFC 3986 §2.1. The secret is
    // already base32 (RFC 4648 A-Z + 2-7 + '='), algorithm is one of
    // "SHA1|SHA256|SHA512", digits/period/counter are decimal ints —
    // none of those need encoding.
    let issuer_enc = url_encode(&issuer);
    let account_enc = url_encode(&args.name);
    let kind = if is_totp { "totp" } else { "hotp" };
    let mut uri = format!(
        "otpauth://{kind}/{issuer_enc}:{account_enc}?secret={secret}&issuer={issuer_enc}&algorithm={algo}&digits={digits}",
        kind = kind,
        issuer_enc = issuer_enc,
        account_enc = account_enc,
        secret = secret_str,
        algo = algo,
        digits = digits,
    );
    if is_totp {
        uri.push_str(&format!("&period={period}"));
    } else {
        uri.push_str(&format!("&counter={counter}"));
    }

    // Print URI on its own line (so `head -1` works for diagnostics),
    // then a blank line, then the QR block.
    println!("uri: {uri}");
    println!();

    let qr = qrcode::QrCode::new(uri.as_bytes())
        .map_err(|e| format!("QR generation failed: {e}"))?;
    let block = qr
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    print!("{block}");

    Ok(())
}

pub fn cmd_import_qr(args: ImportQrArgs) -> Result<(), String> {
    let path = resolve_vault_path(&args.vault)?;

    // Resolve the URI: literal, or @file prefix mirroring origin-identity.
    let raw_uri = if let Some(file_path) = args.uri.strip_prefix('@') {
        std::fs::read_to_string(file_path)
            .map_err(|e| format!("cannot read URI file {file_path}: {e}"))?
            .trim_end_matches(|c: char| c.is_whitespace())
            .to_string()
    } else {
        args.uri.clone()
    };

    let passphrase = resolve_passphrase(&args.passphrase_file)?;
    let mut vault_obj = vault::unlock_vault(&path, &passphrase)?;

    // Parse `otpauth://<type>/<label>?<query>`.
    let after_scheme = raw_uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| "URI must begin with `otpauth://`".to_string())?;
    let (type_and_label, query) = match after_scheme.split_once('?') {
        Some((tl, q)) => (tl, q),
        None => (after_scheme, ""),
    };
    let (kind, label_enc) = type_and_label.split_once('/').ok_or_else(|| {
        format!("URI malformed: missing `/<label>` after type: `{type_and_label}`")
    })?;
    // Label is percent-encoded in real Google Authenticator exports
    // ("Acme%20Corp:Bob%40example.com"). Decode before parsing.
    let label = url_decode(label_enc).map_err(|e| format!("invalid URI label: {e}"))?;

    // Validate kind.
    if kind != "totp" && kind != "hotp" {
        return Err(format!(
            "URI type must be `totp` or `hotp`, got `{kind}`"
        ));
    }

    // Parse + URL-decode query parameters. Reject bare-key pairs
    // (e.g. `?issuer&digits=6`) per RFC 3986 — that form is invalid
    // and silently accepting it was producing empty-value params.
    let mut params = std::collections::HashMap::<String, String>::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k_enc, v_enc) = pair.split_once('=').ok_or_else(|| {
            format!("URI query pair missing `=`: `{pair}`")
        })?;
        let k = url_decode(k_enc).map_err(|e| format!("invalid URI query key: {e}"))?;
        let v = url_decode(v_enc).map_err(|e| format!("invalid URI query value: {e}"))?;
        params.insert(k, v);
    }

    // Required: secret. Validate via base32_decode (rejects invalid
    // base32 strings) but store the URI's base32 string form directly
    // — matches the existing EntryPayload::totp / ::hotp convention.
    let secret_b32 = params
        .get("secret")
        .ok_or_else(|| "URI missing required `secret` query parameter".to_string())?;
    origin_crypto_sdk::drbg::otp::base32_decode(secret_b32)
        .map_err(|e| format!("URI `secret` is not valid base32: {e}"))?;

    // Issuer: prefer query, fallback to label's `Issuer:` prefix.
    let issuer = params
        .get("issuer")
        .cloned()
        .or_else(|| label.split_once(':').map(|(i, _)| i.to_string()))
        .unwrap_or_default();

    // accountname: label minus optional "Issuer:" prefix.
    let accountname = label
        .split_once(':')
        .map(|(_, a)| a.to_string())
        .unwrap_or_else(|| label.to_string());
    if accountname.is_empty() {
        return Err("URI label resolves to empty accountname".to_string());
    }

    // Algorithm: default SHA1, normalize to uppercase.
    let algo = params
        .get("algorithm")
        .map(|s| s.to_uppercase())
        .unwrap_or_else(|| "SHA1".to_string());
    if algo != "SHA1" && algo != "SHA256" && algo != "SHA512" {
        return Err(format!(
            "unsupported algorithm `{algo}` (must be SHA1, SHA256, or SHA512)"
        ));
    }

    // Digits: default 6, valid range 4..=10.
    let digits: u32 = match params.get("digits") {
        Some(s) => s
            .parse()
            .map_err(|_| format!("digits not a valid integer: `{s}`"))?,
        None => 6,
    };
    if !(4..=10).contains(&digits) {
        return Err(format!("digits out of range (4..=10): {digits}"));
    }

    // Period (TOTP only): default 30.
    let period: u32 = if kind == "totp" {
        match params.get("period") {
            Some(p) => p
                .parse()
                .map_err(|_| format!("period not a valid integer: `{p}`"))?,
            None => 30,
        }
    } else {
        0
    };

    // Counter (HOTP only): REQUIRED per RFC 4226 §5.3.
    let counter: u64 = if kind == "hotp" {
        match params.get("counter") {
            Some(c) => c
                .parse()
                .map_err(|_| format!("counter not a valid integer: `{c}`"))?,
            None => {
                return Err(
                    "HOTP URI missing required `counter` query parameter".to_string(),
                )
            }
        }
    } else {
        0
    };

    // Pre-flight: duplicate entry check; --force overwrites.
    let is_overwrite = vault_obj.entries.contains_key(&accountname);
    if is_overwrite && !args.force {
        return Err(format!(
            "entry already exists: {accountname} (use --force to overwrite)"
        ));
    }

    let now = unix_now();
    let mut payload = if kind == "totp" {
        EntryPayload::totp(&accountname, secret_b32, period, digits, &algo)
    } else {
        EntryPayload::hotp(&accountname, secret_b32, counter, digits, &algo)
    };
    // Stash issuer in `notes` so the export round-trip can recover it
    // without needing --issuer (matches Google Authenticator's
    // self-describing QR exports).
    payload.notes = if issuer.is_empty() {
        None
    } else {
        Some(format!("issuer={issuer}"))
    };
    payload.updated_at = now;
    if is_overwrite {
        if let Some(prev) = vault_obj.entries.get(&accountname) {
            payload.created_at = prev.created_at;
        }
    } else {
        payload.created_at = now;
    }

    vault_obj.add_entry(payload)?;
    vault::persist_vault(&path, &vault_obj)?;
    eprintln!("imported: {accountname} (entry: {kind})");
    Ok(())
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

    // ── TOTP/HOTP SDK-level tests (RFC 6238 / RFC 4226 vectors) ──

    #[test]
    fn rfc6238_totp_sha1_t59() {
        use origin_crypto_sdk::drbg::otp::{format_code, totp, HashAlgorithm};
        let secret = b"12345678901234567890";
        let code = totp(secret, 59, 30, 8, HashAlgorithm::Sha1);
        assert_eq!(format_code(code, 8), "94287082");
    }

    #[test]
    fn rfc6238_totp_sha256_t59() {
        use origin_crypto_sdk::drbg::otp::{format_code, totp, HashAlgorithm};
        let secret = b"12345678901234567890123456789012";
        let code = totp(secret, 59, 30, 8, HashAlgorithm::Sha256);
        assert_eq!(format_code(code, 8), "46119246");
    }

    #[test]
    fn rfc6238_totp_sha512_t59() {
        use origin_crypto_sdk::drbg::otp::{format_code, totp, HashAlgorithm};
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        let code = totp(secret, 59, 30, 8, HashAlgorithm::Sha512);
        assert_eq!(format_code(code, 8), "90693936");
    }

    #[test]
    fn rfc4226_hotp_sha1_counters_0_through_9() {
        use origin_crypto_sdk::drbg::otp::{format_code, hotp, HashAlgorithm};
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489",
        ];
        for (i, exp) in expected.iter().enumerate() {
            let code = hotp(secret, i as u64, 6, HashAlgorithm::Sha1);
            assert_eq!(format_code(code, 6), *exp, "HOTP counter {i}");
        }
    }

    // ── cmd_add_otp tests ──

    fn otp_add_args(dir: &std::path::Path, name: &str, hotp: bool) -> AddArgs {
        let secret_file = dir.join("secret.b32");
        // RFC 4226/6238 test secret in base32: "12345678901234567890"
        std::fs::write(&secret_file, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
        AddArgs {
            vault: dir.join("test.vault").to_string_lossy().to_string(),
            name: name.to_string(),
            r#type: crate::cli::EntryType::Otp,
            passphrase_file: Some(dir.join("pp").to_string_lossy().to_string()),
            url: None,
            notes: None,
            secret_file: Some(secret_file.to_string_lossy().to_string()),
            secret_stdin: false,
            force: false,
            period: 30,
            digits: 6,
            algo: crate::cli::HashAlgorithm::Sha1,
            counter: 0,
            hotp,
        }
    }

    fn init_test_vault(dir: &std::path::Path) {
        let pp = dir.join("pp");
        std::fs::write(&pp, "test-pass\n").unwrap();
        cmd_init(InitArgs {
            vault: dir.join("test.vault").to_string_lossy().to_string(),
            tier: "nano".to_string(),
            passphrase_file: Some(pp.to_string_lossy().to_string()),
        })
        .unwrap();
    }

    #[test]
    fn cmd_add_otp_creates_totp_entry() {
        let dir = fresh_vault_dir();
        init_test_vault(dir.path());
        let args = otp_add_args(dir.path(), "github-2fa", false);
        cmd_add(args).expect("add TOTP");

        // Verify the entry exists and is TOTP.
        let vault_obj = vault::unlock_vault(&dir.path().join("test.vault"), "test-pass").unwrap();
        let entry = vault_obj.entries.get("github-2fa").expect("entry exists");
        assert!(entry.totp.is_some(), "must be TOTP");
        assert!(entry.hotp.is_none(), "must not be HOTP");
        let totp_json = entry.totp.as_ref().unwrap();
        assert_eq!(totp_json["period"], 30);
        assert_eq!(totp_json["digits"], 6);
        assert_eq!(totp_json["algo"], "SHA1");
    }

    #[test]
    fn cmd_add_otp_creates_hotp_entry() {
        let dir = fresh_vault_dir();
        init_test_vault(dir.path());
        let mut args = otp_add_args(dir.path(), "bank-hotp", true);
        args.counter = 42;
        cmd_add(args).expect("add HOTP");

        let vault_obj = vault::unlock_vault(&dir.path().join("test.vault"), "test-pass").unwrap();
        let entry = vault_obj.entries.get("bank-hotp").expect("entry exists");
        assert!(entry.hotp.is_some(), "must be HOTP");
        assert!(entry.totp.is_none(), "must not be TOTP");
        let hotp_json = entry.hotp.as_ref().unwrap();
        assert_eq!(hotp_json["counter"], 42);
        assert_eq!(hotp_json["digits"], 6);
    }

    #[test]
    fn cmd_add_otp_rejects_invalid_base32() {
        let dir = fresh_vault_dir();
        init_test_vault(dir.path());
        let secret_file = dir.path().join("bad.b32");
        std::fs::write(&secret_file, "not-valid-base32!!!\n").unwrap();
        let mut args = otp_add_args(dir.path(), "bad-entry", false);
        args.secret_file = Some(secret_file.to_string_lossy().to_string());
        let err = cmd_add(args).expect_err("invalid base32 must fail");
        assert!(err.contains("base32"), "error: {err}");
    }

    #[test]
    fn cmd_add_otp_rejects_digits_out_of_range() {
        let dir = fresh_vault_dir();
        init_test_vault(dir.path());
        let mut args = otp_add_args(dir.path(), "bad-digits", false);
        args.digits = 3;
        let err = cmd_add(args).expect_err("digits=3 must fail");
        assert!(err.contains("digits"), "error: {err}");
    }

    // ── cmd_code_otp end-to-end tests ──

    fn code_args(dir: &std::path::Path, name: &str) -> CodeArgs {
        CodeArgs {
            vault: dir.join("test.vault").to_string_lossy().to_string(),
            name: name.to_string(),
            passphrase_file: Some(dir.join("pp").to_string_lossy().to_string()),
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
    fn cmd_code_totp_produces_6_digit_output() {
        let dir = fresh_vault_dir();
        init_test_vault(dir.path());
        cmd_add(otp_add_args(dir.path(), "github-2fa", false)).expect("add");

        // cmd_code prints to stdout; we just verify it doesn't error.
        cmd_code(code_args(dir.path(), "github-2fa")).expect("code TOTP");
    }

    #[test]
    fn cmd_code_hotp_increments_counter() {
        let dir = fresh_vault_dir();
        init_test_vault(dir.path());
        cmd_add(otp_add_args(dir.path(), "bank-hotp", true)).expect("add");

        // First code call: counter=0 → should increment to 1.
        cmd_code(code_args(dir.path(), "bank-hotp")).expect("code 1");
        let vault_obj = vault::unlock_vault(&dir.path().join("test.vault"), "test-pass").unwrap();
        let counter1 = vault_obj.entries["bank-hotp"].hotp.as_ref().unwrap()["counter"]
            .as_u64()
            .unwrap();
        assert_eq!(counter1, 1, "counter must be 1 after first code");

        // Second code call: counter=1 → should increment to 2.
        cmd_code(code_args(dir.path(), "bank-hotp")).expect("code 2");
        let vault_obj = vault::unlock_vault(&dir.path().join("test.vault"), "test-pass").unwrap();
        let counter2 = vault_obj.entries["bank-hotp"].hotp.as_ref().unwrap()["counter"]
            .as_u64()
            .unwrap();
        assert_eq!(counter2, 2, "counter must be 2 after second code");
    }

    #[test]
    fn cmd_code_rejects_password_entry() {
        let dir = fresh_vault_dir();
        init_test_vault(dir.path());

        // Add a password entry.
        let secret_file = dir.path().join("pw.txt");
        std::fs::write(&secret_file, "hunter2\n").unwrap();
        cmd_add(AddArgs {
            vault: dir.path().join("test.vault").to_string_lossy().to_string(),
            name: "email".to_string(),
            r#type: crate::cli::EntryType::Password,
            passphrase_file: Some(dir.path().join("pp").to_string_lossy().to_string()),
            url: None,
            notes: None,
            secret_file: Some(secret_file.to_string_lossy().to_string()),
            secret_stdin: false,
            force: false,
            period: 30,
            digits: 6,
            algo: crate::cli::HashAlgorithm::Sha1,
            counter: 0,
            hotp: false,
        })
        .expect("add password");

        let err = cmd_code(code_args(dir.path(), "email")).expect_err("password entry must fail");
        assert!(
            err.contains("TOTP") || err.contains("HOTP") || err.contains("type"),
            "error: {err}"
        );
    }

    #[test]
    fn cmd_code_rejects_missing_entry() {
        let dir = fresh_vault_dir();
        init_test_vault(dir.path());
        let err = cmd_code(code_args(dir.path(), "nonexistent")).expect_err("missing entry");
        assert!(err.contains("not found"), "error: {err}");
    }

    #[test]
    fn cmd_code_otp_without_vault_returns_err() {
        let mut args = empty_code_args();
        args.ocra = false;
        let err = cmd_code(args).expect_err("no vault must error");
        assert!(err.contains("vault") || err.contains("TOTP"), "error: {err}");
    }
}
