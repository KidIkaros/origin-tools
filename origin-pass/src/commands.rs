// SPDX-License-Identifier: Apache-2.0

//! Command implementations for `origin-pass`.
//!
//! Each `cmd_*` function returns `Result<(), String>` and is wired to
//! the matching CLI subcommand in `main.rs`.
//!
//! # Unlock model (v0.5)
//!
//! There is **no in-process vault state**. Every command that needs the
//! vault unlocks it fresh from disk via [`unlock_vault_with_args`] using
//! either `--passphrase-file` or a persisted `--session-token` (written
//! by `unlock`, revoked by `lock`). This keeps each CLI invocation
//! self-contained and safe to script; the session token is the only
//! cross-process credential.

use std::path::{Path, PathBuf};

use origin_common::{resolve_passphrase, MemoryTier};

use crate::cli::{
    AddArgs, ChangePassphraseArgs, CodeArgs, ExportQrArgs, GenerateArgs, GetArgs, ImportQrArgs,
    InitArgs, ListArgs, LockAllArgs, LockArgs, RmArgs, TokensArgs, TokensCommand, TokensFormat,
    UnlockArgs,
};
use crate::vault::{self, EntryPayload, Vault};
use crate::{generate, ledger, ocra_suite, session};

/// Conversion from the CLI-facing `HashAlgorithm` enum (clap ValueEnum)
/// to the SDK's `drbg::otp::HashAlgorithm`. Both share the same variants
/// but are distinct Rust types; without this conversion, OCRA dispatch
/// would leak the SDK type into the command surface.
impl From<crate::cli::HashAlgorithm> for origin_crypto_sdk::drbg::otp::HashAlgorithm {
    fn from(v: crate::cli::HashAlgorithm) -> Self {
        match v {
            crate::cli::HashAlgorithm::Sha1 => origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha1,
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
// Passphrase + path helpers
// ──────────────────────────────────────────────────────────────────────

/// Same as `resolve_passphrase` but confirms via a second prompt when
/// reading interactively (used by `cmd_init` and `cmd_change_passphrase`).
pub fn resolve_passphrase_confirm(file: &Option<String>) -> Result<String, String> {
    origin_common::resolve_passphrase_confirm(file.as_deref())
}

/// Value of `$ORIGIN_PASS_TOKEN`, if set and non-empty. Explicit
/// `--session-token` / `--passphrase-file` flags always win over it
/// (see [`unlock_vault_with_args`] and [`cmd_lock`]).
fn session_token_env() -> Option<String> {
    std::env::var("ORIGIN_PASS_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
}

/// True when a session token is available from the flag or from
/// `$ORIGIN_PASS_TOKEN`. Used by pre-flight checks that must reject
/// tokenless invocations before hitting the interactive prompt.
fn session_token_available(flag: Option<&Path>) -> bool {
    flag.is_some() || session_token_env().is_some()
}

/// Unlock the vault using either a passphrase or a persisted session
/// token. Clap enforces the mutual exclusion between `--passphrase-file`
/// and `--session-token`; this helper is the single place both sources
/// are turned into an unlocked `Vault`. `$ORIGIN_PASS_TOKEN` is used as
/// a fallback token source when neither flag is given (explicit flags
/// win). When the token carries an auto-rotate policy and is running
/// low on lifetime, it is refreshed in place as a side effect of use.
fn unlock_vault_with_args(
    vault_raw: &str,
    passphrase_file: Option<&str>,
    session_token: Option<&Path>,
) -> Result<Vault, String> {
    let path = resolve_vault_path(vault_raw)?;
    // Explicit flags win over the env var: --passphrase-file suppresses
    // the env fallback, and the clap conflict handles flag-vs-flag.
    let token = match session_token {
        Some(p) => Some(p.to_path_buf()),
        None if passphrase_file.is_some() => None,
        None => session_token_env().map(PathBuf::from),
    };
    match token {
        Some(token_raw) => {
            // Bare names resolve into ~/.origin/tokens (see session.rs).
            let raw = token_raw.to_string_lossy();
            let token_path = session::resolve_token_path(&raw)?;
            let master = session::read_session_token(&token_path)?;
            // Auto-rotate on use (if the token's policy says so), so a
            // long-running workflow never dies mid-session.
            session::maybe_auto_rotate(&token_path)?;
            vault::unlock_vault_with_key(&path, master.as_ref())
        }
        None => {
            let passphrase = resolve_passphrase(passphrase_file)?;
            vault::unlock_vault(&path, &passphrase)
        }
    }
}

/// Build the auto-rotate policy from `unlock` flags. Errors when the
/// policy-specific flags are given without `--auto-rotate`.
fn build_auto_rotate(args: &UnlockArgs) -> Result<Option<session::AutoRotateConfig>, String> {
    if !args.auto_rotate {
        if args.auto_rotate_threshold.is_some() || args.auto_rotate_ttl.is_some() {
            return Err(
                "--auto-rotate-threshold and --auto-rotate-ttl require --auto-rotate".to_string(),
            );
        }
        return Ok(None);
    }
    Ok(Some(session::AutoRotateConfig {
        threshold: args
            .auto_rotate_threshold
            .unwrap_or(session::DEFAULT_AUTO_ROTATE_THRESHOLD_SECS),
        ttl: args.auto_rotate_ttl.unwrap_or(args.session_ttl),
    }))
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
fn resolve_entry_secret(file: Option<&str>, stdin: bool) -> Result<String, String> {
    use std::io::Read;

    if let Some(path) = file {
        let s = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read secret file {path}: {e}"))?;
        return Ok(s.trim_end_matches(['\n', '\r']).to_string());
    }
    if stdin {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("cannot read secret from stdin: {e}"))?;
        return Ok(s.trim_end_matches(['\n', '\r']).to_string());
    }
    rpassword::prompt_password("Secret: ").map_err(|e| format!("secret prompt failed: {e}"))
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

    let key = std::fs::read(key_path)
        .map_err(|e| format!("failed to read OCRA key file {}: {e}", key_path.display()))?;

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

/// Unlock the vault. Verifies the passphrase and, with
/// `--session-token <path>`, writes a persisted session token file that
/// lets other processes unlock without the passphrase until it expires
/// (see `session.rs`). Nothing is retained in-process.
pub fn cmd_unlock(args: UnlockArgs) -> Result<(), String> {
    // Validate the user-supplied tier string for early failure on typo;
    // the on-disk header is authoritative so this value is unused.
    vault::parse_tier(&args.tier)?;
    let path = resolve_vault_path(&args.vault)?;
    let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;
    let vault_obj = vault::unlock_vault(&path, &passphrase)?;

    if let Some(token_raw) = args.session_token.as_ref() {
        let auto_rotate = build_auto_rotate(&args)?;
        let token_path = session::resolve_token_path(&token_raw.to_string_lossy())?;
        session::write_session_token(
            &token_path,
            &vault_obj.master_key,
            args.session_ttl,
            Some(&path),
            auto_rotate,
        )?;
        eprintln!(
            "session token written: {} (ttl={}s{})",
            token_path.display(),
            args.session_ttl,
            if auto_rotate.is_some() {
                ", auto-rotate"
            } else {
                ""
            },
        );
    }

    let entry_count = vault_obj.entries.len();
    let tier = match vault_obj.header.kdf_tier {
        MemoryTier::Nano => "nano",
        MemoryTier::Standard => "standard",
        MemoryTier::Sovereign => "sovereign",
    };
    // Nothing is retained in-process; `unlock` only verifies the
    // passphrase and optionally writes a session token.
    drop(vault_obj);
    eprintln!(
        "unlocked {} (tier={}, {entry_count} entries)",
        path.display(),
        tier
    );
    Ok(())
}

/// Revoke a persisted session token file. Since v0.5 there is no
/// in-process vault state to drop — the session token is the only
/// cross-process credential, so `lock` without one has nothing to do
/// and errors rather than silently no-oping.
pub fn cmd_lock(args: LockArgs) -> Result<(), String> {
    // The token comes from the flag or, failing that, $ORIGIN_PASS_TOKEN
    // (the env var makes `lock` usable in scripts that never name a token).
    let token_raw = args
        .session_token
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .or_else(session_token_env)
        .ok_or_else(|| {
            "nothing to lock: v0.5 keeps no in-process vault state. \
             Pass --session-token <path> (or set $ORIGIN_PASS_TOKEN) to revoke a \
             persisted session token."
                .to_string()
        })?;
    let token_path = session::resolve_token_path(&token_raw)?;
    session::revoke_session_token(&token_path)?;
    eprintln!("session token revoked: {}", token_path.display());
    Ok(())
}

/// Revoke every persisted session token in the store, optionally only
/// those bound to a specific vault (`--vault <path>`). Like bare
/// `lock`, this errors when nothing was revoked rather than silently
/// no-oping, so scripts can't mistake "nothing happened" for success.
pub fn cmd_lock_all(args: LockAllArgs) -> Result<(), String> {
    let dir = session::resolve_store_dir(&args.dir)?;
    let tokens = session::list_tokens(&dir)?;
    let vault_filter = args.vault.as_deref().map(resolve_vault_path).transpose()?;

    let mut revoked = 0usize;
    for t in &tokens {
        if let Some(target) = &vault_filter {
            let bound = t.vault.as_deref().map(Path::new);
            if bound != Some(target.as_path()) {
                continue;
            }
        }
        session::revoke_session_token(&t.path)?;
        revoked += 1;
    }

    if revoked == 0 {
        return Err(match &vault_filter {
            Some(v) => format!(
                "nothing to lock: no session tokens bound to {} in {}",
                v.display(),
                dir.display()
            ),
            None => format!("nothing to lock: no session tokens in {}", dir.display()),
        });
    }
    eprintln!("locked: revoked {revoked} session token(s)");
    Ok(())
}

/// Manage persisted session tokens without touching the vault:
/// `tokens list|revoke|revoke-all`. The token store defaults to
/// `~/.origin/tokens` and is overridable with `--dir` (mirroring the
/// `origin-identity` store convention). No unlock is required — the
/// commands only read/delete token files.
pub fn cmd_tokens(args: TokensArgs) -> Result<(), String> {
    match args.command {
        TokensCommand::List(list) => {
            let dir = session::resolve_store_dir(&list.dir)?;
            let all = session::list_tokens(&dir)?;
            let now = unix_now();
            // With `--remaining <mins>`, keep only tokens that expire
            // within the window (expired tokens always match); unreadable
            // files have no expiry and are excluded from the filter.
            let tokens: Vec<&session::TokenInfo> = match list.remaining {
                Some(mins) => all
                    .iter()
                    .filter(|t| expires_within(t, now, mins))
                    .collect(),
                None => all.iter().collect(),
            };
            match list.format {
                TokensFormat::Json => {
                    let rows: Vec<serde_json::Value> = tokens
                        .iter()
                        .map(|t| {
                            serde_json::json!({
                                "name": t.name,
                                "token_id": t.token_id,
                                "created_at": t.created_at,
                                "expires_at": t.expires_at,
                                "expires_in_secs": if t.unreadable {
                                    serde_json::Value::Null
                                } else {
                                    serde_json::json!(t.expires_at - now)
                                },
                                "vault": t.vault,
                                "status": token_status(t),
                                "auto_rotate": t.auto_rotate,
                                "auto_rotate_threshold": t.auto_rotate_threshold,
                                "auto_rotate_ttl": t.auto_rotate_ttl,
                                "unreadable": t.unreadable,
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&rows)
                            .map_err(|e| format!("cannot serialize token listing: {e}"))?
                    );
                }
                TokensFormat::Table => {
                    println!(
                        "{:<24} {:<10} {:<20} {:<20} {:<12} {:<12} {:<10} {:<10}",
                        "name",
                        "token_id",
                        "created (UTC)",
                        "expires (UTC)",
                        "remaining",
                        "auto",
                        "vault",
                        "status"
                    );
                    println!("{}", "-".repeat(122));
                    for t in &tokens {
                        let id: String = if t.unreadable {
                            "-".to_string()
                        } else {
                            let full = &t.token_id;
                            if full.len() <= 10 {
                                full.clone()
                            } else {
                                format!("{}…", &full[..10])
                            }
                        };
                        let vault = t.vault.as_deref().unwrap_or("-");
                        let remaining = if t.unreadable {
                            "-".to_string()
                        } else {
                            fmt_remaining(t.expires_at)
                        };
                        let auto = match (t.auto_rotate_threshold, t.auto_rotate_ttl) {
                            (Some(th), Some(ttl)) => {
                                format!("{}→{}", fmt_duration(th), fmt_duration(ttl))
                            }
                            _ => "-".to_string(),
                        };
                        let status = token_status(t);
                        println!(
                            "{:<24} {:<10} {:<20} {:<20} {:<12} {:<12} {:<10} {:<10}",
                            t.name,
                            id,
                            fmt_utc(t.created_at),
                            fmt_utc(t.expires_at),
                            remaining,
                            auto,
                            vault,
                            status,
                        );
                    }
                }
            }
            if list.remaining.is_some() {
                // Scriptable alert: nonzero exit when near-expiry tokens
                // exist (so cron/shell can notice), zero when none.
                if tokens.is_empty() {
                    eprintln!(
                        "no tokens expire within {}m in {}",
                        list.remaining.unwrap_or(0),
                        dir.display()
                    );
                    return Ok(());
                }
                std::process::exit(1);
            }
            if tokens.is_empty() {
                eprintln!("no session tokens in {}", dir.display());
            } else {
                let valid = tokens.iter().filter(|t| token_status(t) == "valid").count();
                let expired = tokens.iter().filter(|t| token_status(t) == "expired").count();
                let unreadable = tokens.iter().filter(|t| t.unreadable).count();
                eprintln!("summary: {valid} valid, {expired} expired, {unreadable} unreadable");
            }
            Ok(())
        }
        TokensCommand::Revoke(revoke) => {
            let dir = session::resolve_store_dir(&revoke.dir)?;
            let path = session::resolve_token_path_in(&dir, &revoke.name)?;
            session::revoke_session_token(&path)?;
            eprintln!("revoked: {}", revoke.name);
            Ok(())
        }
        TokensCommand::Rotate(rotate) => {
            let dir = session::resolve_store_dir(&rotate.dir)?;
            let path = session::resolve_token_path_in(&dir, &rotate.name)?;
            let token = session::rotate_session_token(&path, rotate.ttl)?;
            eprintln!(
                "rotated {}: token id {}, expires {} (ttl={}s)",
                rotate.name,
                token.token_id,
                fmt_utc(token.expires_at),
                token.expires_at - token.created_at,
            );
            Ok(())
        }
        TokensCommand::Renew(renew) => {
            let dir = session::resolve_store_dir(&renew.dir)?;
            let path = session::resolve_token_path_in(&dir, &renew.name)?;
            let token = session::renew_session_token(&path, renew.ttl)?;
            eprintln!(
                "renewed {}: same bearer key, expires {} (+{}s)",
                renew.name,
                fmt_utc(token.expires_at),
                renew.ttl.unwrap_or_else(|| {
                    (token.expires_at - token.created_at).max(1) as u64
                }),
            );
            Ok(())
        }
        TokensCommand::RevokeAll(revoke_all) => {
            let dir = session::resolve_store_dir(&revoke_all.dir)?;
            let revoked = session::revoke_all_tokens(&dir, revoke_all.expired_only)?;
            if revoke_all.expired_only {
                eprintln!("revoked {revoked} expired token(s)");
            } else {
                eprintln!("revoked {revoked} token(s)");
            }
            Ok(())
        }
        TokensCommand::Prune(prune) => {
            let dir = session::resolve_store_dir(&prune.dir)?;
            let now = unix_now();
            // Expired tokens are dead weight; unreadable (corrupt/foreign)
            // files can never unlock anything, so prune both. Valid tokens
            // are never touched.
            let all = session::list_tokens(&dir)?;
            let doomed: Vec<&session::TokenInfo> = all
                .iter()
                .filter(|t| t.unreadable || now >= t.expires_at)
                .collect();
            if doomed.is_empty() {
                eprintln!(
                    "nothing to prune: no expired or unreadable tokens in {}",
                    dir.display()
                );
                return Ok(());
            }
            for t in &doomed {
                session::revoke_session_token(&t.path)?;
                eprintln!(
                    "pruned: {} ({})",
                    t.name,
                    if t.unreadable { "unreadable" } else { "expired" }
                );
            }
            eprintln!("pruned {} token(s) from {}", doomed.len(), dir.display());
            Ok(())
        }
    }
}

/// Lifecycle status of a token for `tokens list`.
fn token_status(t: &session::TokenInfo) -> &'static str {
    if t.unreadable {
        return "unreadable";
    }
    if unix_now() >= t.expires_at {
        "expired"
    } else {
        "valid"
    }
}

/// True when the token's remaining lifetime is under `mins` minutes
/// (expired tokens always match; unreadable files never do). The
/// predicate behind `tokens list --remaining <mins>`.
fn expires_within(t: &session::TokenInfo, now: i64, mins: u64) -> bool {
    !t.unreadable && t.expires_at - now < (mins as i64) * 60
}

/// Compact human duration, e.g. `45s`, `15m`, `2h`, `8h`, `3d` — used
/// for the auto-rotate column (`15m→8h` = threshold→fresh ttl).
fn fmt_duration(secs: u64) -> String {
    if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Compact human-readable time remaining until `expires_at`, e.g.
/// `3d 4h`, `2h 5m`, `45m`, `10s`; `expired` once past it.
fn fmt_remaining(expires_at: i64) -> String {
    let diff = expires_at - unix_now();
    if diff <= 0 {
        return "expired".to_string();
    }
    let (d, h, m, s) = (diff / 86_400, (diff % 86_400) / 3600, (diff % 3600) / 60, diff % 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Format a unix timestamp as `YYYY-MM-DD HH:MM:SS` UTC without pulling
/// in a date library (Howard Hinnant's civil-from-days algorithm).
fn fmt_utc(ts: i64) -> String {
    if ts == 0 {
        return "-".to_string();
    }
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mth <= 2 { y + 1 } else { y };
    format!("{year:04}-{mth:02}-{d:02} {h:02}:{m:02}:{s:02}")
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
            return cmd_add_ocra(args);
        }
        crate::cli::EntryType::Otp => {
            return cmd_add_otp(args);
        }
        crate::cli::EntryType::Password => {} // fall through
    }

    let path = resolve_vault_path(&args.vault)?;
    let mut vault_obj = unlock_vault_with_args(
        &args.vault,
        args.passphrase_file.as_deref(),
        args.session_token.as_deref(),
    )?;

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
    let secret_str = resolve_entry_secret(args.secret_file.as_deref(), args.secret_stdin)?;

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
    let mut vault_obj = unlock_vault_with_args(
        &args.vault,
        args.passphrase_file.as_deref(),
        args.session_token.as_deref(),
    )?;

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

/// Add an OCRA (RFC 6287) challenge-response entry to the vault.
///
/// Requires `--suite <OCRA-1:...>` (validated by `ocra_suite::parse_suite`)
/// and a binary key via `--secret-file` / `--secret-stdin` (OCRA keys are
/// raw bytes, so the text-oriented interactive prompt is not offered).
/// The key must be ≥ 16 bytes (RFC 6287 §10 floor, enforced by the SDK at
/// compute time; we check early for a clear error).
fn cmd_add_ocra(args: AddArgs) -> Result<(), String> {
    let suite_str = args.suite.clone().ok_or_else(|| {
        "--type ocra requires --suite <OCRA-1:HOTP-<hash>-<digits>:<data>> (e.g. \
         OCRA-1:HOTP-SHA1-6:QN08)"
            .to_string()
    })?;
    let suite = ocra_suite::parse_suite(&suite_str)?;

    // SDK limitation guard: the OCRA P slot is hashed with SHA-1 only
    // (see `ocra_suite` module docs). Rejecting P-SHA256/512 suites up
    // front is honest — silently computing a non-conformant P slot would
    // produce codes the verifier rejects (or worse, codes that verify
    // against a weak P).
    if let Some(pin_algo) = suite.pin_algo {
        if pin_algo != origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha1 {
            return Err(format!(
                "suite `{suite_str}` uses P-{:?}, but origin-crypto-sdk computes the OCRA P slot \
                 with SHA-1 only — use a P-SHA1 suite (or no PIN) for now",
                pin_algo
            ));
        }
    }
    // Session data (S<nnn>) has no CLI input surface yet; reject rather
    // than compute a response with an empty session the verifier expects
    // to be populated.
    if suite.session_len.is_some() {
        return Err(format!(
            "suite `{suite_str}` requires session data (S<nnn>), which the CLI does not support \
             yet — use a suite without a session component"
        ));
    }

    // Binary key source: OCRA keys are raw bytes, not text. Read the
    // file/stdin as bytes, stripping one trailing newline (so keys piped
    // via `printf '...' |` or echo'd files work like the text path).
    let key: Vec<u8> = if let Some(file) = args.secret_file.as_deref() {
        std::fs::read(file).map_err(|e| format!("cannot read OCRA key file {file}: {e}"))?
    } else if args.secret_stdin {
        let mut buf = Vec::new();
        use std::io::Read;
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("cannot read OCRA key from stdin: {e}"))?;
        buf
    } else {
        return Err(
            "OCRA keys must be supplied via --secret-file <path> or --secret-stdin (raw bytes); \
             interactive entry is not supported for binary keys"
                .to_string(),
        );
    };
    let key = key
        .strip_suffix(b"\n")
        .map(|k| k.strip_suffix(b"\r").unwrap_or(k).to_vec())
        .unwrap_or(key);
    if key.len() < 16 {
        return Err(format!(
            "OCRA key is {} bytes; RFC 6287 requires at least 16 bytes",
            key.len()
        ));
    }

    let path = resolve_vault_path(&args.vault)?;
    let mut vault_obj = unlock_vault_with_args(
        &args.vault,
        args.passphrase_file.as_deref(),
        args.session_token.as_deref(),
    )?;

    let is_overwrite = vault_obj.entries.contains_key(&args.name);
    if is_overwrite && !args.force {
        return Err(format!(
            "entry already exists: {} (use --force to overwrite)",
            args.name
        ));
    }

    let algo = match suite.algo {
        origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha1 => "SHA1",
        origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha256 => "SHA256",
        origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha512 => "SHA512",
    };
    let now = unix_now();
    let mut payload =
        EntryPayload::ocra(&args.name, &key, &suite_str, suite.digits, algo, args.counter);
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

    vault_obj.add_entry(payload)?;
    vault::persist_vault(&path, &vault_obj)?;

    eprintln!(
        "{}: {} (entry: ocra, suite: {suite_str})",
        if is_overwrite { "updated" } else { "added" },
        args.name
    );
    Ok(())
}

/// Retrieve a single entry by name.
pub fn cmd_get(args: GetArgs) -> Result<(), String> {
    let vault_obj = unlock_vault_with_args(
        &args.vault,
        args.passphrase_file.as_deref(),
        args.session_token.as_deref(),
    )?;

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
    let vault_obj = unlock_vault_with_args(
        &args.vault,
        args.passphrase_file.as_deref(),
        args.session_token.as_deref(),
    )?;

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
    let mut vault_obj = unlock_vault_with_args(
        &args.vault,
        args.passphrase_file.as_deref(),
        args.session_token.as_deref(),
    )?;

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
        return Err("no --vault supplied; cannot derive TOTP/HOTP code. \
             Pass --vault <path> --passphrase-file <path> to unlock the vault."
            .to_string());
    }
    if args.passphrase_file.is_none() && !session_token_available(args.session_token.as_deref()) {
        return Err("TOTP/HOTP code requires a passphrase or session token to unlock the vault. \
             Pass --passphrase-file <path> or --session-token <path> (or set $ORIGIN_PASS_TOKEN), \
             or run from a terminal for interactive unlock."
            .to_string());
    }

    let path = resolve_vault_path(&args.vault)?;
    let mut vault_obj = unlock_vault_with_args(
        &args.vault,
        args.passphrase_file.as_deref(),
        args.session_token.as_deref(),
    )?;

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
        format!(
            "entry '{}' secret is not valid UTF-8 base32: {e}",
            args.name
        )
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
    let stored_digits: u32 = otp_json.get("digits").and_then(|d| d.as_u64()).unwrap_or(6) as u32;

    // CLI overrides take precedence over stored values.
    let algo: origin_crypto_sdk::drbg::otp::HashAlgorithm = match args.algo {
        Some(crate::cli::HashAlgorithm::Sha1) => origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha1,
        Some(crate::cli::HashAlgorithm::Sha256) => {
            origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha256
        }
        Some(crate::cli::HashAlgorithm::Sha512) => {
            origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha512
        }
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
///
/// **Suite-driven**: the entry's stored OCRASuite string is the source
/// of truth for the algorithm, digit count, challenge format, counter /
/// timestamp mode, and PIN requirement. CLI overrides (`--algo`,
/// `--digits`, `--counter`) still take precedence. For challenge-based
/// suites the replay-nonce ledger refuses to re-issue a response for an
/// already-used challenge unless `--force` is given.
fn cmd_code_ocra(args: CodeArgs) -> Result<(), String> {
    // Path 1: testing escape hatch (raw key from file). Explicit
    // algo/digits/counter, no suite, no ledger.
    if let Some(key_path) = args.key_file.as_ref() {
        let challenge = args
            .challenge
            .as_deref()
            .ok_or_else(|| "--ocra --key-file requires --challenge <STRING>".to_string())?;
        let algo = args.algo.clone().unwrap_or(crate::cli::HashAlgorithm::Sha1);
        let digits = args.digits.unwrap_or(6);
        let counter = args.counter.unwrap_or(0);
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
    if args.passphrase_file.is_none() && !session_token_available(args.session_token.as_deref()) {
        return Err(
            "OCRA from vault requires a passphrase or session token to unlock the vault. \
             Pass --passphrase-file <path> or --session-token <path> (or set $ORIGIN_PASS_TOKEN); \
             for tests, prefer --key-file <path>."
                .to_string(),
        );
    }

    let path = resolve_vault_path(&args.vault)?;
    let mut vault_obj = unlock_vault_with_args(
        &args.vault,
        args.passphrase_file.as_deref(),
        args.session_token.as_deref(),
    )?;

    let entry = vault_obj
        .get_ocra_entry(&args.name)
        .map_err(|e| format!("OCRA vault lookup failed: {e}"))?;
    let ocra_json = entry.ocra.as_ref().ok_or_else(|| {
        format!(
            "entry '{}' has no OCRA metadata stored (data corruption?)",
            args.name
        )
    })?;
    let suite_str = ocra_json
        .get("suite")
        .and_then(|s| s.as_str())
        .ok_or_else(|| {
            format!(
                "entry '{}' has no stored OCRA suite — re-add with `add --type ocra --suite <...>`",
                args.name
            )
        })?;
    let suite = ocra_suite::parse_suite(suite_str)?;
    let key = entry.secret.clone().ok_or_else(|| {
        format!(
            "entry '{}' has no secret bytes stored (data corruption?)",
            args.name
        )
    })?;

    // Effective parameters: CLI overrides > stored suite.
    let algo = match args.algo {
        Some(a) => a,
        None => match suite.algo {
            origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha1 => crate::cli::HashAlgorithm::Sha1,
            origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha256 => crate::cli::HashAlgorithm::Sha256,
            origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha512 => crate::cli::HashAlgorithm::Sha512,
        },
    };
    let digits = args.digits.unwrap_or(suite.digits);

    // Counter: only suites with a `C` component use a non-zero counter;
    // the stored counter auto-increments per use (like HOTP) unless the
    // caller overrides with --counter.
    let stored_counter: u64 = ocra_json.get("counter").and_then(|c| c.as_u64()).unwrap_or(0);
    let counter = if suite.has_counter {
        args.counter.unwrap_or(stored_counter)
    } else {
        0
    };

    // Timestamp: suites with `T<num><unit>` use the current time in
    // time-steps (RFC §6.3).
    let timestamp = suite.timestamp_step_secs.map(|step_secs| {
        let now = unix_now().max(0) as u64;
        now / step_secs
    });

    // Challenge: validated + encoded against the suite's format.
    ocra_suite::validate_challenge(&suite, args.challenge.as_deref())?;
    let challenge_bytes = ocra_suite::encode_challenge(&suite, args.challenge.as_deref())?;

    // PIN: suites with `P<hash>` require --pin; suites without one reject it.
    if suite.pin_algo.is_some() && args.pin.is_none() {
        return Err(format!(
            "suite `{suite_str}` requires --pin <STRING> (P- component)"
        ));
    }
    if suite.pin_algo.is_none() && args.pin.is_some() {
        return Err(format!(
            "suite `{suite_str}` has no PIN component — omit --pin"
        ));
    }

    // Replay-nonce ledger: applies to challenge-based suites without a
    // timestamp (time-based replay is bounded by the time window).
    let ledger_applies = suite.challenge.kind != crate::ocra_suite::ChallengeKind::None
        && timestamp.is_none();
    if ledger_applies {
        let fp = ledger::challenge_fingerprint(&challenge_bytes, counter);
        let replay = ledger::record_use(&path, &args.name, &fp, unix_now(), args.force)?;
        if replay && !args.force {
            return Err(format!(
                "OCRA replay detected: challenge `{}` (counter {counter}) was already used for \
                 entry '{}' — refusing to re-issue. Pass --force to override.",
                args.challenge.as_deref().unwrap_or(""),
                args.name
            ));
        }
    }

    // Compute.
    use origin_crypto_sdk::ocra::{ocra, OcraRequest};
    let sdk_algo: origin_crypto_sdk::drbg::otp::HashAlgorithm = algo.into();
    let req = OcraRequest {
        counter,
        challenge: &challenge_bytes,
        password: args.pin.as_deref().map(|p| p.as_bytes()),
        session: b"",
        timestamp,
    };
    let resp = ocra(&key, &req, digits, sdk_algo).map_err(|e| e.to_string())?;
    let code = OcraCode {
        value: resp.format_code(),
        numeric: resp.value,
        digits: resp.digits,
    };

    // Counter auto-increment + persist for C-suites (only when the
    // stored counter was used — an explicit --counter is a verification
    // call and must not advance the stored state).
    if suite.has_counter && args.counter.is_none() {
        if let Some(entry_mut) = vault_obj.entries.get_mut(&args.name) {
            if let Some(ref mut ocra_json_mut) = entry_mut.ocra {
                ocra_json_mut["counter"] = serde_json::json!(stored_counter + 1);
            }
            entry_mut.updated_at = unix_now();
        }
        vault::persist_vault(&path, &vault_obj)?;
    }

    print_ocra_code(&code, args.quiet)
}

pub fn cmd_export_qr(args: ExportQrArgs) -> Result<(), String> {
    let vault_obj = unlock_vault_with_args(
        &args.vault,
        args.passphrase_file.as_deref(),
        args.session_token.as_deref(),
    )?;

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

    let qr =
        qrcode::QrCode::new(uri.as_bytes()).map_err(|e| format!("QR generation failed: {e}"))?;
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

    let mut vault_obj = unlock_vault_with_args(
        &args.vault,
        args.passphrase_file.as_deref(),
        args.session_token.as_deref(),
    )?;

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
        return Err(format!("URI type must be `totp` or `hotp`, got `{kind}`"));
    }

    // Parse + URL-decode query parameters. Reject bare-key pairs
    // (e.g. `?issuer&digits=6`) per RFC 3986 — that form is invalid
    // and silently accepting it was producing empty-value params.
    let mut params = std::collections::HashMap::<String, String>::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k_enc, v_enc) = pair
            .split_once('=')
            .ok_or_else(|| format!("URI query pair missing `=`: `{pair}`"))?;
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
            None => return Err("HOTP URI missing required `counter` query parameter".to_string()),
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
    if args.session_token.is_some() {
        return Err(
            "--session-token is not supported with change-passphrase: rotating the passphrase \
             re-encrypts the vault under a new master key, which invalidates any existing token. \
             Use --passphrase-file."
                .to_string(),
        );
    }
    let path = resolve_vault_path(&args.vault)?;
    // Read the existing tier from the vault header BEFORE unlocking (we
    // need the tier to call `change_vault_passphrase`, but the function
    // reads the header itself; we lock it by reading just the header).
    let current = resolve_passphrase(args.passphrase_file.as_deref())?;

    // Probe the file to recover the existing tier — preserves user's
    // original choice (Nano / Standard / Sovereign).
    let header_bytes =
        std::fs::read(&path).map_err(|e| format!("cannot read vault {}: {e}", path.display()))?;
    if header_bytes.len() < vault::HEADER_BYTES_LEN {
        return Err(format!(
            "vault file too short: {} bytes",
            header_bytes.len()
        ));
    }
    let header = vault::VaultHeader::from_wire(&header_bytes[..vault::HEADER_BYTES_LEN])?;
    let tier = header.kdf_tier;
    // header and header_bytes are consumed below; no explicit drop needed

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

/// Generate a random password or word-based passphrase.
///
/// The secret goes to **stdout** (so it can be piped into
/// `add --secret-stdin`); the entropy estimate goes to **stderr** so it
/// never contaminates a pipeline.
pub fn cmd_generate(args: GenerateArgs) -> Result<(), String> {
    if args.passphrase {
        let words = args.words;
        if !(1..=64).contains(&words) {
            return Err(format!("--words out of range (1..=64): {words}"));
        }
        let phrase = generate::generate_passphrase(words)?;
        let bits = generate::passphrase_entropy_bits(words);
        println!("{phrase}");
        eprintln!("entropy: {bits:.1} bits ({words} words × {:.1} bits/word)", (generate::WORDLIST.len() as f64).log2());
        return Ok(());
    }

    let length = args.length;
    if !(generate::MIN_LENGTH..=generate::MAX_LENGTH).contains(&length) {
        return Err(format!(
            "--length out of range ({}..={}): {length}",
            generate::MIN_LENGTH,
            generate::MAX_LENGTH
        ));
    }
    let charset = generate::build_charset(args.exclude_symbols, args.exclude_digits, args.exclude_upper)?;
    let password = generate::generate_password(length, &charset)?;
    let bits = generate::password_entropy_bits(length, &charset);
    println!("{password}");
    eprintln!("entropy: {bits:.1} bits ({length} chars × {:.1} bits/char)", (charset.len() as f64).log2());
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
// Dispatch
// ──────────────────────────────────────────────────────────────────────

/// Dispatch a parsed CLI to the matching command implementation.
pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    use crate::cli::Commands;
    match cli.command {
        Commands::Init(args) => cmd_init(args),
        Commands::Unlock(args) => cmd_unlock(args),
        Commands::Lock(args) => cmd_lock(args),
        Commands::LockAll(args) => cmd_lock_all(args),
        Commands::Add(args) => cmd_add(args),
        Commands::Get(args) => cmd_get(args),
        Commands::List(args) => cmd_list(args),
        Commands::Rm(args) => cmd_rm(args),
        Commands::Code(args) => cmd_code(args),
        Commands::ExportQr(args) => cmd_export_qr(args),
        Commands::ImportQr(args) => cmd_import_qr(args),
        Commands::ChangePassphrase(args) => cmd_change_passphrase(args),
        Commands::Generate(args) => cmd_generate(args),
        Commands::Tokens(args) => cmd_tokens(args),
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
        let code = compute_ocra_code(
            key.path(),
            "00000000",
            0,
            6,
            crate::cli::HashAlgorithm::Sha1,
        )
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
        let c0 = compute_ocra_code(
            key.path(),
            "12345678",
            0,
            6,
            crate::cli::HashAlgorithm::Sha1,
        )
        .expect("c0");
        let c1 = compute_ocra_code(
            key.path(),
            "12345678",
            1,
            6,
            crate::cli::HashAlgorithm::Sha1,
        )
        .expect("c1");
        assert_ne!(c0.numeric, c1.numeric);
    }

    #[test]
    fn challenge_change_changes_response_sha1() {
        let key = write_key(b"12345678901234567890");
        let c0 = compute_ocra_code(
            key.path(),
            "00000000",
            0,
            6,
            crate::cli::HashAlgorithm::Sha1,
        )
        .expect("c0");
        let c1 = compute_ocra_code(
            key.path(),
            "12345678",
            0,
            6,
            crate::cli::HashAlgorithm::Sha1,
        )
        .expect("c1");
        assert_ne!(c0.numeric, c1.numeric);
    }

    #[test]
    fn short_key_rejected() {
        let short_key: [u8; 15] = [1u8; 15];
        assert_eq!(short_key.len(), 15);
        let key = write_key(&short_key);
        let err = compute_ocra_code(
            key.path(),
            "00000000",
            0,
            6,
            crate::cli::HashAlgorithm::Sha1,
        )
        .expect_err("must reject 15-byte key");
        assert!(err.contains("InvalidKeyLength") || err.contains("key"));
    }

    #[test]
    fn digits_out_of_range_rejected() {
        let key = write_key(b"12345678901234567890");
        let err3 = compute_ocra_code(
            key.path(),
            "00000000",
            0,
            3,
            crate::cli::HashAlgorithm::Sha1,
        )
        .expect_err("3 digits rejected");
        let err11 = compute_ocra_code(
            key.path(),
            "00000000",
            0,
            11,
            crate::cli::HashAlgorithm::Sha1,
        )
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
            session_token: None,
            algo: None,
            digits: None,
            auto_clear: None,
            quiet: false,
            ocra: false,
            challenge: None,
            counter: None,
            key_file: None,
            pin: None,
            force: false,
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
            session_ttl: 3600,
            auto_rotate: false,
            auto_rotate_threshold: None,
            auto_rotate_ttl: None,
        })
        .unwrap();
        cmd_list(ListArgs {
            vault: path.to_string_lossy().to_string(),
            passphrase_file: Some(pp.to_string_lossy().to_string()),
            session_token: None,
        })
        .unwrap();
    }

    #[test]
    fn cmd_lock_without_token_errors() {
        // v0.5 keeps no in-process vault state, so `lock` must be told
        // which session token to revoke — a bare `lock` is a no-op with
        // nothing to do and must say so.
        let err = cmd_lock(LockArgs { session_token: None }).expect_err("bare lock must error");
        assert!(
            err.contains("session-token"),
            "error should point at --session-token, got: {err}"
        );
    }

    #[test]
    fn cmd_lock_with_missing_token_file_errors() {
        let dir = fresh_vault_dir();
        let missing = dir.path().join("no-such.token");
        let err = cmd_lock(LockArgs {
            session_token: Some(missing.clone()),
        })
        .expect_err("missing token file must error");
        assert!(err.contains("not found"), "error: {err}");
    }

    #[test]
    fn cmd_tokens_revoke_and_revoke_all() {
        let dir = fresh_vault_dir();
        let store = dir.path().join("tokens");
        let key = zeroize::Zeroizing::new([7u8; 32]);
        session::write_session_token(&store.join("work.token"), &key, 3600, None, None).unwrap();
        session::write_session_token(&store.join("home.token"), &key, 3600, None, None).unwrap();

        // Revoke a single token by bare name, resolved into the custom store.
        cmd_tokens(TokensArgs {
            command: TokensCommand::Revoke(crate::cli::TokensRevokeArgs {
                name: "work".to_string(),
                dir: store.to_string_lossy().to_string(),
            }),
        })
        .unwrap();
        assert!(!store.join("work.token").exists(), "revoked token must be deleted");
        assert!(store.join("home.token").exists(), "other tokens must survive");

        // Revoking the same name again must error (surfaces typos).
        let err = cmd_tokens(TokensArgs {
            command: TokensCommand::Revoke(crate::cli::TokensRevokeArgs {
                name: "work".to_string(),
                dir: store.to_string_lossy().to_string(),
            }),
        })
        .expect_err("second revoke must fail");
        assert!(err.contains("nothing to revoke"), "error: {err}");

        // Revoke-all clears the remainder.
        cmd_tokens(TokensArgs {
            command: TokensCommand::RevokeAll(crate::cli::TokensRevokeAllArgs {
                dir: store.to_string_lossy().to_string(),
                expired_only: false,
            }),
        })
        .unwrap();
        assert!(session::list_tokens(&store).unwrap().is_empty());
    }

    #[test]
    fn cmd_tokens_revoke_all_expired_only_keeps_valid() {
        let dir = fresh_vault_dir();
        let store = dir.path().join("tokens");
        let key = zeroize::Zeroizing::new([7u8; 32]);
        session::write_session_token(&store.join("keep.token"), &key, 3600, None, None).unwrap();
        // Expired token: rewrite its expiry into the past via the file.
        session::write_session_token(&store.join("expired.token"), &key, 1, None, None).unwrap();
        {
            let mut t: session::SessionToken = serde_json::from_slice(
                &std::fs::read(store.join("expired.token")).unwrap(),
            )
            .unwrap();
            t.expires_at -= 100;
            origin_common::io::atomic_write(&store.join("expired.token"), &serde_json::to_vec(&t).unwrap())
                .unwrap();
        }

        cmd_tokens(TokensArgs {
            command: TokensCommand::RevokeAll(crate::cli::TokensRevokeAllArgs {
                dir: store.to_string_lossy().to_string(),
                expired_only: true,
            }),
        })
        .unwrap();

        let remaining: Vec<String> = session::list_tokens(&store)
            .unwrap()
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(
            remaining,
            vec!["keep.token"],
            "expired-only revoke must keep valid tokens"
        );
    }

    #[test]
    fn cmd_tokens_prune_removes_expired_and_unreadable_keeps_valid() {
        let dir = fresh_vault_dir();
        let store = dir.path().join("tokens");
        let key = zeroize::Zeroizing::new([7u8; 32]);
        session::write_session_token(&store.join("keep.token"), &key, 3600, None, None).unwrap();
        // Expired token: rewrite its expiry into the past via the file.
        session::write_session_token(&store.join("expired.token"), &key, 1, None, None).unwrap();
        {
            let mut t: session::SessionToken = serde_json::from_slice(
                &std::fs::read(store.join("expired.token")).unwrap(),
            )
            .unwrap();
            t.expires_at -= 100;
            origin_common::io::atomic_write(&store.join("expired.token"), &serde_json::to_vec(&t).unwrap())
                .unwrap();
        }
        // Unreadable (corrupt) token — prune cleans it too.
        std::fs::write(store.join("garbage.token"), b"not json").unwrap();

        cmd_tokens(TokensArgs {
            command: TokensCommand::Prune(crate::cli::TokensPruneArgs {
                dir: store.to_string_lossy().to_string(),
            }),
        })
        .unwrap();

        assert!(store.join("keep.token").exists(), "valid tokens must survive prune");
        assert!(!store.join("expired.token").exists(), "expired tokens must be pruned");
        assert!(
            !store.join("garbage.token").exists(),
            "unreadable tokens must be pruned"
        );

        // A second prune has nothing to do and is a success (lenient).
        cmd_tokens(TokensArgs {
            command: TokensCommand::Prune(crate::cli::TokensPruneArgs {
                dir: store.to_string_lossy().to_string(),
            }),
        })
        .unwrap();
        assert!(store.join("keep.token").exists());
    }

    #[test]
    fn cmd_tokens_list_empty_store_is_ok() {
        let dir = fresh_vault_dir();
        let store = dir.path().join("tokens");
        // A store dir that does not exist yet is an empty listing, not an error.
        cmd_tokens(TokensArgs {
            command: TokensCommand::List(crate::cli::TokensListArgs {
                dir: store.to_string_lossy().to_string(),
                format: TokensFormat::Table,
                remaining: None,
            }),
        })
        .unwrap();
        cmd_tokens(TokensArgs {
            command: TokensCommand::List(crate::cli::TokensListArgs {
                dir: store.to_string_lossy().to_string(),
                format: TokensFormat::Json,
                remaining: None,
            }),
        })
        .unwrap();
    }

    #[test]
    fn cmd_lock_all_revokes_everything_and_errors_when_empty() {
        let dir = fresh_vault_dir();
        let store = dir.path().join("tokens");
        let key = zeroize::Zeroizing::new([7u8; 32]);
        session::write_session_token(&store.join("a.token"), &key, 3600, None, None).unwrap();
        session::write_session_token(&store.join("b.token"), &key, 3600, None, None).unwrap();

        cmd_lock_all(LockAllArgs {
            dir: store.to_string_lossy().to_string(),
            vault: None,
        })
        .unwrap();
        assert!(
            session::list_tokens(&store).unwrap().is_empty(),
            "lock-all must revoke every token"
        );

        // Idempotency guard: a second lock-all with nothing left errors.
        let err = cmd_lock_all(LockAllArgs {
            dir: store.to_string_lossy().to_string(),
            vault: None,
        })
        .expect_err("empty store must error like bare lock");
        assert!(err.contains("nothing to lock"), "error: {err}");
    }

    #[test]
    fn cmd_lock_all_vault_filter_only_revokes_matching() {
        let dir = fresh_vault_dir();
        let store = dir.path().join("tokens");
        let key = zeroize::Zeroizing::new([7u8; 32]);
        session::write_session_token(
            &store.join("a.token"),
            &key,
            3600,
            Some(Path::new("/vaults/a.vault")),
            None,
        )
        .unwrap();
        session::write_session_token(
            &store.join("b.token"),
            &key,
            3600,
            Some(Path::new("/vaults/b.vault")),
            None,
        )
        .unwrap();

        cmd_lock_all(LockAllArgs {
            dir: store.to_string_lossy().to_string(),
            vault: Some("/vaults/a.vault".to_string()),
        })
        .unwrap();

        assert!(!store.join("a.token").exists(), "matching token must be revoked");
        assert!(
            store.join("b.token").exists(),
            "tokens bound to other vaults must survive"
        );

        // Nothing bound to a vault with no tokens → error.
        let err = cmd_lock_all(LockAllArgs {
            dir: store.to_string_lossy().to_string(),
            vault: Some("/vaults/ghost.vault".to_string()),
        })
        .expect_err("no matching tokens must error");
        assert!(err.contains("nothing to lock"), "error: {err}");
    }

    #[test]
    fn cmd_tokens_rotate_refreshes_token_in_place() {
        let dir = fresh_vault_dir();
        let store = dir.path().join("tokens");
        let key = zeroize::Zeroizing::new([7u8; 32]);
        let original =
        session::write_session_token(&store.join("work.token"), &key, 3600, Some(Path::new("/v/a.vault")), None)
            .unwrap();

        cmd_tokens(TokensArgs {
            command: TokensCommand::Rotate(crate::cli::TokensRotateArgs {
                name: "work".to_string(),
                dir: store.to_string_lossy().to_string(),
                ttl: Some(7200),
            }),
        })
        .unwrap();

        let rotated = session::parse_token_file(&store.join("work.token")).unwrap();
        assert_ne!(
            rotated.token_id, original.token_id,
            "rotation must mint a new token id"
        );
        assert_ne!(
            rotated.token_key, original.token_key,
            "rotation must mint a new bearer key"
        );
        assert_eq!(
            rotated.expires_at - rotated.created_at,
            7200,
            "--ttl must set the new lifetime"
        );
        assert_eq!(
            rotated.vault.as_deref(),
            Some("/v/a.vault"),
            "rotation must preserve the vault binding"
        );
        // The unsealed master key is unchanged, so the rotated token still unlocks.
        assert_eq!(
            session::read_session_token(&store.join("work.token")).unwrap().as_ref(),
            key.as_ref()
        );
    }

    #[test]
    fn cmd_tokens_rotate_defaults_to_original_ttl() {
        let dir = fresh_vault_dir();
        let store = dir.path().join("tokens");
        let key = zeroize::Zeroizing::new([7u8; 32]);
        session::write_session_token(&store.join("work.token"), &key, 3600, None, None).unwrap();

        cmd_tokens(TokensArgs {
            command: TokensCommand::Rotate(crate::cli::TokensRotateArgs {
                name: "work".to_string(),
                dir: store.to_string_lossy().to_string(),
                ttl: None,
            }),
        })
        .unwrap();

        let rotated = session::parse_token_file(&store.join("work.token")).unwrap();
        assert_eq!(
            rotated.expires_at - rotated.created_at,
            3600,
            "without --ttl, rotation preserves the original lifetime"
        );
    }

    #[test]
    fn build_auto_rotate_validates_flags() {
        let base = UnlockArgs {
            vault: "v".to_string(),
            tier: "nano".to_string(),
            passphrase_file: None,
            session_token: None,
            session_ttl: 3600,
            auto_rotate: false,
            auto_rotate_threshold: None,
            auto_rotate_ttl: None,
        };

        // Off by default → no policy.
        assert!(build_auto_rotate(&base).unwrap().is_none());

        // Policy-specific flags without --auto-rotate are rejected.
        for tweak in [
            |a: &mut UnlockArgs| a.auto_rotate_threshold = Some(60),
            |a: &mut UnlockArgs| a.auto_rotate_ttl = Some(7200),
        ] {
            let mut bad = base.clone();
            tweak(&mut bad);
            let err = build_auto_rotate(&bad).expect_err("must reject orphan flags");
            assert!(err.contains("--auto-rotate"), "error: {err}");
        }

        // Enabled → sensible defaults (threshold 15m, ttl = session ttl).
        let mut on = base.clone();
        on.auto_rotate = true;
        let cfg = build_auto_rotate(&on).unwrap().unwrap();
        assert_eq!(cfg.threshold, session::DEFAULT_AUTO_ROTATE_THRESHOLD_SECS);
        assert_eq!(cfg.ttl, 3600);

        // Explicit overrides win.
        let mut ov = base.clone();
        ov.auto_rotate = true;
        ov.auto_rotate_threshold = Some(60);
        ov.auto_rotate_ttl = Some(7200);
        let cfg = build_auto_rotate(&ov).unwrap().unwrap();
        assert_eq!(cfg.threshold, 60);
        assert_eq!(cfg.ttl, 7200);
    }

    #[test]
    fn expires_within_predicate() {
        let mk = |expires_at: i64, unreadable: bool| session::TokenInfo {
            name: "t".to_string(),
            path: PathBuf::from("/t"),
            token_id: String::new(),
            created_at: 0,
            expires_at,
            vault: None,
            unreadable,
            auto_rotate: false,
            auto_rotate_threshold: None,
            auto_rotate_ttl: None,
        };
        let now = 1_000_000i64;
        // Expiring in 60s → within 2 minutes.
        assert!(expires_within(&mk(now + 60, false), now, 2));
        // Expiring in 3 minutes → not within 2 minutes.
        assert!(!expires_within(&mk(now + 180, false), now, 2));
        // Already expired always matches.
        assert!(expires_within(&mk(now - 5, false), now, 2));
        // Unreadable files never match (no expiry to judge).
        assert!(!expires_within(&mk(now - 5, true), now, 2));
    }

    #[test]
    fn cmd_tokens_renew_keeps_bearer_key() {
        let dir = fresh_vault_dir();
        let store = dir.path().join("tokens");
        let key = zeroize::Zeroizing::new([7u8; 32]);
        let original =
            session::write_session_token(&store.join("work.token"), &key, 30, Some(Path::new("/v/a.vault")), None)
                .unwrap();

        cmd_tokens(TokensArgs {
            command: TokensCommand::Renew(crate::cli::TokensRenewArgs {
                name: "work".to_string(),
                dir: store.to_string_lossy().to_string(),
                ttl: Some(7200),
            }),
        })
        .unwrap();

        let renewed = session::parse_token_file(&store.join("work.token")).unwrap();
        assert_eq!(renewed.token_id, original.token_id, "renew must keep the token id");
        assert_eq!(renewed.token_key, original.token_key, "renew must keep the bearer key");
        assert_ne!(renewed.expires_at, original.expires_at, "renew must extend expiry");
        let remaining = renewed.expires_at - unix_now();
        assert!(
            (7199..=7200).contains(&remaining),
            "--ttl must set the new window, got remaining {remaining}s"
        );
        // The vault binding survives and the token still unseals.
        assert_eq!(renewed.vault.as_deref(), Some("/v/a.vault"));
        assert_eq!(
            session::read_session_token(&store.join("work.token")).unwrap().as_ref(),
            key.as_ref()
        );
    }

    #[test]
    fn cmd_tokens_rotate_expired_token_errors() {
        let dir = fresh_vault_dir();
        let store = dir.path().join("tokens");
        let key = zeroize::Zeroizing::new([7u8; 32]);
        session::write_session_token(&store.join("work.token"), &key, 1, None, None).unwrap();
        // Backdate the expiry into the past.
        {
            let mut t: session::SessionToken = serde_json::from_slice(
                &std::fs::read(store.join("work.token")).unwrap(),
            )
            .unwrap();
            t.expires_at -= 100;
            origin_common::io::atomic_write(&store.join("work.token"), &serde_json::to_vec(&t).unwrap())
                .unwrap();
        }

        let err = cmd_tokens(TokensArgs {
            command: TokensCommand::Rotate(crate::cli::TokensRotateArgs {
                name: "work".to_string(),
                dir: store.to_string_lossy().to_string(),
                ttl: Some(3600),
            }),
        })
        .expect_err("expired tokens cannot be rotated");
        assert!(err.contains("expired"), "error: {err}");
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
                0,
            ))
            .unwrap();
        vault::persist_vault(&path, &vault_obj).unwrap();

        // Run cmd_code --ocra against the vault.
        cmd_code(CodeArgs {
            vault: path.to_string_lossy().to_string(),
            name: "bank-ocra".to_string(),
            passphrase_file: Some(pp.to_string_lossy().to_string()),
            session_token: None,
            algo: Some(crate::cli::HashAlgorithm::Sha1),
            digits: Some(6),
            auto_clear: None,
            quiet: false,
            ocra: true,
            challenge: Some("00000000".to_string()),
            counter: None,
            key_file: None,
            pin: None,
            force: false,
        })
        .expect("cmd_code via vault lookup");

        // And the wrong entry name should fail.
        let err = cmd_code(CodeArgs {
            vault: path.to_string_lossy().to_string(),
            name: "no-such-entry".to_string(),
            passphrase_file: Some(pp.to_string_lossy().to_string()),
            session_token: None,
            algo: Some(crate::cli::HashAlgorithm::Sha1),
            digits: Some(6),
            auto_clear: None,
            quiet: false,
            ocra: true,
            challenge: Some("00000000".to_string()),
            counter: None,
            key_file: None,
            pin: None,
            force: false,
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
            session_token: None,
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
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
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
            session_token: None,
            suite: None,
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
            session_token: None,
            algo: None,
            digits: None,
            auto_clear: None,
            quiet: false,
            ocra: false,
            challenge: None,
            counter: None,
            key_file: None,
            pin: None,
            force: false,
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
            session_token: None,
            suite: None,
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
        assert!(
            err.contains("vault") || err.contains("TOTP"),
            "error: {err}"
        );
    }
}
