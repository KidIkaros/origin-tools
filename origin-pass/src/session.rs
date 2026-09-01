// SPDX-License-Identifier: Apache-2.0

//! Persisted session tokens — `origin-pass unlock --session-token <path>`.
//!
//! # What a token is
//!
//! A session token file is a **bearer credential** (like an SSH private
//! key): whoever holds the file can unlock the vault without the
//! passphrase until the token expires. The vault master key is sealed
//! (ChaCha20-BLAKE3 AEAD) with a fresh random token key that lives in
//! the same file, so:
//!
//! - the master key never appears in cleartext on disk (a hexdump of the
//!   token shows only ciphertext), and
//! - tampering or truncation is detected on read (AEAD tag failure)
//!   instead of silently producing a garbage key.
//!
//! The seal is *not* a second factor — possession of the file is the
//! credential, exactly like `~/.ssh/id_ed25519`. Protect it accordingly
//! (the file is written with mode 0600 on Unix). Tokens carry an expiry
//! (`--session-ttl`, default 8h) so a leaked file degrades over time.

use std::path::{Path, PathBuf};

use origin_common::random_bytes;
use origin_crypto_sdk::chacha20_blake3::ChaCha20Blake3;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Current wire format version.
pub const SESSION_TOKEN_VERSION: u32 = 1;

/// AEAD additional data — binds the seal to this application + format.
const SESSION_TOKEN_AAD: &[u8] = b"origin-pass session token v1";

/// Length of the random token key (32 bytes).
const TOKEN_KEY_LEN: usize = 32;
/// Length of the random token id (16 bytes, hex-encoded to 32 chars).
const TOKEN_ID_LEN: usize = 16;
/// Nonce length for ChaCha20-BLAKE3 (24 bytes).
const NONCE_LEN: usize = 24;

/// Default token lifetime when `--session-ttl` is not given (8 hours).
pub const DEFAULT_SESSION_TTL_SECS: u64 = 8 * 60 * 60;

/// Default auto-rotate threshold (15 minutes): a command using the token
/// refreshes it when less than this much lifetime remains.
pub const DEFAULT_AUTO_ROTATE_THRESHOLD_SECS: u64 = 15 * 60;

/// Auto-rotate policy stored in a token (written by `unlock --auto-rotate`).
/// While a token with this config is used by any command, `maybe_auto_rotate`
/// refreshes it in place once its remaining lifetime drops below
/// `threshold` — extending the session without a passphrase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AutoRotateConfig {
    /// Rotate when remaining lifetime drops below this many seconds.
    pub threshold: u64,
    /// Fresh lifetime in seconds after rotation.
    pub ttl: u64,
}

/// On-disk session token (JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken {
    pub version: u32,
    /// Random identifier, hex-encoded (uniqueness / rotation marker).
    pub token_id: String,
    /// Unix seconds at creation.
    pub created_at: i64,
    /// Unix seconds after which the token is refused.
    pub expires_at: i64,
    /// Hex-encoded 24-byte AEAD nonce.
    pub nonce: String,
    /// Hex-encoded 32-byte token key (the file's bearer secret).
    pub token_key: String,
    /// Hex-encoded sealed vault master key.
    pub sealed_master_key: String,
    /// Vault file this token unlocks (informational, for `tokens list`).
    /// `#[serde(default)]` keeps tokens written before v0.5 readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    /// Optional auto-rotate policy. `#[serde(default)]` keeps tokens
    /// written before v0.5.1 readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_rotate: Option<AutoRotateConfig>,
}

/// Write a session token sealing `master_key`, valid for `ttl_secs`,
/// to `path` (created with mode 0600 on Unix). `vault` is recorded for
/// `tokens list` (not used for unlocking). `auto_rotate` is persisted
/// in the file and honored by [`maybe_auto_rotate`] on every use.
pub fn write_session_token(
    path: &Path,
    master_key: &Zeroizing<[u8; 32]>,
    ttl_secs: u64,
    vault: Option<&Path>,
    auto_rotate: Option<AutoRotateConfig>,
) -> Result<SessionToken, String> {
    if ttl_secs == 0 {
        return Err("token ttl must be ≥ 1 second".to_string());
    }
    let now = unix_now();

    let mut token_id_bytes = [0u8; TOKEN_ID_LEN];
    random_bytes(&mut token_id_bytes).map_err(|e| format!("token id generation failed: {e}"))?;
    let mut token_key = [0u8; TOKEN_KEY_LEN];
    random_bytes(&mut token_key).map_err(|e| format!("token key generation failed: {e}"))?;
    let nonce = ChaCha20Blake3::generate_nonce();

    let sealed = ChaCha20Blake3::encrypt(&token_key, &nonce, master_key.as_ref(), SESSION_TOKEN_AAD)
        .map_err(|e| format!("session token seal failed: {e:?}"))?;

    let token = SessionToken {
        version: SESSION_TOKEN_VERSION,
        token_id: hex::encode(token_id_bytes),
        created_at: now,
        expires_at: now + ttl_secs as i64,
        nonce: hex::encode(nonce),
        token_key: hex::encode(token_key),
        sealed_master_key: hex::encode(&sealed),
        vault: vault.map(|p| p.display().to_string()),
        auto_rotate,
    };

    let json = serde_json::to_vec_pretty(&token)
        .map_err(|e| format!("session token serialize failed: {e}"))?;
    atomic_write_mode_600(path, &json)?;
    // Scrub the in-memory token key copy.
    token_key.fill(0);
    Ok(token)
}

/// Read a token file and validate its envelope (JSON, version, expiry).
/// Shared by `read_session_token` and `rotate_session_token`; also
/// useful for inspecting a token without unsealing it.
pub fn parse_token_file(path: &Path) -> Result<SessionToken, String> {
    let raw = std::fs::read(path)
        .map_err(|e| format!("cannot read session token {}: {e}", path.display()))?;
    let token: SessionToken = serde_json::from_slice(&raw)
        .map_err(|e| format!("session token {} is not valid JSON: {e}", path.display()))?;

    if token.version != SESSION_TOKEN_VERSION {
        return Err(format!(
            "session token version mismatch: got {}, expected {SESSION_TOKEN_VERSION}",
            token.version
        ));
    }
    let now = unix_now();
    if now >= token.expires_at {
        return Err(format!(
            "session token expired at {} (now {now}) — run `origin-pass unlock --session-token <path>` again",
            token.expires_at
        ));
    }
    Ok(token)
}

/// Unseal the vault master key from a validated token. Errors on AEAD
/// tamper detection (file modified in place).
fn unseal_master_key(token: &SessionToken) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut nonce = [0u8; NONCE_LEN];
    hex::decode_to_slice(&token.nonce, &mut nonce)
        .map_err(|_| "session token nonce is corrupt".to_string())?;
    let mut token_key = [0u8; TOKEN_KEY_LEN];
    hex::decode_to_slice(&token.token_key, &mut token_key)
        .map_err(|_| "session token key is corrupt".to_string())?;
    let sealed = hex::decode(&token.sealed_master_key)
        .map_err(|_| "session token sealed key is corrupt".to_string())?;

    let mut plain = ChaCha20Blake3::decrypt(&token_key, &nonce, &sealed, SESSION_TOKEN_AAD)
        .map_err(|_| {
            "session token unseal failed — file tampered or truncated; re-run `origin-pass unlock`".to_string()
        })?;
    if plain.len() != 32 {
        return Err(format!(
            "session token sealed key is {} bytes; expected 32",
            plain.len()
        ));
    }
    let mut master = Zeroizing::new([0u8; 32]);
    master.copy_from_slice(&plain);
    // Scrub every local copy of the master key material.
    plain.fill(0);
    token_key.fill(0);
    Ok(master)
}

/// Read and unseal a session token, returning the vault master key.
/// Errors on: missing/corrupt file, unknown version, expiry, or AEAD
/// tamper detection.
pub fn read_session_token(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let token = parse_token_file(path)?;
    unseal_master_key(&token)
}

/// Rotate a session token in place: unseal the master key from the
/// *current* token (no passphrase needed), then write a fresh token —
/// new token id, new bearer key, new nonce, new expiry — to the same
/// path, preserving the vault binding. This extends a still-valid
/// session without re-entering the passphrase; it does **not** revoke
/// copies of the old file (use `lock` / `tokens revoke` for that).
///
/// `ttl_secs`: new lifetime; `None` preserves the token's original
/// lifetime. Errors on missing/corrupt/expired tokens — an expired
/// token must be re-minted with `unlock --session-token` (passphrase).
/// An existing auto-rotate policy is preserved.
pub fn rotate_session_token(path: &Path, ttl_secs: Option<u64>) -> Result<SessionToken, String> {
    let token = parse_token_file(path)?;
    let master = unseal_master_key(&token)?;
    let ttl = ttl_secs.unwrap_or_else(|| (token.expires_at - token.created_at).max(1) as u64);
    let vault = token.vault.as_deref().map(Path::new);
    write_session_token(path, &master, ttl, vault, token.auto_rotate)
}

/// Renew a still-valid token in place **without minting a new bearer
/// key**: the token id, token key, nonce, and AEAD seal are untouched —
/// only `expires_at` is pushed forward. Use this when the current key
/// is trusted and you only need more time (contrast [`rotate_session_token`],
/// which mints a fresh key). `ttl_secs` (default: the token's lifetime
/// span from creation to its current expiry) sets the new window from
/// now; the auto-rotate policy is preserved. Errors on
/// missing/corrupt/expired tokens.
pub fn renew_session_token(path: &Path, ttl_secs: Option<u64>) -> Result<SessionToken, String> {
    let mut token = parse_token_file(path)?;
    let ttl = ttl_secs.unwrap_or_else(|| (token.expires_at - token.created_at).max(1) as u64);
    token.expires_at = unix_now() + ttl as i64;
    let json = serde_json::to_vec_pretty(&token)
        .map_err(|e| format!("session token serialize failed: {e}"))?;
    atomic_write_mode_600(path, &json)?;
    Ok(token)
}

/// Auto-rotate a token on use, if its policy requires it. Call after a
/// successful [`read_session_token`]: when the token carries an
/// `auto_rotate` policy and less than `threshold` lifetime remains, it
/// is rotated in place (fresh bearer key, nonce, and expiry; vault
/// binding and policy preserved) and `true` is returned. A token
/// without a policy, or one still above the threshold, is untouched.
///
/// If the file disappeared or expired between the read and this call,
/// the rotation is skipped silently — the caller already holds the
/// unsealed key, so the command proceeds with the token it has.
pub fn maybe_auto_rotate(path: &Path) -> Result<bool, String> {
    let token = match parse_token_file(path) {
        Ok(t) => t,
        Err(_) => return Ok(false),
    };
    let Some(cfg) = token.auto_rotate else {
        return Ok(false);
    };
    let remaining = token.expires_at - unix_now();
    if remaining >= cfg.threshold as i64 {
        return Ok(false);
    }
    rotate_session_token(path, Some(cfg.ttl))?;
    Ok(true)
}

/// Revoke a session token by deleting its file. Errors if the file does
/// not exist (so a typo'd path is surfaced rather than silently ignored).
pub fn revoke_session_token(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!(
            "session token not found: {} (nothing to revoke)",
            path.display()
        ));
    }
    std::fs::remove_file(path)
        .map_err(|e| format!("cannot remove session token {}: {e}", path.display()))
}

// ──────────────────────────────────────────────────────────────────────
// Token store (~/.origin/tokens) + `tokens` command support
// ──────────────────────────────────────────────────────────────────────

/// The managed token store directory: `~/.origin/tokens`.
pub fn token_store_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME")
        .map_err(|_| "$HOME is unset; cannot resolve ~/.origin/tokens. Pass an explicit path.".to_string())?;
    Ok(PathBuf::from(home).join(".origin").join("tokens"))
}

/// Expand a `~/` prefix against `$HOME` (same rule as vault paths).
pub fn resolve_store_dir(raw: &str) -> Result<PathBuf, String> {
    if let Some(rest) = raw.strip_prefix("~/") {
        let home = std::env::var("HOME").map_err(|_| {
            "$HOME is unset; cannot expand ~/ paths. Pass an absolute path instead.".to_string()
        })?;
        Ok(PathBuf::from(home).join(rest))
    } else {
        Ok(PathBuf::from(raw))
    }
}

/// Resolve a `--session-token` value to a concrete file path.
///
/// A **bare name** (no path separators, not `./`-prefixed, not `~`)
/// resolves into the managed store: `work` → `~/.origin/tokens/work.token`.
/// Everything else is treated as a literal path (with `~/` expansion), so
/// existing absolute / relative usage keeps working unchanged.
///
/// All token-consuming commands (`unlock`, `lock`, and every command
/// that accepts `--session-token`) route through this, so the managed
/// store and ad-hoc paths coexist.
/// Expand a leading `~/` against `$HOME`; everything else is returned
/// untouched. Shared by `resolve_token_path` and `resolve_token_path_in`.
fn expand_tilde(raw: &str) -> Result<PathBuf, String> {
    if let Some(rest) = raw.strip_prefix("~/") {
        let home = std::env::var("HOME").map_err(|_| {
            "$HOME is unset; cannot expand ~/ paths. Pass an absolute path instead.".to_string()
        })?;
        Ok(PathBuf::from(home).join(rest))
    } else {
        Ok(PathBuf::from(raw))
    }
}

/// Resolve a `--session-token` value to a concrete file path.
///
/// A **bare name** (no path separators, not `./`-prefixed, not `~`)
/// resolves into the managed store: `work` → `~/.origin/tokens/work.token`.
/// Everything else is treated as a literal path (with `~/` expansion), so
/// existing absolute / relative usage keeps working unchanged.
///
/// All token-consuming commands (`unlock`, `lock`, and every command
/// that accepts `--session-token`) route through this, so the managed
/// store and ad-hoc paths coexist.
pub fn resolve_token_path(raw: &str) -> Result<PathBuf, String> {
    resolve_token_path_in(&token_store_dir()?, raw)
}

/// Like [`resolve_token_path`], but bare names resolve against an
/// explicit store directory instead of `~/.origin/tokens`. Used by
/// `tokens revoke --dir <dir> <name>` so a custom store and the
/// default store behave identically.
pub fn resolve_token_path_in(dir: &Path, raw: &str) -> Result<PathBuf, String> {
    let expanded = expand_tilde(raw)?;
    let looks_like_path = raw.starts_with("/")
        || raw.starts_with(".")
        || raw.starts_with("~")
        || expanded.components().count() > 1;
    if looks_like_path {
        Ok(expanded)
    } else {
        Ok(dir.join(format!("{raw}.token")))
    }
}

/// Metadata about one token file, for `tokens list` (no decryption).
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub name: String,
    pub path: PathBuf,
    pub token_id: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub vault: Option<String>,
    /// True when the file exists but is not parseable (corrupt / foreign).
    pub unreadable: bool,
    /// True when the token carries an auto-rotate policy.
    pub auto_rotate: bool,
    /// Auto-rotate threshold in seconds (None without a policy).
    pub auto_rotate_threshold: Option<u64>,
    /// Auto-rotate fresh lifetime in seconds (None without a policy).
    pub auto_rotate_ttl: Option<u64>,
}

/// Parse a token file's metadata without unsealing it. Unreadable files
/// are surfaced as `unreadable: true` (so `tokens list` can show them)
/// rather than erroring the whole listing.
pub fn read_token_metadata(path: &Path) -> Result<TokenInfo, String> {
    let raw = std::fs::read(path)
        .map_err(|e| format!("cannot read session token {}: {e}", path.display()))?;
    let parsed: Result<SessionToken, _> = serde_json::from_slice(&raw);
    let token = match parsed {
        Ok(t) => t,
        // Unreadable files are listed (so `tokens revoke` can clean them
        // up) rather than failing the whole listing.
        Err(_) => {
            return Ok(TokenInfo {
                name: path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| path.display().to_string()),
                path: path.to_path_buf(),
                token_id: String::new(),
                created_at: 0,
                expires_at: 0,
                vault: None,
                unreadable: true,
                auto_rotate: false,
                auto_rotate_threshold: None,
                auto_rotate_ttl: None,
            })
        }
    };
    Ok(TokenInfo {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string()),
        path: path.to_path_buf(),
        token_id: token.token_id,
        created_at: token.created_at,
        expires_at: token.expires_at,
        vault: token.vault,
        unreadable: false,
        auto_rotate: token.auto_rotate.is_some(),
        auto_rotate_threshold: token.auto_rotate.map(|c| c.threshold),
        auto_rotate_ttl: token.auto_rotate.map(|c| c.ttl),
    })
}

/// List token files in `dir`, sorted by name. A missing dir is an empty
/// list; a dir that exists but is unreadable is an error.
pub fn list_tokens(dir: &Path) -> Result<Vec<TokenInfo>, String> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read token store {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read token store entry: {e}"))?;
        let path = entry.path();
        // Only manage `*.token` files — a store dir may legitimately
        // contain other files, and `revoke-all` must never touch them.
        if !path.is_file() || path.extension().map(|e| e != "token").unwrap_or(true) {
            continue;
        }
        if let Ok(info) = read_token_metadata(&path) {
            out.push(info);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Revoke every token in `dir` (optionally only expired ones). Returns
/// the number of tokens revoked. A missing dir revokes nothing.
pub fn revoke_all_tokens(dir: &Path, expired_only: bool) -> Result<usize, String> {
    if !dir.exists() {
        return Ok(0);
    }
    let now = unix_now();
    let mut revoked = 0usize;
    for info in list_tokens(dir)? {
        if expired_only && !info.unreadable && now < info.expires_at {
            continue;
        }
        std::fs::remove_file(&info.path)
            .map_err(|e| format!("cannot remove {}: {e}", info.path.display()))?;
        revoked += 1;
    }
    Ok(revoked)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Atomic write (tmp + rename) with mode 0600 on Unix.
fn atomic_write_mode_600(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create token dir {}: {e}", parent.display()))?;
        }
    }
    origin_common::io::atomic_write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Zeroizing<[u8; 32]> {
        let mut k = Zeroizing::new([0u8; 32]);
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn write_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.token");
        let key = test_key();
        let token = write_session_token(&path, &key, 3600, None, None).unwrap();
        assert_eq!(token.version, SESSION_TOKEN_VERSION);
        assert!(path.exists());

        let recovered = read_session_token(&path).unwrap();
        assert_eq!(*recovered, *key);
    }

    #[test]
    fn vault_field_is_recorded_for_tokens_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.token");
        let key = test_key();
        let vault = dir.path().join("vault.opass");
        let token = write_session_token(&path, &key, 3600, Some(&vault), None).unwrap();
        assert_eq!(
            token.vault.as_deref(),
            Some(vault.to_str().unwrap()),
            "vault path must be recorded for `tokens list`"
        );
        // Old tokens without the field still read (serde default).
        let mut t = token.clone();
        t.vault = None;
        let json = serde_json::to_vec(&t).unwrap();
        origin_common::io::atomic_write(&path, &json).unwrap();
        assert_eq!(read_session_token(&path).unwrap().len(), 32);
    }

    #[test]
    fn expired_token_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.token");
        let key = test_key();
        let token = write_session_token(&path, &key, 1, None, None).unwrap();

        // Rewrite the expiry into the past.
        let mut t = token.clone();
        t.expires_at = unix_now() - 10;
        let json = serde_json::to_vec(&t).unwrap();
        origin_common::io::atomic_write(&path, &json).unwrap();

        let err = read_session_token(&path).expect_err("must refuse expired");
        assert!(err.contains("expired"));
    }

    #[test]
    fn tampered_token_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.token");
        let key = test_key();
        write_session_token(&path, &key, 3600, None, None).unwrap();

        // Flip a byte inside the sealed ciphertext.
        let mut raw = std::fs::read(&path).unwrap();
        let mut token: SessionToken = serde_json::from_slice(&raw).unwrap();
        let mut sealed = hex::decode(&token.sealed_master_key).unwrap();
        sealed[0] ^= 0x01;
        token.sealed_master_key = hex::encode(&sealed);
        raw = serde_json::to_vec(&token).unwrap();
        origin_common::io::atomic_write(&path, &raw).unwrap();

        let err = read_session_token(&path).expect_err("must refuse tampered");
        assert!(err.contains("tampered") || err.contains("unseal"));
    }

    #[test]
    fn revoke_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.token");
        write_session_token(&path, &test_key(), 3600, None, None).unwrap();
        assert!(path.exists());
        revoke_session_token(&path).unwrap();
        assert!(!path.exists());
        // Revoking a missing file is an error (surfaces typos).
        assert!(revoke_session_token(&path).is_err());
    }

    #[test]
    fn zero_ttl_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.token");
        let err = write_session_token(&path, &test_key(), 0, None, None).expect_err("must reject 0 ttl");
        assert!(err.contains("ttl"));
    }

    #[test]
    fn resolve_token_path_bare_name_goes_to_store() {
        // Bare names resolve into the managed store…
        let path = resolve_token_path("work").unwrap();
        assert_eq!(
            path,
            token_store_dir().unwrap().join("work.token"),
            "bare name must resolve into ~/.origin/tokens"
        );
        // …while paths stay literal (with ~/ expansion).
        let abs = resolve_token_path("/tmp/session.token").unwrap();
        assert_eq!(abs, PathBuf::from("/tmp/session.token"));
        let rel = resolve_token_path("./session.token").unwrap();
        assert_eq!(rel, PathBuf::from("./session.token"));
        let tild = resolve_token_path("~/origin/foo.token").unwrap();
        let home = std::env::var("HOME").unwrap();
        assert_eq!(tild, PathBuf::from(home).join("origin/foo.token"));
        let subdir = resolve_token_path("sub/dir/token").unwrap();
        assert_eq!(subdir, PathBuf::from("sub/dir/token"));
    }

    #[test]
    fn resolve_token_path_in_uses_custom_store() {
        let store = PathBuf::from("/tmp/custom-store");
        // Bare names resolve into the given store…
        assert_eq!(
            resolve_token_path_in(&store, "work").unwrap(),
            store.join("work.token")
        );
        // …while literal paths are untouched.
        assert_eq!(
            resolve_token_path_in(&store, "/abs/token").unwrap(),
            PathBuf::from("/abs/token")
        );
        assert_eq!(
            resolve_token_path_in(&store, "sub/dir/token").unwrap(),
            PathBuf::from("sub/dir/token")
        );
    }

    #[test]
    fn list_and_revoke_all() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_key();
        // Two valid tokens, one expired, one corrupt, one foreign file.
        write_session_token(&dir.path().join("a.token"), &key, 3600, Some(Path::new("/v/a.vault")), None)
            .unwrap();
        write_session_token(&dir.path().join("b.token"), &key, 3600, None, None).unwrap();
        write_session_token(&dir.path().join("c.token"), &key, 1, None, None).unwrap();
        // Expire c by rewriting its expiry into the past.
        {
            let mut t: SessionToken =
                serde_json::from_slice(&std::fs::read(dir.path().join("c.token")).unwrap()).unwrap();
            t.expires_at = unix_now() - 10;
            origin_common::io::atomic_write(&dir.path().join("c.token"), &serde_json::to_vec(&t).unwrap())
                .unwrap();
        }
        std::fs::write(dir.path().join("z.token"), b"not json").unwrap();
        std::fs::write(dir.path().join("ignore.txt"), b"x").unwrap();

        let listed = list_tokens(dir.path()).unwrap();
        let names: Vec<&str> = listed.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["a.token", "b.token", "c.token", "z.token"],
            "foreign files must be excluded from the store listing"
        );
        let a = listed.iter().find(|t| t.name == "a.token").unwrap();
        assert_eq!(a.vault.as_deref(), Some("/v/a.vault"));
        assert!(!a.unreadable);
        let z = listed.iter().find(|t| t.name == "z.token").unwrap();
        assert!(z.unreadable, "corrupt file must be surfaced, not crash the listing");

        // expired-only revocation clears expired + corrupt, keeps valid.
        assert_eq!(revoke_all_tokens(dir.path(), true).unwrap(), 2);
        let remaining: Vec<String> = list_tokens(dir.path())
            .unwrap()
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(remaining, vec!["a.token", "b.token"]);

        // full revocation clears everything; the foreign file survives.
        assert_eq!(revoke_all_tokens(dir.path(), false).unwrap(), 2);
        assert!(list_tokens(dir.path()).unwrap().is_empty());
        assert!(dir.path().join("ignore.txt").exists(), "foreign files must survive revoke-all");
    }

    #[test]
    fn renew_extends_expiry_without_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("work.token");
        let key = test_key();
        let cfg = AutoRotateConfig {
            threshold: 900,
            ttl: 3600,
        };
        let original = write_session_token(&path, &key, 30, Some(Path::new("/v/a.vault")), Some(cfg))
            .unwrap();

        let renewed = renew_session_token(&path, Some(3600)).unwrap();
        let remaining = renewed.expires_at - unix_now();
        assert!(
            (3599..=3600).contains(&remaining),
            "expiry must extend by the new ttl, got remaining {remaining}s"
        );
        // Unchanged-key rotation: id, key, nonce, seal, and vault all stay.
        assert_eq!(renewed.token_id, original.token_id, "renew must keep the token id");
        assert_eq!(renewed.token_key, original.token_key, "renew must keep the bearer key");
        assert_eq!(renewed.nonce, original.nonce, "renew must keep the nonce");
        assert_eq!(renewed.sealed_master_key, original.sealed_master_key, "renew must keep the seal");
        assert_eq!(renewed.vault, original.vault, "renew must keep the vault binding");
        assert!(renewed.auto_rotate.is_some(), "renew must keep the policy");
        // Still unseals to the same master key.
        assert_eq!(read_session_token(&path).unwrap().as_ref(), key.as_ref());

        // Without a ttl, a fresh token's lifetime span is preserved.
        let fresh = dir.path().join("fresh.token");
        write_session_token(&fresh, &key, 30, None, None).unwrap();
        let again = renew_session_token(&fresh, None).unwrap();
        let remaining = again.expires_at - unix_now();
        assert!(
            (29..=30).contains(&remaining),
            "lifetime span must be preserved, got remaining {remaining}s"
        );
    }

    #[test]
    fn renew_expired_token_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("work.token");
        write_session_token(&path, &test_key(), 1, None, None).unwrap();
        {
            let mut t: SessionToken =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            t.expires_at = unix_now() - 10;
            origin_common::io::atomic_write(&path, &serde_json::to_vec(&t).unwrap()).unwrap();
        }
        let err = renew_session_token(&path, Some(3600)).expect_err("expired token must be refused");
        assert!(err.contains("expired"), "error: {err}");
    }

    #[test]
    fn maybe_auto_rotate_rotates_below_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("work.token");
        let key = test_key();
        let cfg = AutoRotateConfig {
            threshold: 900,
            ttl: 3600,
        };
        let original = write_session_token(&path, &key, 30, None, Some(cfg)).unwrap();

        // Remaining lifetime (≈30s) is below the 900s threshold → rotate.
        assert!(maybe_auto_rotate(&path).unwrap(), "must rotate below threshold");
        let rotated = parse_token_file(&path).unwrap();
        assert_ne!(rotated.token_id, original.token_id, "rotation must mint a new id");
        assert_eq!(rotated.expires_at - rotated.created_at, 3600, "must adopt the policy ttl");
        assert!(
            rotated.auto_rotate.is_some(),
            "auto-rotate policy must survive rotation"
        );
        // The rotated token still unseals to the same master key.
        assert_eq!(read_session_token(&path).unwrap().as_ref(), key.as_ref());
    }

    #[test]
    fn maybe_auto_rotate_skips_above_threshold_and_without_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("work.token");
        let key = test_key();

        // No policy → untouched.
        write_session_token(&path, &key, 3600, None, None).unwrap();
        let before = parse_token_file(&path).unwrap();
        assert!(!maybe_auto_rotate(&path).unwrap());
        assert_eq!(parse_token_file(&path).unwrap().token_id, before.token_id);

        // Policy but remaining ≫ threshold → untouched.
        let cfg = AutoRotateConfig {
            threshold: 10,
            ttl: 3600,
        };
        write_session_token(&path, &key, 3600, None, Some(cfg)).unwrap();
        let before = parse_token_file(&path).unwrap();
        assert!(!maybe_auto_rotate(&path).unwrap());
        assert_eq!(parse_token_file(&path).unwrap().token_id, before.token_id);

        // Missing file → Ok(false), never an error.
        assert!(!maybe_auto_rotate(&dir.path().join("missing.token")).unwrap());
    }
}

