// SPDX-License-Identifier: Apache-2.0

//! TOTP 2FA for operator admin commands (design §3, P7).
//!
//! `admin-2fa init` generates a random secret (SDK CSPRNG) and prints an
//! `otpauth://` URI for the operator's authenticator app; admin commands
//! (`keys-backup`, `psp-configure`) then require `--totp <code>`,
//! verified RFC 6238-style against the stored secret with a ±1-step
//! window. The secret lives at `<root>/admin_2fa.secret` (0600).

use std::path::{Path, PathBuf};

use origin_crypto_sdk::drbg::otp::{format_code, totp, HashAlgorithm};

use crate::error::{Error, Result};

pub const TOTP_SECRET_BYTES: usize = 20;
pub const TOTP_STEP_SECS: u64 = 30;
pub const TOTP_DIGITS: u32 = 6;
/// Allowed clock drift, in steps (RFC 6238 ±1 window).
pub const TOTP_WINDOW_STEPS: i64 = 1;

pub fn secret_path(root: &Path) -> PathBuf {
    root.join("admin_2fa.secret")
}

/// Generate a fresh TOTP secret, persist it (0600), and return the
/// provisioning URI.
pub fn init(root: &Path) -> Result<String> {
    let mut secret = [0u8; TOTP_SECRET_BYTES];
    origin_crypto_sdk::fill_random(&mut secret).map_err(|e| Error::CryptoError {
        details: format!("generating 2FA secret: {e}"),
    })?;
    let hex_secret = hex::encode(secret);
    std::fs::write(secret_path(root), &hex_secret).map_err(|e| Error::IoError {
        details: format!("writing {}: {e}", secret_path(root).display()),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(secret_path(root), std::fs::Permissions::from_mode(0o600));
    }
    Ok(otpauth_uri(&secret))
}

/// Verify a 6-digit TOTP code against the stored secret (±1 step).
/// Returns an error when 2FA is not configured.
pub fn verify(root: &Path, code: &str) -> Result<bool> {
    let path = secret_path(root);
    if !path.exists() {
        return Err(Error::TwofaNotConfigured);
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| Error::IoError {
        details: format!("reading {}: {e}", path.display()),
    })?;
    let secret = hex::decode(raw.trim()).map_err(|e| Error::StoreCorrupted {
        details: format!("bad 2FA secret on disk: {e}"),
    })?;
    let now = chrono::Utc::now().timestamp();
    for offset in -TOTP_WINDOW_STEPS..=TOTP_WINDOW_STEPS {
        let ts = (now + offset * TOTP_STEP_SECS as i64).max(0) as u64;
        let expected = format_code(
            totp(
                &secret,
                ts,
                TOTP_STEP_SECS,
                TOTP_DIGITS,
                HashAlgorithm::Sha256,
            ),
            TOTP_DIGITS,
        );
        if expected == code {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `otpauth://totp/...` provisioning URI (RFC 4648 base32 secret).
pub fn otpauth_uri(secret: &[u8]) -> String {
    format!(
        "otpauth://totp/Origin-Payments:operator?secret={}&issuer=Origin-Payments&period={}&digits={}&algorithm=SHA256",
        base32(secret),
        TOTP_STEP_SECS,
        TOTP_DIGITS
    )
}

/// RFC 4648 base32 (no padding) — for authenticator-app provisioning only.
fn base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 0x1F) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_encoding_matches_rfc4648_vectors() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"hello"), "NBSWY3DP");
    }

    #[test]
    fn init_then_verify_current_code() {
        let dir = tempfile::tempdir().unwrap();
        let uri = init(dir.path()).unwrap();
        assert!(uri.starts_with("otpauth://totp/"), "{uri}");
        assert!(secret_path(dir.path()).exists());

        let raw = std::fs::read_to_string(secret_path(dir.path())).unwrap();
        let secret = hex::decode(raw.trim()).unwrap();
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let code = format_code(
            totp(
                &secret,
                now,
                TOTP_STEP_SECS,
                TOTP_DIGITS,
                HashAlgorithm::Sha256,
            ),
            TOTP_DIGITS,
        );
        assert!(verify(dir.path(), &code).unwrap());
        assert_eq!(verify(dir.path(), "000000").unwrap(), false);
    }

    #[test]
    fn verify_without_setup_is_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            verify(dir.path(), "123456").unwrap_err(),
            Error::TwofaNotConfigured
        ));
    }
}
