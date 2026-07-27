// SPDX-License-Identifier: Apache-2.0

//! Command implementations for `origin-pass`.
//!
//! Each `cmd_*` function returns `Result<(), String>`. v0.1.0 ships only
//! the OCRA branch of `cmd_code` — every other command is a `todo!()`
//! stub awaiting the v0.2.x implementation sequence in
//! `origin-tools/DESIGN.md` §6.

use crate::cli::{
    AddArgs, ChangePassphraseArgs, CodeArgs, ExportQrArgs, GetArgs, ImportQrArgs,
    InitArgs, ListArgs, LockArgs, RmArgs, UnlockArgs,
};

// ---------------------------------------------------------------------------
// OCRA (RFC 6287) helpers — used by `cmd_code` and exposed to the
// `tests` module below for RFC-vector verification.
// ---------------------------------------------------------------------------

/// Result of an OCRA computation — the formatted code + algorithm metadata
/// so callers (cmd_code, future vault-backed paths, and integration tests)
/// can render or compare without re-deriving inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcraCode {
    /// RFC 4226 §5.3 dynamic-truncated value, rendered with `digits`
    /// leading zeros.
    pub value: String,
    /// Numeric value (unguarded for downstream /QA tooling; do NOT log).
    pub numeric: u64,
    /// Digit width (4..=10).
    pub digits: u32,
}

/// Conversion from the CLI-facing enum (a `clap::ValueEnum` so clap can
/// accept `--algo sha256` etc) to the SDK's enum. Both share the same
/// variants but are distinct Rust types; without this conversion,
/// `compute_ocra_code` would need to import `origin_crypto_sdk` directly,
/// which leaks an internal type into `cmd_code`'s surface.
impl From<crate::cli::HashAlgorithm> for origin_crypto_sdk::drbg::otp::HashAlgorithm {
    fn from(v: crate::cli::HashAlgorithm) -> Self {
        match v {
            crate::cli::HashAlgorithm::Sha1 => origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha1,
            crate::cli::HashAlgorithm::Sha256 => origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha256,
            crate::cli::HashAlgorithm::Sha512 => origin_crypto_sdk::drbg::otp::HashAlgorithm::Sha512,
        }
    }
}

/// Compute an OCRA response per RFC 6287 §7.1.
///
/// Reads the secret from `key_path` (raw bytes — testing escape hatch
/// until vault unlock lands). `challenge.as_bytes()` is fed into the Q
/// slot. `counter` and `timestamp` default to 0 and None respectively;
/// `digits` defaults to 6; `algo` defaults to SHA-1 per the RFC 6287
/// canonical Suite.
pub fn compute_ocra_code(
    key_path: &std::path::Path,
    challenge: &str,
    counter: u64,
    digits: u32,
    algo: crate::cli::HashAlgorithm,
) -> Result<OcraCode, String> {
    use origin_crypto_sdk::ocra::{ocra, OcraRequest};

    let key = std::fs::read(key_path).map_err(|e| {
        format!(
            "failed to read OCRA key file {}: {e}",
            key_path.display()
        )
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

// ---------------------------------------------------------------------------
// Public command entry points
// ---------------------------------------------------------------------------

pub fn cmd_init(_args: InitArgs) -> Result<(), String> {
    todo!("origin-pass init — see DESIGN.md §6 step 2")
}

pub fn cmd_unlock(_args: UnlockArgs) -> Result<(), String> {
    todo!("origin-pass unlock — see DESIGN.md §6 step 3")
}

pub fn cmd_lock(_args: LockArgs) -> Result<(), String> {
    todo!("origin-pass lock — see DESIGN.md §6 step 3")
}

pub fn cmd_add(_args: AddArgs) -> Result<(), String> {
    todo!("origin-pass add — see DESIGN.md §6 step 3")
}

pub fn cmd_get(_args: GetArgs) -> Result<(), String> {
    todo!("origin-pass get — see DESIGN.md §6 step 3")
}

pub fn cmd_list(_args: ListArgs) -> Result<(), String> {
    todo!("origin-pass list — see DESIGN.md §6 step 3")
}

pub fn cmd_rm(_args: RmArgs) -> Result<(), String> {
    todo!("origin-pass rm — see DESIGN.md §6 step 3")
}

/// Compute and display an OTP code (TOTP/HOTP) or OCRA response.
///
/// OCRA branch is the only one implemented in v0.1.0; it is triggered
/// by `--ocra` on the CLI. TOTP/HOTP branches fall through to a
/// `todo!()` until the vault lookup path lands.
pub fn cmd_code(args: CodeArgs) -> Result<(), String> {
    if !args.ocra {
        let msg = "TOTP/HOTP code path not yet implemented; pass --ocra for OCRA mode \
             (see DESIGN.md §6 step 4)";
        return Err(msg.to_string());
    }

    // --ocra is set; --challenge is also required (enforced by clap
    // `requires = "ocra"` on the field; the reverse — --ocra requiring
    // --challenge — is checked here for ergonomics).
    let challenge = args
        .challenge
        .as_deref()
        .ok_or_else(|| "--ocra requires --challenge <STRING>".to_string())?;

    let key_path = args
        .key_file
        .as_ref()
        .ok_or_else(|| {
            "--ocra currently requires --key-file <PATH> (vault unlock not yet wired; \
             see DESIGN.md §6 step 4)"
                .to_string()
        })?
        .clone();

    let algo = args.algo.unwrap_or(crate::cli::HashAlgorithm::Sha1);
    let digits = args.digits.unwrap_or(6);
    let counter = args.counter.unwrap_or(0);

    let code = compute_ocra_code(&key_path, challenge, counter, digits, algo)?;

    if args.quiet {
        // Suppress echo — emit to stderr only.
        eprintln!("{}", code.value);
    } else {
        println!("{}", code.value);
    }
    Ok(())
}

pub fn cmd_export_qr(_args: ExportQrArgs) -> Result<(), String> {
    todo!("origin-pass export-qr — see DESIGN.md §6 step 4 (OTP)")
}

pub fn cmd_import_qr(_args: ImportQrArgs) -> Result<(), String> {
    todo!("origin-pass import-qr — see DESIGN.md §6 step 4 (OTP)")
}

pub fn cmd_change_passphrase(_args: ChangePassphraseArgs) -> Result<(), String> {
    todo!("origin-pass change-passphrase — see DESIGN.md §6 step 3")
}

// ---------------------------------------------------------------------------
// Tests — RFC 6287 §A.1 + edge cases
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::HashAlgorithm;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Write `bytes` to a temp file and return the path. Used to back
    /// `--key-file` in tests with raw OCRA keys.
    fn write_key(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("temp file");
        f.write_all(bytes).expect("write key");
        f.flush().expect("flush");
        f
    }

    // RFC 6287 Appendix A, Table 1, Test #1
    // Suite: OCRA-1:HOTP-SHA1-6:QN08
    // Key (ASCII): "12345678901234567890"
    // Q (ASCII): "00000000"
    // Expected: 196958
    #[test]
    fn rfc6287_a1_qn08_sha1_canonical_196958() {
        let key = write_key(b"12345678901234567890");
        let code = compute_ocra_code(
            key.path(),
            "00000000",
            0,
            6,
            HashAlgorithm::Sha1,
        )
        .expect("ocra should succeed");
        assert_eq!(code.value, "196958");
        assert_eq!(code.numeric, 196_958);
        assert_eq!(code.digits, 6);
    }

    // Two invocations with identical inputs must yield identical codes
    // (determinism is the foundational property of RFC 6287).
    #[test]
    fn deterministic_same_input_same_output_sha256() {
        let key = write_key(b"a-key-with-32-bytes-for-sha256!!!!"); // 32 bytes
        let c1 = compute_ocra_code(key.path(), "12345678", 0, 8, HashAlgorithm::Sha256)
            .expect("first ocra");
        let c2 = compute_ocra_code(key.path(), "12345678", 0, 8, HashAlgorithm::Sha256)
            .expect("second ocra");
        assert_eq!(c1, c2);
    }

    // 10-digit SHA-512 response exercises the u64 code path; value must
    // fit in 10 digits (i.e. ≤ 9_999_999_999). This guards against the
    // historic u32 overflow that the SDK OCRA module once had.
    #[test]
    fn sha512_ten_digit_fits_in_u64() {
        let key = write_key(b"a-64-byte-key-for-sha512-pad-pad-pad-pad-pad-pad-pad0"); // 64 B
        let code = compute_ocra_code(key.path(), "12345678", 0, 10, HashAlgorithm::Sha512)
            .expect("sha512 ocra");
        assert!(code.numeric <= 9_999_999_999);
        assert_eq!(code.value.len(), 10);
    }

    // Bumping the C counter must produce a different response — guards
    // the counter wiring into the OCRA M layout.
    #[test]
    fn counter_change_changes_response_sha1() {
        let key = write_key(b"12345678901234567890");
        let c0 = compute_ocra_code(key.path(), "12345678", 0, 6, HashAlgorithm::Sha1)
            .expect("c0");
        let c1 = compute_ocra_code(key.path(), "12345678", 1, 6, HashAlgorithm::Sha1)
            .expect("c1");
        assert_ne!(c0.numeric, c1.numeric);
    }

    // Different challenges must produce different responses — guards
    // the Q wiring through SHA-1 hashing.
    #[test]
    fn challenge_change_changes_response_sha1() {
        let key = write_key(b"12345678901234567890");
        let c0 = compute_ocra_code(key.path(), "00000000", 0, 6, HashAlgorithm::Sha1)
            .expect("c0");
        let c1 = compute_ocra_code(key.path(), "12345678", 0, 6, HashAlgorithm::Sha1)
            .expect("c1");
        assert_ne!(c0.numeric, c1.numeric);
    }

    // OCRA_MIN_KEY_LEN = 16. A 15-byte key must be rejected with
    // InvalidKeyLength, surfacing as a String error (not a panic).
    // The fixture is a 15-element `[u8; 15]` array built at runtime so
    // the length is unambiguous — prior attempts using a string literal
    // (`b"fifteen_bytes_xx"`, `b"too-short-key-15"`) were miscounted
    // and silently produced 16-byte fixtures that the SDK accepted.
    #[test]
    fn short_key_rejected() {
        let short_key: [u8; 15] = [1u8; 15];
        assert_eq!(
            short_key.len(),
            15,
            "short-key fixture must be exactly 15 bytes; got {}",
            short_key.len()
        );
        let key = write_key(&short_key);
        let err = compute_ocra_code(key.path(), "00000000", 0, 6, HashAlgorithm::Sha1)
            .expect_err("15-byte key should be rejected");
        assert!(
            err.contains("InvalidKeyLength") || err.contains("key"),
            "unexpected error message: {err}"
        );
    }

    // OCRA_MIN_DIGITS = 4, OCRA_MAX_DIGITS = 10. We forward digits
    // directly to the SDK; an out-of-range value surfaces as an
    // InvalidParameter error.
    #[test]
    fn digits_out_of_range_rejected() {
        let key = write_key(b"12345678901234567890");
        let err3 = compute_ocra_code(key.path(), "00000000", 0, 3, HashAlgorithm::Sha1)
            .expect_err("3 digits should be rejected");
        let err11 = compute_ocra_code(key.path(), "00000000", 0, 11, HashAlgorithm::Sha1)
            .expect_err("11 digits should be rejected");
        assert!(err3.contains("digits") || err3.contains("parameter"));
        assert!(err11.contains("digits") || err11.contains("parameter"));
    }

    // cmd_code without --ocra must return an Err (not panic) so the
    // shell wrapper exits 1 with a useful message.
    #[test]
    fn cmd_code_without_ocra_flag_returns_err() {
        // Construct an *empty* CodeArgs — derive(Default) isn't available,
        // so we rely on the default() chain via Option::default / String
        // defaults. Name is irrelevant since the early return fires
        // before any lookup.
        let args = CodeArgs {
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
        };
        let err = cmd_code(args).expect_err("--ocra absent must error");
        assert!(err.contains("OCRA") || err.contains("TOTP"));
    }

    // cmd_code with --ocra but missing --key-file must return an Err
    // (not panic) explaining the testing escape hatch.
    #[test]
    fn cmd_code_ocra_without_key_file_returns_err() {
        let args = CodeArgs {
            vault: String::new(),
            name: String::new(),
            passphrase_file: None,
            algo: None,
            digits: None,
            auto_clear: None,
            quiet: false,
            ocra: true,
            challenge: Some("00000000".to_string()),
            counter: None,
            key_file: None,
        };
        let err = cmd_code(args).expect_err("--ocra without --key-file must error");
        assert!(err.contains("key-file") || err.contains("vault"));
    }
}
