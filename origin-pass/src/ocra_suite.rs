// SPDX-License-Identifier: Apache-2.0

//! RFC 6287 §6 OCRASuite string parser.
//!
//! Grammar (RFC 6287 §6.1–6.3):
//!
//! ```text
//! OCRASuite   = <Algorithm> ":" <CryptoFunction> ":" <DataInput>
//! Algorithm   = "OCRA-1"
//! CryptoFunction = "HOTP-" <hash> "-" <digits>     // RFC §5.2
//! hash        = "SHA1" | "SHA256" | "SHA512"
//! digits      = "4"..="10"
//! DataInput   = [ "C" ] [ "Q" <format> <2DIGIT> ] [ "P" <hash> ] [ "S" <3DIGIT> ] [ "T" <num> <unit> ]
//! ```
//!
//! Components of DataInput are separated by `-` (RFC §6.3: "each input
//! that is used for the computation is represented by a single letter
//! (except Q), and they are separated by a hyphen"). The RFC examples
//! `C-QN08-PSHA1`, `QA10-T1M`, and `QH8-S512` show the P hash and T/S
//! sizes are glued to their letter with no separator.
//!
//! # Mapping onto the SDK
//!
//! `origin_crypto_sdk::ocra::ocra` takes explicit fields (counter,
//! challenge, password, session, timestamp) and always lays out
//! `M = C ‖ SHA1(Q) ‖ SHA1(P) ‖ S ‖ T`, substituting zero bytes for
//! absent fields. origin-pass therefore passes:
//!
//! - `counter`: the stored counter when the suite has `C`, else 0;
//! - `challenge`: the CLI challenge, encoded per format (QN → ASCII
//!   digits, QH → binary hex decode, QA → UTF-8 bytes, absent → empty);
//! - `password`: the `--pin` value when the suite has `P<hash>` (the SDK
//!   currently hashes the P slot with SHA-1 regardless of the suite's
//!   declared hash — suites with `P-SHA256` / `P-SHA512` are rejected at
//!   `add` time rather than silently computing a non-conformant code);
//! - `session`: always empty (no CLI surface);
//! - `timestamp`: `now / step_secs` when the suite has `T<num><unit>`
//!   (the T value is expressed in time-steps, RFC §6.3), else None.

use origin_crypto_sdk::drbg::otp::HashAlgorithm;

/// Challenge format qualifier (RFC §6.3 table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    /// No challenge in the suite (data input has no Q component).
    None,
    /// QN — numeric challenge, `len` decimal digits.
    Numeric,
    /// QH — hexadecimal challenge, `len` hex characters.
    Hex,
    /// QA — alphanumeric challenge, `len` alphanumeric characters.
    Alphanumeric,
}

/// Parsed challenge spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcraChallenge {
    pub kind: ChallengeKind,
    /// Exact character length for QN/QH/QA (0 when kind is None).
    pub len: usize,
}

/// A parsed `OCRA-1:<crypto>:<data>` suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcraSuite {
    pub algo: HashAlgorithm,
    pub digits: u32,
    /// Suite uses the counter (C component). The counter auto-increments
    /// and persists per use, like HOTP.
    pub has_counter: bool,
    pub challenge: OcraChallenge,
    /// Suite uses a PIN/password (P<hash>). Only `Some(Sha1)` is
    /// supported end-to-end (see module docs).
    pub pin_algo: Option<HashAlgorithm>,
    /// Suite uses session data (S<nnn>). Parsed for validation only —
    /// the CLI has no session input, so such suites are rejected at add.
    pub session_len: Option<usize>,
    /// Suite uses a timestamp (T<num><unit>); value is the time-step
    /// size in seconds.
    pub timestamp_step_secs: Option<u64>,
}

/// Parse a full OCRASuite string per RFC 6287 §6.
pub fn parse_suite(suite: &str) -> Result<OcraSuite, String> {
    let parts: Vec<&str> = suite.split(':').collect();
    if parts.len() != 3 {
        return Err(format!(
            "malformed OCRA suite `{suite}`: expected `OCRA-1:<CryptoFunction>:<DataInput>` (got {} colon-separated parts)",
            parts.len()
        ));
    }
    if parts[0] != "OCRA-1" {
        return Err(format!(
            "unsupported OCRA algorithm `{}` (only OCRA-1 is defined by RFC 6287)",
            parts[0]
        ));
    }
    let (algo, digits) = parse_crypto_function(parts[1])?;
    let data = parse_data_input(parts[2])?;

    Ok(OcraSuite {
        algo,
        digits,
        has_counter: data.0,
        challenge: data.1,
        pin_algo: data.2,
        session_len: data.3,
        timestamp_step_secs: data.4,
    })
}

/// `HOTP-<hash>-<digits>` (RFC §5.2). Digits 4..=10; `t=0` (full HMAC,
/// no truncation) is defined by the RFC but not supported by the SDK, so
/// it is rejected here.
fn parse_crypto_function(crypto: &str) -> Result<(HashAlgorithm, u32), String> {
    let rest = crypto
        .strip_prefix("HOTP-")
        .ok_or_else(|| format!("unsupported crypto function `{crypto}`: only HOTP-<hash>-<digits> is defined by RFC 6287"))?;
    let (hash, digits_str) = rest.rsplit_once('-').ok_or_else(|| {
        format!("malformed crypto function `{crypto}`: expected HOTP-<hash>-<digits>")
    })?;
    let algo = match hash {
        "SHA1" => HashAlgorithm::Sha1,
        "SHA256" => HashAlgorithm::Sha256,
        "SHA512" => HashAlgorithm::Sha512,
        other => {
            return Err(format!(
                "unsupported hash function `{other}` (must be SHA1, SHA256, or SHA512)"
            ))
        }
    };
    let digits: u32 = digits_str
        .parse()
        .map_err(|_| format!("crypto function digits `{digits_str}` is not an integer"))?;
    if !(4..=10).contains(&digits) {
        return Err(format!(
            "crypto function digits `{digits_str}` out of range 4..=10"
        ));
    }
    Ok((algo, digits))
}

type DataInput = (
    bool,                  // has_counter
    OcraChallenge,         // challenge
    Option<HashAlgorithm>, // pin_algo
    Option<usize>,         // session_len
    Option<u64>,           // timestamp_step_secs
);

/// `[C] [Q<fmt><len>] [P<hash>] [S<len>] [T<num><unit>]`, hyphen-separated.
fn parse_data_input(data: &str) -> Result<DataInput, String> {
    let mut has_counter = false;
    let mut challenge = OcraChallenge {
        kind: ChallengeKind::None,
        len: 0,
    };
    let mut pin_algo = None;
    let mut session_len = None;
    let mut timestamp_step = None;

    if data.is_empty() {
        return Err("empty DataInput (suite must have at least one component)".to_string());
    }

    for comp in data.split('-') {
        if comp.is_empty() {
            return Err(format!(
                "empty DataInput component in `{data}` (double hyphen?)"
            ));
        }
        match comp.as_bytes()[0] {
            b'C' if comp.len() == 1 => {
                if has_counter {
                    return Err(format!("duplicate counter component in `{data}`"));
                }
                has_counter = true;
            }
            b'Q' => {
                if challenge.kind != ChallengeKind::None {
                    return Err(format!("duplicate challenge component in `{data}`"));
                }
                challenge = parse_challenge(comp)?;
            }
            b'P' => {
                if pin_algo.is_some() {
                    return Err(format!("duplicate PIN component in `{data}`"));
                }
                pin_algo = Some(parse_pin_hash(comp)?);
            }
            b'S' => {
                if session_len.is_some() {
                    return Err(format!("duplicate session component in `{data}`"));
                }
                session_len = Some(parse_session_len(comp)?);
            }
            b'T' => {
                if timestamp_step.is_some() {
                    return Err(format!("duplicate timestamp component in `{data}`"));
                }
                timestamp_step = Some(parse_timestamp_step(comp)?);
            }
            other => {
                return Err(format!(
                    "unknown DataInput component `{comp}` (component must start with C, Q, P, S, or T; got byte 0x{other:02x})"
                ))
            }
        }
    }

    Ok((
        has_counter,
        challenge,
        pin_algo,
        session_len,
        timestamp_step,
    ))
}

/// `Q<F><len>` where F ∈ {A, N, H} and len is a value 04..=64 (RFC §6.3
/// table 2). The ABNF says `<2*DIGIT>` but the RFC's own §6.4 examples
/// use both `QN08` and `QH8` — so 1 or 2 digits are accepted (3+ are
/// rejected as clearly non-conformant).
fn parse_challenge(comp: &str) -> Result<OcraChallenge, String> {
    let kind = match comp.as_bytes().get(1) {
        Some(b'A') => ChallengeKind::Alphanumeric,
        Some(b'N') => ChallengeKind::Numeric,
        Some(b'H') => ChallengeKind::Hex,
        other => {
            return Err(format!(
                "malformed challenge `{comp}`: expected Q<A|N|H><len> (got {:?})",
                other.map(|b| *b as char)
            ))
        }
    };
    let len_str = &comp[2..];
    if len_str.is_empty() || len_str.len() > 2 {
        return Err(format!(
            "malformed challenge `{comp}`: length must be 1 or 2 digits (e.g. QN08, QH8)"
        ));
    }
    let len: usize = len_str
        .parse()
        .map_err(|_| format!("challenge `{comp}` length `{len_str}` is not an integer"))?;
    if !(4..=64).contains(&len) {
        return Err(format!(
            "challenge `{comp}` length {len} out of range 04..=64 (RFC §6.3)"
        ));
    }
    Ok(OcraChallenge { kind, len })
}

/// `P<hash>` (RFC §6.3: "the input for P is further qualified by the
/// hash function used"; the RFC examples glue it as `PSHA1`).
fn parse_pin_hash(comp: &str) -> Result<HashAlgorithm, String> {
    match &comp[1..] {
        "SHA1" => Ok(HashAlgorithm::Sha1),
        "SHA256" => Ok(HashAlgorithm::Sha256),
        "SHA512" => Ok(HashAlgorithm::Sha512),
        other => Err(format!(
            "malformed PIN component `{comp}`: expected P<SHA1|SHA256|SHA512> (got `{other}`)"
        )),
    }
}

/// `S<nnn>` with nnn ∈ {064, 128, 256, 512} (RFC §6.3). The length is a
/// three-digit value — `S64` is malformed, only `S064` is valid.
fn parse_session_len(comp: &str) -> Result<usize, String> {
    if comp.len() != 4 {
        return Err(format!(
            "malformed session component `{comp}`: expected S<064|128|256|512> (3-digit length)"
        ));
    }
    let n: usize = comp[1..].parse().map_err(|_| {
        format!("malformed session component `{comp}`: expected S<064|128|256|512>")
    })?;
    match n {
        64 | 128 | 256 | 512 => Ok(n),
        other => Err(format!(
            "session length {other} not one of 064/128/256/512 (RFC §6.3)"
        )),
    }
}

/// `T<num><unit>` where unit ∈ {S, M, H} — the time-step size (RFC §6.3
/// table 3). Returns the step size in seconds. The step value is bounded
/// per the RFC table: `[1-59]S`, `[1-59]M`, `[0-48]H`.
fn parse_timestamp_step(comp: &str) -> Result<u64, String> {
    let bytes = comp.as_bytes();
    let last = *bytes
        .last()
        .ok_or_else(|| format!("malformed timestamp component `{comp}`"))?;
    let (num_str, mult, max) = match last {
        b'S' => (&comp[1..comp.len() - 1], 1u64, 59u64),
        b'M' => (&comp[1..comp.len() - 1], 60u64, 59u64),
        b'H' => (&comp[1..comp.len() - 1], 3600u64, 48u64),
        _ => {
            return Err(format!(
            "malformed timestamp component `{comp}`: expected T<num><S|M|H> (e.g. T1M, T20S, T24H)"
        ))
        }
    };
    if num_str.is_empty() || !num_str.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "malformed timestamp component `{comp}`: step `{num_str}` is not an integer"
        ));
    }
    let num: u64 = num_str
        .parse()
        .map_err(|_| format!("timestamp component `{comp}` step `{num_str}` is not an integer"))?;
    if num == 0 || num > max {
        return Err(format!(
            "timestamp component `{comp}` step {num} out of range (1..={max} for {})",
            match last {
                b'S' => "seconds",
                b'M' => "minutes",
                _ => "hours",
            }
        ));
    }
    Ok(num * mult)
}

/// Validate a CLI challenge string against the suite's challenge spec.
/// `challenge` is `None` when the user supplied no `--challenge`.
///
/// RFC §6.3 table 2 header is "Up to Length (xx)" — the challenge may
/// be **any length from 1 to the suite's max**, not exactly the max
/// (a QN08 suite accepts a 4-digit question; the verifier computes over
/// the exact challenge bytes it sent). Only the character set and the
/// upper bound are enforced.
pub fn validate_challenge(suite: &OcraSuite, challenge: Option<&str>) -> Result<(), String> {
    match suite.challenge.kind {
        ChallengeKind::None => {
            if challenge.is_some() {
                return Err(format!(
                    "suite `{}` has no challenge component — omit --challenge",
                    suite_display(suite)
                ));
            }
            Ok(())
        }
        kind => {
            let ch = challenge.ok_or_else(|| {
                format!(
                    "suite `{}` requires --challenge <{}> (up to {} chars)",
                    suite_display(suite),
                    kind_name(kind),
                    suite.challenge.len
                )
            })?;
            if ch.is_empty() || ch.len() > suite.challenge.len {
                return Err(format!(
                    "challenge `{ch}` is {} chars; suite accepts 1..={} ({})",
                    ch.len(),
                    suite.challenge.len,
                    kind_name(kind)
                ));
            }
            let valid = match kind {
                ChallengeKind::Numeric => ch.chars().all(|c| c.is_ascii_digit()),
                ChallengeKind::Hex => ch.chars().all(|c| c.is_ascii_hexdigit()),
                ChallengeKind::Alphanumeric => ch.chars().all(|c| c.is_ascii_alphanumeric()),
                ChallengeKind::None => unreachable!(),
            };
            if !valid {
                return Err(format!(
                    "challenge `{ch}` is not a valid {} challenge (must contain only {})",
                    kind_name(kind),
                    match kind {
                        ChallengeKind::Numeric => "digits 0-9",
                        ChallengeKind::Hex => "hex characters 0-9 a-f A-F",
                        ChallengeKind::Alphanumeric => "alphanumeric characters A-Z a-z 0-9",
                        ChallengeKind::None => unreachable!(),
                    }
                ));
            }
            Ok(())
        }
    }
}

/// Encode a validated challenge into the byte form fed to the SDK's
/// `challenge` field:
/// - QN → the ASCII digits themselves;
/// - QA → the UTF-8 bytes;
/// - QH → the binary decode of the hex string (RFC §6.3: hex input is
///   converted to its binary representation);
/// - None → empty.
pub fn encode_challenge(suite: &OcraSuite, challenge: Option<&str>) -> Result<Vec<u8>, String> {
    match suite.challenge.kind {
        ChallengeKind::None => Ok(Vec::new()),
        ChallengeKind::Numeric | ChallengeKind::Alphanumeric => {
            Ok(challenge.unwrap_or_default().as_bytes().to_vec())
        }
        ChallengeKind::Hex => {
            let ch = challenge.unwrap_or_default();
            hex::decode(ch).map_err(|e| format!("challenge `{ch}` is not valid hex: {e}"))
        }
    }
}

/// Human-readable suite for error messages (re-derives the input).
fn suite_display(suite: &OcraSuite) -> String {
    format!("{:?}:{:?}", suite.algo, suite.challenge)
}

fn kind_name(kind: ChallengeKind) -> &'static str {
    match kind {
        ChallengeKind::None => "none",
        ChallengeKind::Numeric => "numeric",
        ChallengeKind::Hex => "hex",
        ChallengeKind::Alphanumeric => "alphanumeric",
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn algo(h: HashAlgorithm) -> String {
        match h {
            HashAlgorithm::Sha1 => "SHA1",
            HashAlgorithm::Sha256 => "SHA256",
            HashAlgorithm::Sha512 => "SHA512",
        }
        .to_string()
    }

    #[test]
    fn rfc_example_qn08() {
        // RFC §6.4 / §A.1 — the canonical suite.
        let s = parse_suite("OCRA-1:HOTP-SHA1-6:QN08").unwrap();
        assert_eq!(s.algo, HashAlgorithm::Sha1);
        assert_eq!(s.digits, 6);
        assert!(!s.has_counter);
        assert_eq!(s.challenge.kind, ChallengeKind::Numeric);
        assert_eq!(s.challenge.len, 8);
        assert_eq!(s.pin_algo, None);
        assert_eq!(s.session_len, None);
        assert_eq!(s.timestamp_step_secs, None);
    }

    #[test]
    fn rfc_example_counter_pin() {
        // RFC §6.4: "OCRA-1:HOTP-SHA512-8:C-QN08-PSHA1"
        let s = parse_suite("OCRA-1:HOTP-SHA512-8:C-QN08-PSHA1").unwrap();
        assert_eq!(s.algo, HashAlgorithm::Sha512);
        assert_eq!(s.digits, 8);
        assert!(s.has_counter);
        assert_eq!(s.challenge.kind, ChallengeKind::Numeric);
        assert_eq!(s.challenge.len, 8);
        assert_eq!(s.pin_algo, Some(HashAlgorithm::Sha1));
    }

    #[test]
    fn rfc_example_timestamp_session() {
        // RFC §6.4: "OCRA-1:HOTP-SHA256-6:QA10-T1M"
        let s = parse_suite("OCRA-1:HOTP-SHA256-6:QA10-T1M").unwrap();
        assert_eq!(s.algo, HashAlgorithm::Sha256);
        assert_eq!(s.challenge.kind, ChallengeKind::Alphanumeric);
        assert_eq!(s.challenge.len, 10);
        assert_eq!(s.timestamp_step_secs, Some(60));

        // RFC §6.4: "OCRA-1:HOTP-SHA1-4:QH8-S512"
        let s = parse_suite("OCRA-1:HOTP-SHA1-4:QH8-S512").unwrap();
        assert_eq!(s.digits, 4);
        assert_eq!(s.challenge.kind, ChallengeKind::Hex);
        assert_eq!(s.challenge.len, 8);
        assert_eq!(s.session_len, Some(512));
    }

    #[test]
    fn timestamp_step_units() {
        assert_eq!(
            parse_suite("OCRA-1:HOTP-SHA1-6:QN08-T20S")
                .unwrap()
                .timestamp_step_secs,
            Some(20)
        );
        assert_eq!(
            parse_suite("OCRA-1:HOTP-SHA1-6:QN08-T5M")
                .unwrap()
                .timestamp_step_secs,
            Some(300)
        );
        assert_eq!(
            parse_suite("OCRA-1:HOTP-SHA1-6:QN08-T24H")
                .unwrap()
                .timestamp_step_secs,
            Some(86_400)
        );
    }

    #[test]
    fn counter_and_timestamp_may_coexist() {
        // RFC's reference implementation handles C and T together
        // ("C-QN08-T1M"); we allow it too.
        let s = parse_suite("OCRA-1:HOTP-SHA1-6:C-QN08-T1M").unwrap();
        assert!(s.has_counter);
        assert_eq!(s.timestamp_step_secs, Some(60));
    }

    #[test]
    fn rejects_bad_suites() {
        for bad in [
            "OCRA-2:HOTP-SHA1-6:QN08",      // wrong algorithm version
            "HOTP-SHA1-6:QN08",             // missing algorithm
            "OCRA-1:HOTP-SHA1-6",           // missing data input
            "OCRA-1:TOTP-SHA1-6:QN08",      // TOTP crypto function not defined by RFC 6287
            "OCRA-1:HOTP-MD5-6:QN08",       // bad hash
            "OCRA-1:HOTP-SHA1-3:QN08",      // digits out of range
            "OCRA-1:HOTP-SHA1-6:QN03",      // challenge length too small
            "OCRA-1:HOTP-SHA1-6:QN65",      // challenge length too big
            "OCRA-1:HOTP-SHA1-6:QN008", // length must be 1 or 2 digits (QN08 / QH8 per RFC §6.4)
            "OCRA-1:HOTP-SHA1-6:S64",   // session length must be 3 digits (S064, not S64)
            "OCRA-1:HOTP-SHA1-6:QN08-P", // pin without hash
            "OCRA-1:HOTP-SHA1-6:S999",  // bad session length
            "OCRA-1:HOTP-SHA1-6:T0M",   // zero time step
            "OCRA-1:HOTP-SHA1-6:T60S",  // time step out of range (1..=59 seconds)
            "OCRA-1:HOTP-SHA1-6:T60M",  // time step out of range (1..=59 minutes)
            "OCRA-1:HOTP-SHA1-6:T49H",  // time step out of range (0..=48 hours)
            "OCRA-1:HOTP-SHA1-6:QN08-X", // unknown component
            "OCRA-1:HOTP-SHA1-6:QN08-QN08", // duplicate challenge
            "OCRA-1:HOTP-SHA1-6:",      // empty data input
        ] {
            assert!(parse_suite(bad).is_err(), "suite `{bad}` must be rejected");
        }
    }

    #[test]
    fn challenge_validation_per_format() {
        // "Up to Length (xx)" (RFC §6.3): any length 1..=max is valid.
        let qn = parse_suite("OCRA-1:HOTP-SHA1-6:QN08").unwrap();
        assert!(validate_challenge(&qn, Some("12345678")).is_ok());
        assert!(validate_challenge(&qn, Some("1234567")).is_ok()); // shorter than max is fine
        assert!(validate_challenge(&qn, Some("123456789")).is_err()); // over max
        assert!(validate_challenge(&qn, Some("")).is_err()); // empty
        assert!(validate_challenge(&qn, Some("1234567a")).is_err()); // non-digit
        assert!(validate_challenge(&qn, None).is_err()); // required

        let qh = parse_suite("OCRA-1:HOTP-SHA1-6:QH08").unwrap();
        assert!(validate_challenge(&qh, Some("a1b2c3d4")).is_ok());
        assert!(validate_challenge(&qh, Some("a1b2")).is_ok());
        assert!(validate_challenge(&qh, Some("a1b2c3d!")).is_err());

        let qa = parse_suite("OCRA-1:HOTP-SHA1-6:QA04").unwrap();
        assert!(validate_challenge(&qa, Some("Ab12")).is_ok());
        assert!(validate_challenge(&qa, Some("Ab")).is_ok());
        assert!(validate_challenge(&qa, Some("Ab-1")).is_err());

        let no_ch = parse_suite("OCRA-1:HOTP-SHA1-6:C").unwrap();
        assert!(validate_challenge(&no_ch, None).is_ok());
        assert!(validate_challenge(&no_ch, Some("1234")).is_err());
    }

    #[test]
    fn challenge_encoding_per_format() {
        let qn = parse_suite("OCRA-1:HOTP-SHA1-6:QN08").unwrap();
        assert_eq!(
            encode_challenge(&qn, Some("12345678")).unwrap(),
            b"12345678"
        );

        let qh = parse_suite("OCRA-1:HOTP-SHA1-6:QH08").unwrap();
        // Hex decodes to binary: "a1b2c3d4" → 4 bytes.
        assert_eq!(
            encode_challenge(&qh, Some("a1b2c3d4")).unwrap(),
            vec![0xa1, 0xb2, 0xc3, 0xd4]
        );

        let qa = parse_suite("OCRA-1:HOTP-SHA1-6:QA04").unwrap();
        assert_eq!(encode_challenge(&qa, Some("Ab12")).unwrap(), b"Ab12");

        let none = parse_suite("OCRA-1:HOTP-SHA1-6:C").unwrap();
        assert_eq!(encode_challenge(&none, None).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn pin_sha256_suite_parses_but_is_marked_for_rejection_at_add() {
        // Parser accepts it; `cmd_add` refuses P-SHA256/512 because the
        // SDK hashes the P slot with SHA-1 only.
        let s = parse_suite("OCRA-1:HOTP-SHA1-6:QN08-PSHA256").unwrap();
        assert_eq!(s.pin_algo, Some(HashAlgorithm::Sha256));
        let s = parse_suite("OCRA-1:HOTP-SHA1-6:QN08-PSHA512").unwrap();
        assert_eq!(s.pin_algo, Some(HashAlgorithm::Sha512));
    }

    #[test]
    fn suite_without_algorithm_keeps_sha1_defaults() {
        // Regression: the old compute path defaulted to SHA1/6 for
        // `code --ocra`; a bare counter suite parses with the same.
        let s = parse_suite("OCRA-1:HOTP-SHA1-6:C").unwrap();
        assert_eq!(algo(s.algo), "SHA1");
        assert_eq!(s.digits, 6);
    }
}
