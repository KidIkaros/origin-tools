// SPDX-License-Identifier: Apache-2.0

//! License tokens (ticket T-G5 pre-build): signed, offline-verifiable
//! entitlements for the product shell.
//!
//! Design posture (matches the product's rules of the road):
//! - **Offline by construction.** A license is a file the user owns.
//!   Verification reads local bytes and crypto — no activation server, no
//!   network, no telemetry. A future purchase webhook's only job is to run
//!   `issue` and deliver the file; the server never participates in
//!   verification.
//! - **Same crypto family as manifests, different domain.** Signatures are
//!   the engine's hybrid Ed25519+Falcon over `TAG_LICENSE` — a distinct
//!   domain from manifest checkpoints and head anchors, so a signature over
//!   one structure can never be replayed as a signature over another
//!   (same discipline as `TAG_ANCHOR`).
//! - **Feature flag = compile-time issuer pin.** [`issuer_fingerprint`]
//!   returns the fingerprint baked in at build time via `ORIGIN_ISSUER_FP`
//!   (hex, 64 chars). Builds without it are inert: `issue`/`show` report
//!   "licensing is not active" rather than pretending to work. The billing
//!   milestone's activation is then a CI secret plus a rebuild — no code
//!   change, no redesign.
//!
//! The engine stays product-agnostic: `tier` is an opaque `u8` code (0 is
//! reserved as "unpaid" and never issued) and `subject` is an opaque
//! string; tier names and entitlement semantics live in the product shell.

use crate::encoding::license_payload_input;
use crate::error::{ProvenanceError, Result};
use crate::identity::SignerKeys;

/// Current license token format version.
pub const LICENSE_VERSION: u8 = 1;

/// Opaque tier codes: 0 is reserved as "unpaid" (never issued) and is
/// rejected by [`License::verify`]; 1..=16 are product-defined. The engine
/// does not name tiers — entitlement semantics live in the product shell.
pub const MAX_TIER: u8 = 16;

/// Maximum canonical-JSON size accepted on parse (sanity bound, mirroring
/// the engine's parse-bounds discipline elsewhere).
pub const MAX_LICENSE_BYTES: usize = 16 * 1024;

/// A signed, offline-verifiable license token.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct License {
    /// Format version (must equal [`LICENSE_VERSION`]).
    pub v: u8,
    /// Stable license identifier (e.g. a UUID from the purchase flow).
    pub id: String,
    /// Opaque tier code (product-defined; 0 reserved as "unpaid").
    pub tier: u8,
    /// Opaque subject string (email or account handle).
    pub subject: String,
    /// Issued-at (unix seconds).
    pub issued_at: i64,
    /// Expiry (unix seconds), if any. `None` = perpetual.
    pub expires_at: Option<i64>,
    /// Issuer's embedded public keys (transitive authentication, P-03
    /// pattern: the fingerprint is a commitment to keys; carrying the keys
    /// lets an offline verifier recompute and check the commitment).
    pub issuer_keys: SignerKeys,
    /// Base64 hybrid signature over [`license_payload_input`].
    pub sig: String,
}

impl License {
    /// Payload bytes this token commits to (what the signature covers).
    pub fn payload(&self) -> Vec<u8> {
        license_payload_input(
            self.v,
            &self.id,
            self.tier,
            &self.subject,
            self.issued_at,
            self.expires_at,
        )
    }

    /// Issuer public keys as raw bytes: `(ed25519(32), falcon(1793))`.
    pub fn issuer_keys_bytes(&self) -> Result<([u8; 32], Vec<u8>)> {
        let ed = hex::decode(&self.issuer_keys.ed25519_pk).map_err(|e| {
            ProvenanceError::InvalidLicense(format!("bad issuer ed25519_pk hex: {e}"))
        })?;
        let ed: [u8; 32] = ed
            .try_into()
            .map_err(|_| {
                ProvenanceError::InvalidLicense("issuer ed25519_pk must be 32 bytes".into())
            })?;
        let falcon = hex::decode(&self.issuer_keys.falcon_pk).map_err(|e| {
            ProvenanceError::InvalidLicense(format!("bad issuer falcon_pk hex: {e}"))
        })?;
        Ok((ed, falcon))
    }

    /// The issuer's fingerprint recomputed from embedded keys.
    pub fn issuer_fingerprint_raw(&self) -> Result<[u8; 32]> {
        let (ed, falcon) = self.issuer_keys_bytes()?;
        Ok(crate::encoding::signer_fingerprint(&ed, &falcon)?)
    }

    /// Full verification: recomputes the issuer fingerprint from the
    /// embedded keys, compares it to `expected_issuer_fp` (the build-time
    /// pin), checks version/tier/field bounds, then verifies the hybrid
    /// signature over the canonical payload. No wall-clock checks here —
    /// expiry presentation belongs to the shell.
    pub fn verify(&self, expected_issuer_fp: &[u8; 32]) -> Result<()> {
        if self.v != LICENSE_VERSION {
            return Err(ProvenanceError::InvalidLicense(format!(
                "unsupported license version {} (expected {LICENSE_VERSION})",
                self.v
            )));
        }
        if self.id.is_empty() || self.id.len() > 128 {
            return Err(field_err("id"));
        }
        if self.tier == 0 || self.tier > MAX_TIER {
            return Err(field_err("tier"));
        }
        if self.subject.is_empty() || self.subject.len() > 256 {
            return Err(field_err("subject"));
        }
        if let Some(exp) = self.expires_at {
            if exp < self.issued_at {
                return Err(field_err("expires_at"));
            }
        }
        let keys = self.issuer_keys_bytes()?;
        if self.issuer_fingerprint_raw()? != *expected_issuer_fp {
            return Err(ProvenanceError::InvalidLicense(
                "license issuer fingerprint does not match this build's pin — the license was not issued by this publisher".into(),
            ));
        }
        let sig = SignerKeys::hybrid_sig_from_base64(&self.sig)?;
        sig.verify(&keys.0, &keys.1, &self.payload())
            .map_err(|e| {
                ProvenanceError::InvalidLicense(format!("license signature invalid: {e}"))
            })?;
        Ok(())
    }

    /// Remaining seconds until expiry, or `None` if perpetual.
    pub fn seconds_remaining(&self, now: i64) -> Option<i64> {
        self.expires_at.map(|exp| exp - now)
    }

    /// `expires_at` rendered as ISO-8601 UTC, or "perpetual".
    pub fn format_expires(&self) -> String {
        match self.expires_at {
            None => "perpetual".to_string(),
            Some(ts) => format_unix(ts),
        }
    }
}

/// Seconds→ISO-8601 UTC without pulling a chrono dependency into the
/// engine. Proleptic Gregorian, days-from-epoch algorithm.
pub fn format_unix(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let mth = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Parse a license file with size bounds. Inverse of [`write`].
pub fn parse(text: &str) -> Result<License> {
    if text.len() > MAX_LICENSE_BYTES {
        return Err(ProvenanceError::InvalidLicense(format!(
            "license file too large ({} bytes > {MAX_LICENSE_BYTES})",
            text.len()
        )));
    }
    serde_json::from_str(text)
        .map_err(|e| ProvenanceError::InvalidLicense(format!("bad license JSON: {e}")))
}

/// Serialize a license to canonical pretty JSON (what `issue` writes).
pub fn write(lic: &License) -> Result<String> {
    serde_json::to_string_pretty(lic)
        .map_err(|e| ProvenanceError::InvalidLicense(format!("serialize: {e}")))
}

fn field_err(field: &str) -> ProvenanceError {
    ProvenanceError::InvalidLicense(format!("invalid license {field}"))
}

/// Whether `s` is a syntactically valid issuer pin (64 hex chars).
/// Split out for tests; [`issuer_fingerprint`] fails closed through it.
pub fn is_valid_pin(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The compile-time feature flag: issuer fingerprint hex pinned at build
/// time via the `ORIGIN_ISSUER_FP` env var. Fails closed: anything that is
/// not exactly a valid 64-hex pin — absent, EMPTY (a nonexistent GitHub
/// Actions secret expands to "" and cargo forwards the outer env to
/// rustc, so `option_env!` sees it even when build.rs withholds it), or
/// malformed — yields `None`, i.e. licensing inert in this build.
pub fn issuer_fingerprint() -> Option<&'static str> {
    match option_env!("ORIGIN_ISSUER_FP") {
        Some(s) if is_valid_pin(s) => Some(s),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Signer;

    fn issuer() -> Signer {
        Signer::from_seed(&[7u8; 32]).expect("derive")
    }

    fn sample(issuer: &Signer) -> License {
        License {
            v: LICENSE_VERSION,
            id: "lic-123".into(),
            tier: 1,
            subject: "user@example.com".into(),
            issued_at: 1_700_000_000,
            expires_at: Some(1_800_000_000),
            issuer_keys: issuer.public_keys(),
            sig: {
                let sig = issuer.sign(&license_payload_input(
                    LICENSE_VERSION,
                    "lic-123",
                    1,
                    "user@example.com",
                    1_700_000_000,
                    Some(1_800_000_000),
                )).expect("sign");
                SignerKeys::hybrid_sig_to_base64(&sig).expect("b64")
            },
        }
    }

    #[test]
    fn issue_verify_roundtrip() {
        let iss = issuer();
        let lic = sample(&iss);
        lic.verify(&iss.fingerprint_raw()).expect("valid license verifies");
    }

    #[test]
    fn wrong_issuer_pin_rejected() {
        let iss = issuer();
        let lic = sample(&iss);
        let other = Signer::from_seed(&[8u8; 32]).expect("derive");
        let err = lic
            .verify(&other.fingerprint_raw())
            .expect_err("wrong issuer pin must fail");
        assert!(err.to_string().contains("issuer"), "got: {err}");
    }

    #[test]
    fn tampered_payload_rejected() {
        let iss = issuer();
        let mut lic = sample(&iss);
        lic.tier = 2; // upgrade attempt: payload changes, sig doesn't
        let err = lic
            .verify(&iss.fingerprint_raw())
            .expect_err("tampered license must fail");
        assert!(err.to_string().contains("signature"), "got: {err}");
    }

    #[test]
    fn swap_embedded_keys_rejected() {
        // Attacker swaps in their own keys AND re-signs — but the pin
        // compares against the *pinned* issuer, and the recomputed
        // fingerprint of the swapped keys no longer matches it.
        let iss = issuer();
        let lic = sample(&iss);
        let mallory = Signer::from_seed(&[9u8; 32]).expect("derive");
        let mut forged = lic.clone();
        forged.issuer_keys = mallory.public_keys();
        forged.sig = {
            let sig = mallory.sign(&forged.payload()).expect("sign");
            SignerKeys::hybrid_sig_to_base64(&sig).expect("b64")
        };
        let err = forged
            .verify(&iss.fingerprint_raw())
            .expect_err("key-swap forgery must fail");
        assert!(err.to_string().contains("issuer"), "got: {err}");
    }

    #[test]
    fn parse_write_roundtrip() {
        let iss = issuer();
        let lic = sample(&iss);
        let text = write(&lic).expect("write");
        let back = parse(&text).expect("parse");
        assert_eq!(lic, back);
        back.verify(&iss.fingerprint_raw()).expect("roundtrip verifies");
    }

    #[test]
    fn cross_domain_replay_rejected() {
        // A signature over an ANCHOR payload must not verify as a license
        // (distinct domain tags). Reuse the same issuer over anchor-shaped
        // bytes; the license payload differs, so verification fails.
        let iss = issuer();
        let lic = sample(&iss);
        let anchor_msg = crate::encoding::anchor_payload_input(1, &[3u8; 32], &[4u8; 32]);
        let cross = License {
            sig: {
                let sig = iss.sign(&anchor_msg).expect("sign");
                SignerKeys::hybrid_sig_to_base64(&sig).expect("b64")
            },
            ..lic
        };
        assert!(cross.verify(&iss.fingerprint_raw()).is_err());
    }

    #[test]
    fn field_bounds_enforced() {
        let iss = issuer();
        let mut lic = sample(&iss);
        lic.tier = 0;
        assert!(lic.verify(&iss.fingerprint_raw()).is_err());
        let mut lic = sample(&iss);
        lic.v = 2;
        assert!(lic.verify(&iss.fingerprint_raw()).is_err());
        let mut lic = sample(&iss);
        lic.expires_at = Some(lic.issued_at - 1);
        assert!(lic.verify(&iss.fingerprint_raw()).is_err());
    }

    #[test]
    fn format_unix_known_values() {
        assert_eq!(format_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_unix(951_782_400), "2000-02-29T00:00:00Z"); // leap day
    }

    #[test]
    fn pin_validation_fails_closed() {
        assert!(is_valid_pin(
            "f7977ba05b5f3929da6a6d3508fd344bd04a2445f26f4bfd833ebd9a3da6a775"
        ));
        // Empty string: the nonexistent-CI-secret case — must NOT count as
        // an active pin (v0.1.8 release-gate lesson).
        assert!(!is_valid_pin(""));
        assert!(!is_valid_pin("   "));
        assert!(!is_valid_pin("nothex"));
        assert!(!is_valid_pin(&"a".repeat(63)));
        assert!(!is_valid_pin(&"a".repeat(65)));
        assert!(!is_valid_pin(&format!("{}gg", "a".repeat(62))));
    }
}
