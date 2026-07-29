//! Cookie-based handshake anti-DoS protection (WireGuard-style).
//!
//! Before doing any expensive computation, the responder can issue a
//! **cookie challenge** to an unknown initiator. The initiator must
//! include the cookie (HMAC of source IP + responder secret) in their
//! retry. The responder verifies the cookie before processing the
//! handshake, proving the initiator can receive at their claimed source
//! address — preventing CPU-exhaustion DoS.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A cookie is an HMAC-SHA3-256 truncated to 16 bytes.
pub type Cookie = [u8; 16];

/// Default cookie secret rotation interval (2 minutes).
pub const DEFAULT_COOKIE_ROTATION_SECS: u64 = 120;

/// Cookie generator for handshake DoS protection.
///
/// The responder holds a `CookieSecret` and issues cookies per source IP.
/// When an initiator presents a valid cookie, the responder knows the
/// initiator can receive at that IP (no spoofing).
pub struct CookieSecret {
    current: [u8; 32],
    previous: Option<[u8; 32]>,
    last_rotation: Instant,
    rotation_interval: Duration,
}

impl CookieSecret {
    /// Create a new secret with a random key from the OS CSPRNG.
    pub fn new() -> Self {
        let mut current = [0u8; 32];
        getrandom::fill(&mut current).expect("OS CSPRNG unavailable");
        Self {
            current,
            previous: None,
            last_rotation: Instant::now(),
            rotation_interval: Duration::from_secs(DEFAULT_COOKIE_ROTATION_SECS),
        }
    }

    /// Create with a custom rotation interval.
    pub fn with_rotation_interval(secs: u64) -> Self {
        let mut s = Self::new();
        s.rotation_interval = Duration::from_secs(secs);
        s
    }

    /// Generate a cookie for a given source IP.
    pub fn generate(&self, source_ip: &str) -> Cookie {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.generate_at(source_ip, now)
    }

    fn generate_at(&self, source_ip: &str, now: u64) -> Cookie {
        let mut input = Vec::with_capacity(source_ip.len() + 8);
        input.extend_from_slice(source_ip.as_bytes());
        input.extend_from_slice(&now.to_be_bytes());

        let full = origin_crypto_sdk::kdf::mac::hmac_sha3_256(&self.current, &input)
            .unwrap_or([0u8; 32]);
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(&full[..16]);
        cookie
    }

    /// Verify a cookie from a given source IP.
    ///
    /// Checks against both current and previous secrets (for rotation
    /// compatibility). Uses constant-time comparison.
    pub fn verify(&self, source_ip: &str, cookie: &Cookie) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.verify_at(source_ip, cookie, now)
    }

    fn verify_at(&self, source_ip: &str, cookie: &Cookie, now: u64) -> bool {
        let expected = self.generate_at(source_ip, now);
        if expected.ct_eq(cookie).into() {
            return true;
        }

        if let Some(ref prev_secret) = self.previous {
            let mut prev_input = Vec::with_capacity(source_ip.len() + 8);
            prev_input.extend_from_slice(source_ip.as_bytes());
            prev_input.extend_from_slice(&now.to_be_bytes());
            if let Ok(full) =
                origin_crypto_sdk::kdf::mac::hmac_sha3_256(prev_secret, &prev_input)
            {
                let mut prev_expected = [0u8; 16];
                prev_expected.copy_from_slice(&full[..16]);
                if prev_expected.ct_eq(cookie).into() {
                    return true;
                }
            }
        }

        false
    }

    /// Rotate the secret if the rotation interval has elapsed.
    pub fn maybe_rotate(&mut self) -> bool {
        if self.last_rotation.elapsed() >= self.rotation_interval {
            self.force_rotate();
            true
        } else {
            false
        }
    }

    /// Force rotation (for testing or manual key management).
    pub fn force_rotate(&mut self) {
        self.previous = Some(self.current);
        let mut new_secret = [0u8; 32];
        getrandom::fill(&mut new_secret).expect("OS CSPRNG unavailable");
        self.current = new_secret;
        self.last_rotation = Instant::now();
    }

    /// Time since last rotation.
    pub fn time_since_rotation(&self) -> Duration {
        self.last_rotation.elapsed()
    }
}

impl Default for CookieSecret {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CookieSecret {
    fn drop(&mut self) {
        self.current.zeroize();
        if let Some(ref mut prev) = self.previous {
            prev.zeroize();
        }
    }
}

// ── Frame Tag Constants ───────────────────────────────────────────

/// Tag byte for a cookie challenge frame (responder → initiator).
pub const COOKIE_CHALLENGE_TAG: u8 = 0xCC;
/// Total length of a cookie challenge frame.
pub const COOKIE_CHALLENGE_LEN: usize = 17;

/// Tag byte for a cookie response frame (initiator → responder).
pub const COOKIE_RESPONSE_TAG: u8 = 0xCD;
/// Total length of a cookie response frame.
pub const COOKIE_RESPONSE_LEN: usize = 17;

/// Encode a cookie challenge frame.
pub fn encode_cookie_challenge(cookie: &Cookie) -> Vec<u8> {
    let mut frame = Vec::with_capacity(COOKIE_CHALLENGE_LEN);
    frame.push(COOKIE_CHALLENGE_TAG);
    frame.extend_from_slice(cookie);
    frame
}

/// Encode a cookie response frame.
pub fn encode_cookie_response(cookie: &Cookie) -> Vec<u8> {
    let mut frame = Vec::with_capacity(COOKIE_RESPONSE_LEN);
    frame.push(COOKIE_RESPONSE_TAG);
    frame.extend_from_slice(cookie);
    frame
}

/// Decode a cookie frame, returning the cookie bytes if valid.
pub fn decode_cookie_frame(frame: &[u8]) -> Option<Cookie> {
    if frame.len() < 17 {
        return None;
    }
    match frame[0] {
        COOKIE_CHALLENGE_TAG | COOKIE_RESPONSE_TAG => {
            let mut cookie = [0u8; 16];
            cookie.copy_from_slice(&frame[1..17]);
            Some(cookie)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_verify() {
        let secret = CookieSecret::new();
        let cookie = secret.generate("192.168.1.50");
        assert!(secret.verify("192.168.1.50", &cookie));
        assert!(!secret.verify("10.0.0.1", &cookie));
    }

    #[test]
    fn test_different_secrets() {
        let s1 = CookieSecret::new();
        let s2 = CookieSecret::new();
        let c1 = s1.generate("1.2.3.4");
        let c2 = s2.generate("1.2.3.4");
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_constant_time() {
        let secret = CookieSecret::new();
        let cookie = secret.generate("1.2.3.4");
        let mut wrong = cookie;
        wrong[0] ^= 1;
        assert!(!secret.verify("1.2.3.4", &wrong));
        assert!(secret.verify("1.2.3.4", &cookie));
    }

    #[test]
    fn test_rotation_validates_old() {
        let mut secret = CookieSecret::new();
        let cookie = secret.generate("10.0.0.1");
        secret.force_rotate();
        assert!(secret.verify("10.0.0.1", &cookie));
    }

    #[test]
    fn test_rotation_new_secret_differs() {
        let mut secret = CookieSecret::new();
        let c1 = secret.generate("10.0.0.1");
        secret.force_rotate();
        let c2 = secret.generate("10.0.0.1");
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_maybe_rotate_no_rotation() {
        let mut secret = CookieSecret::with_rotation_interval(3600);
        let c1 = secret.generate("1.2.3.4");
        assert!(!secret.maybe_rotate());
        let c2 = secret.generate("1.2.3.4");
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_frame_encode_decode() {
        let cookie = [0xAB; 16];
        let challenge = encode_cookie_challenge(&cookie);
        assert_eq!(challenge[0], COOKIE_CHALLENGE_TAG);
        assert_eq!(challenge.len(), COOKIE_CHALLENGE_LEN);

        let response = encode_cookie_response(&cookie);
        assert_eq!(response[0], COOKIE_RESPONSE_TAG);
        assert_eq!(response.len(), COOKIE_RESPONSE_LEN);

        assert_eq!(decode_cookie_frame(&challenge), Some(cookie));
        assert_eq!(decode_cookie_frame(&response), Some(cookie));
    }

    #[test]
    fn test_frame_decode_invalid() {
        assert_eq!(decode_cookie_frame(&[0xFF; 17]), None);
        assert_eq!(decode_cookie_frame(&[0xCC; 5]), None);
    }

    #[test]
    fn test_os_csprng() {
        let s1 = CookieSecret::new();
        let s2 = CookieSecret::new();
        let c1 = s1.generate("same-ip");
        let c2 = s2.generate("same-ip");
        assert_ne!(c1, c2);
    }
}
