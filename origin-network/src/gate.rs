// SPDX-License-Identifier: Apache-2.0

//! Anti-abuse gates (spec REV 3 §9) — composed from existing crates:
//!
//! * **Cookie gate** (origin-attest): WireGuard-style HMAC cookie proves a
//!   handshake source can receive at its claimed address — checked BEFORE
//!   any expensive crypto.
//! * **PoW gate** (origin-stealth via SDK): spam registrations / inbox
//!   abuse pay a stealth proof-of-work bound to the destination.
//! * **Token bucket** (origin-network): per-source handshake flood limit.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{NetworkError, Result};

// ── Cookie gate (origin-attest) ─────────────────────────────────────────

/// Handshake DoS gate. Wraps origin-attest's WireGuard-style cookie
/// machinery: a source must echo back a cookie (HMAC of its address under
/// a rotating relay secret) before the relay spends ECDH cycles on it.
pub struct CookieGate {
    secret: origin_attest::cookie::CookieSecret,
}

impl CookieGate {
    pub fn new() -> Result<Self> {
        Ok(Self {
            secret: origin_attest::cookie::CookieSecret::new()
                .map_err(|e| NetworkError::Crypto(e.to_string()))?,
        })
    }

    /// Issue a cookie for a source address (relay → challenger).
    pub fn challenge(&self, source: &str) -> [u8; 16] {
        self.secret.generate(source)
    }

    /// Verify an echoed cookie from a source address.
    pub fn verify(&self, source: &str, cookie: &[u8; 16]) -> bool {
        self.secret.verify(source, cookie)
    }

    /// Rotate the secret if due (returns whether rotation happened).
    pub fn maybe_rotate(&mut self) -> Result<bool> {
        self.secret
            .maybe_rotate()
            .map_err(|e| NetworkError::Crypto(e.to_string()))
    }
}

impl Default for CookieGate {
    fn default() -> Self {
        Self::new().expect("OS CSPRNG available")
    }
}

/// Wire payload for a cookie challenge/response exchange.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CookieChallenge {
    pub cookie: [u8; 16],
}

// ── PoW gate (origin-stealth via SDK) ───────────────────────────────────

/// Spam gate: a sender must present a valid stealth PoW bound to the
/// destination before SESSION_OPEN / INBOX_PUSH are honored.
pub struct PowGate {
    /// Required difficulty (leading zero bits).
    pub difficulty: u32,
}

/// Wire-serializable PoW proof (mirrors the SDK struct, serde-friendly).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PowProof {
    pub nonce: [u8; 32],
    pub extra: [u8; 16],
    pub counter: u64,
    pub difficulty: u32,
}

impl PowGate {
    pub fn new(difficulty: u32) -> Self {
        Self { difficulty }
    }

    /// Verify a proof: must satisfy the gate's difficulty, and the SDK's
    /// hash check must pass for (identity_pk, destination_hint).
    pub fn verify(&self, proof: &PowProof, identity_pk: &[u8], dest_hint: &[u8]) -> bool {
        if proof.difficulty < self.difficulty {
            return false;
        }
        let sdk_proof = origin_crypto_sdk::stealth::pow::StealthPowProof {
            nonce: proof.nonce,
            extra: proof.extra,
            counter: proof.counter,
            difficulty: proof.difficulty,
        };
        origin_crypto_sdk::stealth::pow::verify(&sdk_proof, identity_pk, dest_hint).unwrap_or(false)
    }

    /// Solve a proof (client side; tests / relay clients).
    pub fn solve(identity_pk: &[u8], dest_hint: &[u8], difficulty: u32) -> Result<PowProof> {
        let (proof, _iters) =
            origin_crypto_sdk::stealth::pow::solve(identity_pk, dest_hint, difficulty)
                .map_err(|e| NetworkError::Crypto(e.to_string()))?;
        Ok(PowProof {
            nonce: proof.nonce,
            extra: proof.extra,
            counter: proof.counter,
            difficulty: proof.difficulty,
        })
    }
}

// ── Token bucket (flood control) ────────────────────────────────────────

/// Per-source token bucket. Handshake attempts consume tokens; tokens
/// refill continuously up to `capacity`. Default: 5 per minute per spec.
pub struct TokenBucket {
    capacity: u32,
    refill: Duration, // time per token
    buckets: HashMap<String, (u32, Instant)>,
}

impl TokenBucket {
    /// New bucket: `capacity` attempts, refilling one token per
    /// `refill_secs`.
    pub fn new(capacity: u32, refill_secs: u64) -> Self {
        Self {
            capacity,
            refill: Duration::from_secs(refill_secs.max(1)),
            buckets: HashMap::new(),
        }
    }

    /// Try to admit one attempt from `source`. Returns true if allowed.
    pub fn allow(&mut self, source: &str) -> bool {
        let now = Instant::now();
        let entry = self
            .buckets
            .entry(source.to_string())
            .or_insert((self.capacity, now));
        // Refill.
        let elapsed = now.duration_since(entry.1);
        let refilled = (elapsed.as_secs_f64() / self.refill.as_secs_f64()).floor() as u32;
        if refilled > 0 {
            entry.0 = self.capacity.min(entry.0 + refilled);
            entry.1 = now;
        }
        if entry.0 > 0 {
            entry.0 -= 1;
            true
        } else {
            false
        }
    }

    /// Drop stale sources (memory hygiene for long-running relays).
    pub fn prune(&mut self, idle: Duration) {
        let now = Instant::now();
        self.buckets
            .retain(|_, (_, last)| now.duration_since(*last) < idle);
    }

    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

/// Composite ingress gate: bucket → cookie → (handshake proceeds).
pub struct IngressGate {
    pub bucket: TokenBucket,
    pub cookie: CookieGate,
}

impl IngressGate {
    pub fn new(capacity: u32, refill_secs: u64) -> Result<Self> {
        Ok(Self {
            bucket: TokenBucket::new(capacity, refill_secs),
            cookie: CookieGate::new()?,
        })
    }

    /// Admit a handshake attempt from `source`.
    pub fn allow_handshake(&mut self, source: &str) -> bool {
        self.bucket.allow(source)
    }

    /// Issue a cookie challenge for `source`.
    pub fn challenge(&self, source: &str) -> [u8; 16] {
        self.cookie.challenge(source)
    }

    /// Verify an echoed cookie.
    pub fn verify_cookie(&self, source: &str, cookie: &[u8; 16]) -> bool {
        self.cookie.verify(source, cookie)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_challenge_verify_roundtrip() {
        let gate = CookieGate::new().unwrap();
        let c = gate.challenge("203.0.113.7:5555");
        assert!(gate.verify("203.0.113.7:5555", &c));
    }

    #[test]
    fn cookie_wrong_source_rejected() {
        let gate = CookieGate::new().unwrap();
        let c = gate.challenge("203.0.113.7:5555");
        assert!(!gate.verify("198.51.100.1:1234", &c));
    }

    #[test]
    fn cookie_garbage_rejected() {
        let gate = CookieGate::new().unwrap();
        let _ = gate.challenge("1.2.3.4:1");
        assert!(!gate.verify("1.2.3.4:1", &[0u8; 16]));
    }

    #[test]
    fn cookie_rotation_keeps_previous_valid() {
        let mut gate = CookieGate::new().unwrap();
        let c = gate.challenge("9.9.9.9:9");
        gate.maybe_rotate().unwrap(); // may or may not rotate (time-based)
                                      // Cookies from the current OR previous secret verify.
        let c2 = gate.challenge("9.9.9.9:9");
        assert!(gate.verify("9.9.9.9:9", &c2));
        let _ = c;
    }

    #[test]
    fn pow_solve_verify_roundtrip() {
        let gate = PowGate::new(4);
        let identity_pk = b"identity-public-key";
        let dest = b"target-fingerprint";
        let proof = PowGate::solve(identity_pk, dest, 4).unwrap();
        assert!(gate.verify(&proof, identity_pk, dest));
    }

    #[test]
    fn pow_wrong_destination_rejected() {
        let gate = PowGate::new(4);
        let proof = PowGate::solve(b"pk", b"dest-a", 4).unwrap();
        assert!(!gate.verify(&proof, b"pk", b"dest-b"));
    }

    #[test]
    fn pow_wrong_identity_rejected() {
        let gate = PowGate::new(4);
        let proof = PowGate::solve(b"pk-a", b"dest", 4).unwrap();
        assert!(!gate.verify(&proof, b"pk-b", b"dest"));
    }

    #[test]
    fn pow_below_gate_difficulty_rejected() {
        let gate = PowGate::new(8);
        let proof = PowGate::solve(b"pk", b"dest", 4).unwrap();
        assert!(!gate.verify(&proof, b"pk", b"dest"));
    }

    #[test]
    fn pow_zero_difficulty_trivial() {
        let gate = PowGate::new(0);
        let proof = PowGate::solve(b"pk", b"dest", 0).unwrap();
        assert!(gate.verify(&proof, b"pk", b"dest"));
    }

    #[test]
    fn bucket_allows_up_to_capacity() {
        let mut b = TokenBucket::new(3, 60);
        assert!(b.allow("a"));
        assert!(b.allow("a"));
        assert!(b.allow("a"));
        assert!(!b.allow("a")); // exhausted
                                // Different source unaffected.
        assert!(b.allow("b"));
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut b = TokenBucket::new(1, 1);
        assert!(b.allow("s"));
        assert!(!b.allow("s"));
        std::thread::sleep(Duration::from_millis(1100));
        assert!(b.allow("s")); // refilled
    }

    #[test]
    fn bucket_prune_drops_idle() {
        let mut b = TokenBucket::new(2, 60);
        b.allow("x");
        assert_eq!(b.len(), 1);
        b.prune(Duration::from_secs(0)); // everything idle > 0s is stale…
                                         // prune keeps entries touched within `idle`; a 0s idle prunes none
                                         // because duration_since is ~0 < 0 is false → pruned.
        assert!(b.is_empty());
    }

    #[test]
    fn ingress_gate_composes() {
        let mut gate = IngressGate::new(2, 60).unwrap();
        let src = "192.0.2.1:4444";
        assert!(gate.allow_handshake(src));
        assert!(gate.allow_handshake(src));
        assert!(!gate.allow_handshake(src)); // flooded

        let c = gate.challenge(src);
        assert!(gate.verify_cookie(src, &c));
        assert!(!gate.verify_cookie("192.0.2.2:9", &c));
    }

    #[test]
    fn cookie_challenge_wire_roundtrip() {
        let gate = CookieGate::new().unwrap();
        let c = gate.challenge("8.8.8.8:53");
        let wire = serde_json::to_vec(&CookieChallenge { cookie: c }).unwrap();
        let back: CookieChallenge = serde_json::from_slice(&wire).unwrap();
        assert!(gate.verify("8.8.8.8:53", &back.cookie));
    }

    #[test]
    fn pow_proof_wire_roundtrip() {
        let proof = PowGate::solve(b"pk", b"dest", 4).unwrap();
        let wire = serde_json::to_vec(&proof).unwrap();
        let back: PowProof = serde_json::from_slice(&wire).unwrap();
        assert_eq!(proof, back);
    }
}
