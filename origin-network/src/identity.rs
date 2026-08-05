// SPDX-License-Identifier: Apache-2.0

//! Identity binding — transport keys, AUTH claims, peer verification.
//!
//! Spec REV 3 §3.2/§3.3:
//! * Transport keys are DERIVED from the identity seed, never random.
//! * The AUTH claim proves fingerprint↔key ownership via a hybrid
//!   Ed25519+Falcon-1024 signature over the handshake transcript.
//! * Verification needs the peer's public keys (a fingerprint is a hash —
//!   it cannot be derived from a public key). The `PeerKeys` record is the
//!   directory entry that carries that binding (out-of-band exchange / TOFU).

use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use origin_crypto_sdk::pqc::falcon1024::{FalconPublicKey, FalconSignature};
use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle};

use crate::address::Fingerprint;
use crate::error::{NetworkError, Result};
use crate::wire::AuthClaim;

/// Key derivation domain for network transport keys (spec §3.2).
pub const TRANSPORT_KEY_DOMAIN: &str = "origin-network:transport:v1";
/// Key derivation domain for identity signing keys — must match
/// origin-identity's convention so signatures verify against the same
/// identity keys.
pub const IDENTITY_KEY_DOMAIN: &str = "origin-identity:v1";
/// Current protocol version carried in AUTH claims (spec §6.6).
pub const PROTOCOL_VERSION: u16 = 1;

/// Length-prefix size for the hybrid signature wire format.
const SIG_LEN_PREFIX: usize = 4;
/// Ed25519 signature length.
const ED_SIG_LEN: usize = 64;
/// Maximum Falcon-1024 signature length (SDK CT bound).
const FALCON_SIG_MAX: usize = origin_crypto_sdk::pqc::falcon1024::sizes::SIGNATURE_MAX;

/// Derive a device's X25519 transport static secret from the identity
/// seed. Deterministic: same seed + device index → same key. Zeroized on
/// drop.
pub fn derive_transport_secret(seed: &[u8; 32], device_index: u32) -> Result<StaticSecret> {
    let mut bytes = [0u8; 32];
    {
        let mut derived = origin_crypto_sdk::seed::SeedHandle::new(seed, None)
            .derive_key(TRANSPORT_KEY_DOMAIN, &device_index.to_string(), 32)
            .ok_or_else(|| NetworkError::Crypto("transport key derivation failed".into()))?;
        bytes.copy_from_slice(&derived[..32]);
        derived.zeroize();
    }
    Ok(StaticSecret::from(bytes))
}

/// The X25519 public key for a derived transport secret.
pub fn transport_public_key(secret: &StaticSecret) -> [u8; 32] {
    X25519PublicKey::from(secret).to_bytes()
}

/// Serialize a hybrid signature to wire bytes:
/// `[4B falcon_len BE][64B ed25519][falcon...]`.
pub fn hybrid_sig_to_wire(sig: &Ed25519Falcon1024) -> Vec<u8> {
    let falcon = sig.falcon_sig.as_bytes();
    let mut out = Vec::with_capacity(SIG_LEN_PREFIX + ED_SIG_LEN + falcon.len());
    out.extend_from_slice(&(falcon.len() as u32).to_be_bytes());
    out.extend_from_slice(&sig.ed25519_sig.to_bytes());
    out.extend_from_slice(falcon);
    out
}

/// Parse a hybrid signature from wire bytes.
pub fn hybrid_sig_from_wire(raw: &[u8]) -> Result<Ed25519Falcon1024> {
    let min = SIG_LEN_PREFIX + ED_SIG_LEN;
    if raw.len() < min {
        return Err(NetworkError::Auth(format!(
            "signature too short: {} bytes (min {min})",
            raw.len()
        )));
    }
    let falcon_len = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;
    if falcon_len > FALCON_SIG_MAX {
        return Err(NetworkError::Auth(format!(
            "falcon signature length {falcon_len} exceeds max {FALCON_SIG_MAX}"
        )));
    }
    if raw.len() != min + falcon_len {
        return Err(NetworkError::Auth(format!(
            "signature length mismatch: header says {falcon_len} falcon bytes, total {}",
            raw.len()
        )));
    }
    let ed_sig =
        ed25519_dalek::Signature::from_slice(&raw[SIG_LEN_PREFIX..SIG_LEN_PREFIX + ED_SIG_LEN])
            .map_err(|e| NetworkError::Auth(format!("bad ed25519 signature: {e}")))?;
    let falcon_sig = FalconSignature::from_bytes(&raw[SIG_LEN_PREFIX + ED_SIG_LEN..])
        .map_err(|e| NetworkError::Auth(format!("bad falcon signature: {e}")))?;
    Ok(Ed25519Falcon1024 {
        ed25519_sig: ed_sig,
        falcon_sig,
    })
}

/// The message signed in an AUTH claim — binds the claim to this exact
/// handshake and this exact relay/peer.
///
/// `SHA3-256(domain ‖ version ‖ fingerprint ‖ x25519_pk ‖ nonce ‖
///            peer_fp ‖ transcript)`
pub fn auth_message(
    fingerprint: &Fingerprint,
    x25519_pk: &[u8; 32],
    nonce: &[u8; 16],
    peer_fp: &Fingerprint,
    transcript: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(128 + transcript.len());
    msg.extend_from_slice(b"origin-network:auth-claim:v1");
    msg.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    msg.extend_from_slice(fingerprint.as_bytes());
    msg.extend_from_slice(x25519_pk);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(peer_fp.as_bytes());
    msg.extend_from_slice(transcript);
    origin_crypto_sdk::sha3_256(&msg).to_vec()
}

/// Sign an AUTH claim with the identity's hybrid keys.
pub fn sign_auth_claim(
    seed: &[u8; 32],
    device_index: u32,
    peer_fp: &Fingerprint,
    transcript: &[u8],
) -> Result<AuthClaim> {
    let bundle = HybridSigningKeyBundle::from_seed(seed, IDENTITY_KEY_DOMAIN)
        .map_err(|e| NetworkError::Auth(format!("identity bundle: {e}")))?;
    let secret = derive_transport_secret(seed, device_index)?;
    let x25519_pk = transport_public_key(&secret);
    let fingerprint = Fingerprint::from_seed_bytes(seed);
    let mut nonce = [0u8; 16];
    origin_crypto_sdk::fill_random(&mut nonce).map_err(|e| NetworkError::Crypto(e.to_string()))?;
    let message = auth_message(&fingerprint, &x25519_pk, &nonce, peer_fp, transcript);
    let sig = bundle
        .try_sign_hybrid(&message)
        .map_err(|e| NetworkError::Auth(format!("signing failed: {e}")))?;
    Ok(AuthClaim {
        fingerprint: fingerprint.0,
        x25519_pk,
        hybrid_signature: hybrid_sig_to_wire(&sig),
        protocol_version: PROTOCOL_VERSION,
        nonce,
    })
}

/// Public keys needed to verify an identity's AUTH claims and dial its
/// devices. Exchanged out-of-band (contact add / TOFU) — a fingerprint
/// alone cannot verify. One record per (identity, device).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerKeys {
    pub fingerprint: [u8; 32],
    /// Device index this record's transport key belongs to.
    pub device_index: u32,
    /// Ed25519 verifying key (32 bytes).
    pub ed25519_pk: Vec<u8>,
    /// Falcon-1024 public key (1793 bytes).
    pub falcon_pk: Vec<u8>,
    /// X25519 transport public key for this device (32 bytes) — required
    /// for IK dialing and AUTH claim verification.
    pub transport_pk: Vec<u8>,
}

impl PeerKeys {
    /// Build a record from a local seed (for tests / self-hosted contacts).
    pub fn from_seed(seed: &[u8; 32], device_index: u32) -> Result<Self> {
        let bundle = HybridSigningKeyBundle::from_seed(seed, IDENTITY_KEY_DOMAIN)
            .map_err(|e| NetworkError::Auth(format!("identity bundle: {e}")))?;
        let secret = derive_transport_secret(seed, device_index)?;
        Ok(Self {
            fingerprint: Fingerprint::from_seed_bytes(seed).0,
            device_index,
            ed25519_pk: bundle.ed25519_pk().to_bytes().to_vec(),
            falcon_pk: bundle.falcon1024_pk().as_bytes().to_vec(),
            transport_pk: transport_public_key(&secret).to_vec(),
        })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(self.fingerprint)
    }

    /// Transport public key as a fixed array, if well-formed.
    pub fn transport_pk_bytes(&self) -> Result<[u8; 32]> {
        self.transport_pk
            .as_slice()
            .try_into()
            .map_err(|_| NetworkError::Auth("bad transport key length in peer record".into()))
    }
}

/// Verify an AUTH claim against known peer keys.
///
/// Checks, in order:
/// 1. claimed fingerprint matches the record's fingerprint,
/// 2. protocol version is current,
/// 3. hybrid signature verifies over the auth message,
/// 4. (caller separately checks x25519_pk == handshake static key).
pub fn verify_auth_claim(
    peer: &PeerKeys,
    claim: &AuthClaim,
    peer_fp: &Fingerprint,
    transcript: &[u8],
) -> Result<()> {
    if claim.fingerprint != peer.fingerprint {
        return Err(NetworkError::Auth(
            "fingerprint mismatch with peer record".into(),
        ));
    }
    if claim.protocol_version != PROTOCOL_VERSION {
        return Err(NetworkError::Auth(format!(
            "unsupported protocol version {}",
            claim.protocol_version
        )));
    }
    if peer.ed25519_pk.len() != 32 {
        return Err(NetworkError::Auth(
            "bad ed25519 public key length in peer record".into(),
        ));
    }
    let ed_pk_bytes: [u8; 32] = peer.ed25519_pk[..32].try_into().unwrap();
    let ed_pk = ed25519_dalek::VerifyingKey::from_bytes(&ed_pk_bytes)
        .map_err(|e| NetworkError::Auth(format!("bad ed25519 public key: {e}")))?;
    let falcon_pk = FalconPublicKey::from_bytes(&peer.falcon_pk)
        .map_err(|e| NetworkError::Auth(format!("bad falcon public key: {e}")))?;
    let sig = hybrid_sig_from_wire(&claim.hybrid_signature)?;
    let fp = Fingerprint(claim.fingerprint);
    let message = auth_message(&fp, &claim.x25519_pk, &claim.nonce, peer_fp, transcript);
    Ed25519Falcon1024::verify(&ed_pk, &falcon_pk, &message, &sig)
        .map_err(|_| NetworkError::Auth("hybrid signature verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_a() -> [u8; 32] {
        [0x11; 32]
    }
    fn seed_b() -> [u8; 32] {
        [0x22; 32]
    }

    #[test]
    fn transport_key_derivation_deterministic() {
        let k1 = derive_transport_secret(&seed_a(), 0).unwrap();
        let k2 = derive_transport_secret(&seed_a(), 0).unwrap();
        assert_eq!(transport_public_key(&k1), transport_public_key(&k2));
    }

    #[test]
    fn transport_keys_differ_per_device() {
        let k0 = derive_transport_secret(&seed_a(), 0).unwrap();
        let k1 = derive_transport_secret(&seed_a(), 1).unwrap();
        assert_ne!(transport_public_key(&k0), transport_public_key(&k1));
    }

    #[test]
    fn transport_keys_differ_per_seed() {
        let ka = derive_transport_secret(&seed_a(), 0).unwrap();
        let kb = derive_transport_secret(&seed_b(), 0).unwrap();
        assert_ne!(transport_public_key(&ka), transport_public_key(&kb));
    }

    #[test]
    fn hybrid_sig_wire_roundtrip() {
        let bundle = HybridSigningKeyBundle::from_seed(&seed_a(), IDENTITY_KEY_DOMAIN).unwrap();
        let sig = bundle.sign_hybrid(b"payload");
        let wire = hybrid_sig_to_wire(&sig);
        let back = hybrid_sig_from_wire(&wire).unwrap();
        assert_eq!(back.ed25519_sig.to_bytes(), sig.ed25519_sig.to_bytes());
        assert_eq!(back.falcon_sig.as_bytes(), sig.falcon_sig.as_bytes());
    }

    #[test]
    fn hybrid_sig_wire_rejects_bad_input() {
        assert!(hybrid_sig_from_wire(&[]).is_err());
        assert!(hybrid_sig_from_wire(&[0; 10]).is_err());
        // Header claims more falcon bytes than present.
        let mut forged = vec![0, 0, 0x10, 0]; // 4096 falcon bytes claimed
        forged.extend_from_slice(&[0u8; 64]);
        forged.extend_from_slice(&[0u8; 10]);
        assert!(hybrid_sig_from_wire(&forged).is_err());
        // Header claims more than the Falcon maximum.
        let mut huge = vec![0xFF; 4];
        huge.extend_from_slice(&[0u8; 64]);
        assert!(hybrid_sig_from_wire(&huge).is_err());
    }

    #[test]
    fn peer_keys_from_seed_fingerprint_matches() {
        let pk = PeerKeys::from_seed(&seed_a(), 0).unwrap();
        assert_eq!(pk.fingerprint(), Fingerprint::from_seed_bytes(&seed_a()));
        assert_eq!(pk.ed25519_pk.len(), 32);
        assert_eq!(
            pk.falcon_pk.len(),
            origin_crypto_sdk::pqc::falcon1024::sizes::PUBLIC_KEY
        );
    }

    #[test]
    fn auth_claim_sign_verify_roundtrip() {
        let peer = PeerKeys::from_seed(&seed_a(), 0).unwrap();
        let relay_fp = Fingerprint::from_seed_bytes(&seed_b());
        let transcript = b"handshake-transcript-bytes";
        let claim = sign_auth_claim(&seed_a(), 0, &relay_fp, transcript).unwrap();
        verify_auth_claim(&peer, &claim, &relay_fp, transcript).unwrap();
    }

    #[test]
    fn auth_claim_rejects_wrong_transcript() {
        let peer = PeerKeys::from_seed(&seed_a(), 0).unwrap();
        let relay_fp = Fingerprint::from_seed_bytes(&seed_b());
        let claim = sign_auth_claim(&seed_a(), 0, &relay_fp, b"t1").unwrap();
        assert!(verify_auth_claim(&peer, &claim, &relay_fp, b"t2").is_err());
    }

    #[test]
    fn auth_claim_rejects_wrong_relay_fp() {
        let peer = PeerKeys::from_seed(&seed_a(), 0).unwrap();
        let relay_fp = Fingerprint::from_seed_bytes(&seed_b());
        let other_fp = Fingerprint::from_seed_bytes(&seed_a());
        let claim = sign_auth_claim(&seed_a(), 0, &relay_fp, b"t").unwrap();
        assert!(verify_auth_claim(&peer, &claim, &other_fp, b"t").is_err());
    }

    #[test]
    fn auth_claim_rejects_wrong_peer_record() {
        let wrong_peer = PeerKeys::from_seed(&seed_b(), 0).unwrap();
        let relay_fp = Fingerprint::from_seed_bytes(&seed_b());
        let claim = sign_auth_claim(&seed_a(), 0, &relay_fp, b"t").unwrap();
        assert!(verify_auth_claim(&wrong_peer, &claim, &relay_fp, b"t").is_err());
    }

    #[test]
    fn auth_claim_rejects_tampered_key() {
        let peer = PeerKeys::from_seed(&seed_a(), 0).unwrap();
        let relay_fp = Fingerprint::from_seed_bytes(&seed_b());
        let mut claim = sign_auth_claim(&seed_a(), 0, &relay_fp, b"t").unwrap();
        claim.x25519_pk[0] ^= 0xFF;
        assert!(verify_auth_claim(&peer, &claim, &relay_fp, b"t").is_err());
    }

    #[test]
    fn auth_claim_rejects_bad_version() {
        let peer = PeerKeys::from_seed(&seed_a(), 0).unwrap();
        let relay_fp = Fingerprint::from_seed_bytes(&seed_b());
        let mut claim = sign_auth_claim(&seed_a(), 0, &relay_fp, b"t").unwrap();
        claim.protocol_version = 99;
        assert!(verify_auth_claim(&peer, &claim, &relay_fp, b"t").is_err());
    }

    #[test]
    fn auth_claim_rejects_fingerprint_mismatch() {
        let peer = PeerKeys::from_seed(&seed_a(), 0).unwrap();
        let relay_fp = Fingerprint::from_seed_bytes(&seed_b());
        let mut claim = sign_auth_claim(&seed_a(), 0, &relay_fp, b"t").unwrap();
        claim.fingerprint = [0; 32];
        assert!(verify_auth_claim(&peer, &claim, &relay_fp, b"t").is_err());
    }

    #[test]
    fn auth_message_deterministic_and_bound() {
        let fp = Fingerprint::from_seed_bytes(&seed_a());
        let pk = [7u8; 32];
        let nonce = [9u8; 16];
        let m1 = auth_message(&fp, &pk, &nonce, &fp, b"t");
        let m2 = auth_message(&fp, &pk, &nonce, &fp, b"t");
        assert_eq!(m1, m2);
        let m3 = auth_message(&fp, &pk, &nonce, &fp, b"t2");
        assert_ne!(m1, m3);
        assert_eq!(m1.len(), 32); // SHA3-256 output
    }
}
