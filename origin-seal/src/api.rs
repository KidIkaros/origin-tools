// SPDX-License-Identifier: Apache-2.0

//! api — the typed library surface for origin-seal.
//!
//! This is the "foundational crate" surface: an application that needs
//! encrypt/decrypt/sign/hash/mac calls these functions directly and gets
//! back typed values — no clap structs, no stdout parsing, no `String`
//! errors. The CLI (`commands.rs`) is a thin shell over this module.
//!
//! Design rules (suite-wide, see ARCHITECTURE.md):
//! - One crypto provider: every primitive goes through `origin-crypto-sdk`.
//! - One envelope format: bytes produced/consumed here are the ORGN wire
//!   format shared with `origin-common::Envelope` consumers.
//! - Errors are typed (`SealError`), never `String`.

use origin_common::{tier_from_byte, tier_to_byte, MemoryTier};
use origin_crypto_sdk::{
    aead::XChaCha20Poly1305, blake3, compression, hmac_sha3_256, sha3_256, sha3_512,
    signing::hybrid::HybridSigningKeyBundle,
};

use crate::error::{Result, SealError};

// ---------------------------------------------------------------------------
// hash
// ---------------------------------------------------------------------------

/// Hash algorithm selector for [`hash`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    /// SHA3-256 (32-byte digest).
    Sha3_256,
    /// SHA3-512 (64-byte digest).
    Sha3_512,
    /// BLAKE3 (32-byte digest).
    Blake3,
    /// HMAC-SHA3-256 (32-byte MAC; requires a key).
    HmacSha3_256,
}

/// Compute a digest/MAC over `data`. Keyed algorithms (`HmacSha3_256`) need
/// `key`; unkeyed algorithms reject a key rather than silently ignoring it.
pub fn hash(kind: HashKind, data: &[u8], key: Option<&[u8]>) -> Result<Vec<u8>> {
    match kind {
        HashKind::Sha3_256 => Ok(sha3_256(data).to_vec()),
        HashKind::Sha3_512 => Ok(sha3_512(data).to_vec()),
        HashKind::Blake3 => Ok(blake3::hash(data).as_bytes().to_vec()),
        HashKind::HmacSha3_256 => {
            let key =
                key.ok_or_else(|| SealError::Validation("HMAC-SHA3-256 requires a key".into()))?;
            hmac_sha3_256(key, data)
                .map_err(|e| SealError::Crypto(format!("HMAC failed: {e:?}")))
                .map(|m| m.to_vec())
        }
    }
}

// ---------------------------------------------------------------------------
// kdf
// ---------------------------------------------------------------------------

/// Derive a key of `len` bytes from a passphrase + salt using Argon2id at the
/// given tier. Deterministic: same (passphrase, salt, tier, len) → same key.
pub fn kdf(passphrase: &[u8], salt: &[u8; 16], tier: MemoryTier, len: usize) -> Result<Vec<u8>> {
    let params = tier.argon2_params(len);
    origin_crypto_sdk::kdf::Argon2idBuilder::new()
        .memory_kib(params.m_cost())
        .iterations(params.t_cost())
        .parallelism(params.p_cost())
        .output_len(len)
        .derive(passphrase, salt)
        .map_err(|e| SealError::Crypto(format!("Argon2id failed: {e:?}")))
}

// ---------------------------------------------------------------------------
// mac
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA3-256 over `data` with `key` (32-byte MAC).
pub fn mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hash(HashKind::HmacSha3_256, data, Some(key))
}

// ---------------------------------------------------------------------------
// envelope format (SEAL v1)
// ---------------------------------------------------------------------------

/// magic(4) ‖ version(1) ‖ flags(1) ‖ tier(1) ‖ reserved(1)
/// ‖ salt(16) ‖ nonce(24) ‖ ciphertext+tag(...)
const MAGIC: &[u8; 4] = b"SEAL";
const VERSION: u8 = 1;
const FLAG_COMPRESSED: u8 = 0x01;
const FLAG_STREAMED: u8 = 0x02;
const SUPPORTED_FLAGS: u8 = FLAG_COMPRESSED | FLAG_STREAMED;
const HEADER_LEN: usize = 48; // magic+ver+flags+tier+rsvd + salt + nonce

/// Maximum total envelope size: 4 GiB.
const MAX_ENVELOPE_LEN: usize = 4 * 1024 * 1024 * 1024;

/// Streaming chunk bounds.
const CHUNK_MIN: usize = 1024; // 1 KiB
const CHUNK_MAX: usize = 1 << 30; // 1 GiB

fn validate_envelope_flags(flags: u8, reserved: u8) -> Result<()> {
    if flags & !SUPPORTED_FLAGS != 0 {
        return Err(SealError::Envelope(format!(
            "unsupported envelope flags: 0x{flags:02x}"
        )));
    }
    if flags & FLAG_COMPRESSED != 0 && flags & FLAG_STREAMED != 0 {
        return Err(SealError::Envelope(
            "compressed and streamed envelope flags are mutually exclusive".into(),
        ));
    }
    if reserved != 0 {
        return Err(SealError::Envelope(format!(
            "unsupported reserved envelope byte: 0x{reserved:02x}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// encrypt / decrypt (passphrase-keyed, in-memory)
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with a passphrase-derived key (Argon2id at `tier`,
/// XChaCha20-Poly1305 for the payload). Optional zstd compression before
/// encryption. Returns the self-describing SEAL v1 envelope.
///
/// The passphrase is consumed as bytes; callers that hold a `String` should
/// zeroize it themselves (this API never logs or persists it).
pub fn encrypt(
    plaintext: &[u8],
    passphrase: &[u8],
    tier: MemoryTier,
    compress: bool,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    origin_crypto_sdk::fill_random(&mut salt)
        .map_err(|e| SealError::Crypto(format!("salt generation failed: {e}")))?;

    let key = derive_key(passphrase, &salt, tier)?;
    let mut nonce = [0u8; 24];
    origin_crypto_sdk::fill_random(&mut nonce)
        .map_err(|e| SealError::Crypto(format!("nonce generation failed: {e}")))?;

    let (payload, compressed) = if compress {
        let c = compression::compress(plaintext)
            .map_err(|e| SealError::Crypto(format!("compression failed: {e}")))?;
        (c, true)
    } else {
        (plaintext.to_vec(), false)
    };

    let ct = XChaCha20Poly1305::encrypt(&key, &nonce, &payload)
        .map_err(|e| SealError::Crypto(format!("encryption failed: {e:?}")))?;

    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(if compressed { FLAG_COMPRESSED } else { 0 });
    out.push(tier_to_byte(tier));
    out.push(0); // reserved
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt an envelope produced by [`encrypt`] (non-streamed path).
/// The tier is read from the envelope itself, so callers don't need to
/// remember it — but the passphrase must be the same one used to seal.
pub fn decrypt(envelope: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    let (header, payload) = parse_envelope(envelope)?;
    if header.flags & FLAG_STREAMED != 0 {
        return Err(SealError::Envelope(
            "streamed envelopes need decrypt_stream (not decrypt)".into(),
        ));
    }
    let key = derive_key(passphrase, &header.salt, header.tier)?;
    let pt = XChaCha20Poly1305::decrypt(&key, &header.nonce, payload).map_err(|_| {
        SealError::Verification("decryption failed (wrong passphrase or corrupt data)".into())
    })?;
    if header.flags & FLAG_COMPRESSED != 0 {
        compression::decompress(&pt)
            .map_err(|e| SealError::Crypto(format!("decompression failed: {e}")))
    } else {
        Ok(pt)
    }
}

/// A parsed envelope header — everything except the ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub version: u8,
    pub flags: u8,
    pub tier: MemoryTier,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
}

/// Parse an envelope header without decrypting. Useful for inspecting tier,
/// flags, or streaming mode before committing to a (potentially expensive)
/// key-derivation step.
pub fn parse_envelope(envelope: &[u8]) -> Result<(EnvelopeHeader, &[u8])> {
    if envelope.len() < HEADER_LEN + 16 {
        return Err(SealError::Envelope(format!(
            "input too short ({} bytes) to be a sealed envelope",
            envelope.len()
        )));
    }
    if envelope.len() > MAX_ENVELOPE_LEN {
        return Err(SealError::Envelope(format!(
            "envelope too large ({} bytes, max {MAX_ENVELOPE_LEN})",
            envelope.len()
        )));
    }
    if &envelope[..4] != MAGIC {
        return Err(SealError::Envelope(
            "not an origin-seal envelope (bad magic)".into(),
        ));
    }
    let version = envelope[4];
    if version != VERSION {
        return Err(SealError::Envelope(format!(
            "unsupported envelope version {version}"
        )));
    }
    let flags = envelope[5];
    validate_envelope_flags(flags, envelope[7])?;
    let tier = tier_from_byte(envelope[6])
        .map_err(|e| SealError::Envelope(format!("invalid tier byte: {e}")))?;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&envelope[8..24]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&envelope[24..48]);
    Ok((
        EnvelopeHeader {
            version,
            flags,
            tier,
            salt,
            nonce,
        },
        &envelope[HEADER_LEN..],
    ))
}

/// Derive the 32-byte symmetric key the same way the sealing path does
/// (Argon2id at `tier`, over `passphrase` and `salt`). Exposed so callers
/// who pre-parse the envelope can derive the key once and reuse it.
pub fn derive_key(passphrase: &[u8], salt: &[u8; 16], tier: MemoryTier) -> Result<[u8; 32]> {
    let params = tier.argon2_params(32);
    let key = origin_crypto_sdk::kdf::Argon2idBuilder::new()
        .memory_kib(params.m_cost())
        .iterations(params.t_cost())
        .parallelism(params.p_cost())
        .derive(passphrase, salt)
        .map_err(|e| SealError::Crypto(format!("Argon2id failed: {e:?}")))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key[..32]);
    Ok(arr)
}

// ---------------------------------------------------------------------------
// sign / verify (hybrid Ed25519 + Falcon-1024)
// ---------------------------------------------------------------------------

/// A hybrid signature over a message, keyed by the derivation domain.
#[derive(Debug, Clone)]
pub struct HybridSignature {
    /// 64-byte Ed25519 signature.
    pub ed25519: [u8; 64],
    /// Falcon-1024 signature bytes.
    pub falcon1024: Vec<u8>,
    /// Domain used for key derivation (must match at verify time).
    pub domain: String,
}

impl HybridSignature {
    /// Length-prefixed wire format: len(4 BE) ‖ ed25519(64) ‖ falcon(len).
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 64 + self.falcon1024.len());
        out.extend_from_slice(&(self.falcon1024.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&self.falcon1024);
        out
    }

    /// Parse from the length-prefixed wire format.
    pub fn from_wire(raw: &[u8]) -> Result<Self> {
        if raw.len() < 4 + 64 {
            return Err(SealError::Validation(format!(
                "signature wire too short ({} bytes); need >= 68",
                raw.len()
            )));
        }
        let falcon_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        let mut ed = [0u8; 64];
        ed.copy_from_slice(&raw[4..68]);
        if raw.len() != 68 + falcon_len {
            return Err(SealError::Validation(format!(
                "signature wire length mismatch: header says falcon={} but total={}",
                falcon_len,
                raw.len()
            )));
        }
        Ok(Self {
            ed25519: ed,
            falcon1024: raw[68..68 + falcon_len].to_vec(),
            domain: String::new(),
        })
    }
}

/// Sign `data` with a hybrid Ed25519 + Falcon-1024 key bundle derived from
/// `seed` and `domain`. Same seed + domain → same keys → verifiable.
pub fn sign(seed: &[u8; 32], domain: &str, data: &[u8]) -> Result<HybridSignature> {
    let bundle = HybridSigningKeyBundle::from_seed(seed, domain)
        .map_err(|e| SealError::KeyDerivation(format!("bundle derivation failed: {e:?}")))?;
    let sig = bundle.sign_hybrid(data);
    Ok(HybridSignature {
        ed25519: sig.ed25519_sig.to_bytes(),
        falcon1024: sig.falcon_sig.as_bytes().to_vec(),
        domain: domain.to_string(),
    })
}

/// Verify a hybrid signature. Returns `Ok(())` when both components verify,
/// or a `SealError::Verification` naming the failing component.
pub fn verify(seed: &[u8; 32], domain: &str, data: &[u8], sig: &HybridSignature) -> Result<()> {
    let bundle = HybridSigningKeyBundle::from_seed(seed, domain)
        .map_err(|e| SealError::KeyDerivation(format!("bundle derivation failed: {e:?}")))?;
    // Verify each component with the SDK's raw-byte APIs — no direct dalek
    // dependency (same pattern as the CLI's cmd_verify).
    let ed_ok = origin_crypto_sdk::signing::classical::Ed25519Signer::verify_with_pubkey(
        &bundle.ed25519_pk().to_bytes(),
        data,
        &sig.ed25519,
    );
    let falcon_ok =
        match origin_crypto_sdk::pqc::falcon1024::FalconSignature::from_bytes(&sig.falcon1024) {
            Ok(f) => {
                origin_crypto_sdk::pqc::falcon1024::verify(data, &f, bundle.falcon1024_pk()).is_ok()
            }
            Err(_) => false,
        };
    if ed_ok && falcon_ok {
        Ok(())
    } else {
        Err(SealError::Verification(
            "signature verification FAILED (ed25519 + falcon1024)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIER: MemoryTier = MemoryTier::Nano;

    #[test]
    fn hash_sha3_256_length() {
        let d = hash(HashKind::Sha3_256, b"data", None).unwrap();
        assert_eq!(d.len(), 32);
    }

    #[test]
    fn hash_blake3_length() {
        let d = hash(HashKind::Blake3, b"data", None).unwrap();
        assert_eq!(d.len(), 32);
    }

    #[test]
    fn hash_sha3_512_length() {
        let d = hash(HashKind::Sha3_512, b"data", None).unwrap();
        assert_eq!(d.len(), 64);
    }

    #[test]
    fn hmac_requires_key() {
        assert!(hash(HashKind::HmacSha3_256, b"data", None).is_err());
    }

    #[test]
    fn mac_roundtrip_length() {
        let m = mac(b"key", b"data").unwrap();
        assert_eq!(m.len(), 32);
    }

    #[test]
    fn kdf_deterministic() {
        let salt = [0x11u8; 16];
        let a = kdf(b"pw", &salt, TIER, 32).unwrap();
        let b = kdf(b"pw", &salt, TIER, 32).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn kdf_different_salt_differs() {
        let a = kdf(b"pw", &[1u8; 16], TIER, 32).unwrap();
        let b = kdf(b"pw", &[2u8; 16], TIER, 32).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let env = encrypt(b"secret payload", b"pw", TIER, false).unwrap();
        let pt = decrypt(&env, b"pw").unwrap();
        assert_eq!(pt, b"secret payload");
    }

    #[test]
    fn encrypt_decrypt_compressed_roundtrip() {
        let env = encrypt(b"aaaaaaa", b"pw", TIER, true).unwrap();
        let pt = decrypt(&env, b"pw").unwrap();
        assert_eq!(pt, b"aaaaaaa");
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let env = encrypt(b"secret", b"right", TIER, false).unwrap();
        assert!(decrypt(&env, b"wrong").is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut env = encrypt(b"secret", b"pw", TIER, false).unwrap();
        let last = env.len() - 1;
        env[last] ^= 0xff;
        assert!(decrypt(&env, b"pw").is_err());
    }

    #[test]
    fn envelope_magic_enforced() {
        let env = encrypt(b"secret", b"pw", TIER, false).unwrap();
        let mut bad = env.clone();
        bad[0] = b'X';
        assert!(decrypt(&bad, b"pw").is_err());
    }

    #[test]
    fn envelope_too_short_rejected() {
        assert!(decrypt(&[0u8; 10], b"pw").is_err());
    }

    #[test]
    fn envelope_header_parses_tier() {
        let env = encrypt(b"secret", b"pw", TIER, false).unwrap();
        let (header, payload) = parse_envelope(&env).unwrap();
        assert_eq!(header.tier, TIER);
        assert_eq!(header.flags, 0);
        assert!(!payload.is_empty());
    }

    #[test]
    fn signature_wire_roundtrip() {
        let seed = [0x42u8; 32];
        let sig = sign(&seed, "origin-seal:test", b"payload").unwrap();
        let wire = sig.to_wire();
        let back = HybridSignature::from_wire(&wire).unwrap();
        assert_eq!(back.ed25519, sig.ed25519);
        assert_eq!(back.falcon1024, sig.falcon1024);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let seed = [0x42u8; 32];
        let sig = sign(&seed, "origin-seal:test", b"payload").unwrap();
        assert!(verify(&seed, "origin-seal:test", b"payload", &sig).is_ok());
    }

    #[test]
    fn tampered_data_fails_verify() {
        let seed = [0x42u8; 32];
        let sig = sign(&seed, "origin-seal:test", b"payload").unwrap();
        assert!(verify(&seed, "origin-seal:test", b"tampered", &sig).is_err());
    }

    #[test]
    fn wrong_domain_fails_verify() {
        let seed = [0x42u8; 32];
        let sig = sign(&seed, "origin-seal:test", b"payload").unwrap();
        assert!(verify(&seed, "origin-seal:other", b"payload", &sig).is_err());
    }

    #[test]
    fn wrong_seed_fails_verify() {
        let sig = sign(&[1u8; 32], "origin-seal:test", b"payload").unwrap();
        assert!(verify(&[2u8; 32], "origin-seal:test", b"payload", &sig).is_err());
    }

    #[test]
    fn wire_too_short_rejected() {
        assert!(HybridSignature::from_wire(&[0u8; 10]).is_err());
    }

    #[test]
    fn wire_length_mismatch_rejected() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&100u32.to_be_bytes());
        wire.extend_from_slice(&[0u8; 64]);
        wire.extend_from_slice(&[0u8; 5]);
        assert!(HybridSignature::from_wire(&wire).is_err());
    }

    // SEAL v1 golden vector — FORMAT_REGISTRY.md priority 6. Fixed
    // (passphrase, salt, nonce, tier) make the envelope deterministic:
    // `derive_key` and XChaCha20-Poly1305 are pure functions of their
    // inputs. The pinned hex is the canonical v1 encoding; the parse +
    // decrypt half proves the fixture still round-trips.
    #[test]
    fn seal_envelope_golden_vector_v1() {
        let passphrase = b"golden seal passphrase";
        let salt = [0x11u8; 16];
        let nonce = [0x22u8; 24];
        let plaintext = b"origin seal golden vector";

        let key = derive_key(passphrase, &salt, TIER).expect("derive key");
        let ct = XChaCha20Poly1305::encrypt(&key, &nonce, plaintext).expect("encrypt");

        let mut blob = Vec::new();
        blob.extend_from_slice(MAGIC);
        blob.push(VERSION);
        blob.push(0); // flags: uncompressed, non-streamed
        blob.push(tier_to_byte(TIER));
        blob.push(0); // reserved
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);

        const EXPECTED: &str = "5345414c010000001111111111111111111111111111111122222222222222222222222222222222222222222222222219cd21e4fad504a5c1c59b6bf94c09347cd3a83e594b649578007eb2c857f3c0e0d5124d4de908db57";
        assert_eq!(hex::encode(&blob), EXPECTED);

        // The pinned fixture must parse and decrypt to the known plaintext.
        let pt = decrypt(&hex::decode(EXPECTED).expect("decode golden"), passphrase)
            .expect("decrypt golden vector");
        assert_eq!(pt, plaintext);
    }
}
