//! Envelope — unified binary format for encrypted/signed data.
//!
//! All tools in the suite speak this format. Replaces the legacy "OVLT" and "SEAL" formats.
//!
//! Format:
//!   offset  size  field
//!   0       4     magic "ORGN"
//!   4       1     version (1)
//!   5       1     payload_type (0x01=vault, 0x02=file, 0x03=signed)
//!   6       1     flags (bit0=compressed, bit1=streamed, bit2=dual_signed)
//!   7       1     tier
//!   8       16    salt
//!   24      24    nonce (base nonce if streamed)
//!   48      ...   payload (ciphertext or signed data)
//!
//! For streamed payloads, the payload section is length-framed chunks + sentinel.

use origin_crypto_sdk::aead::XChaCha20Poly1305;
use origin_crypto_sdk::tier::MemoryTier;
use serde::{Deserialize, Serialize};

use crate::tier_ext::{tier_from_byte, tier_to_byte};

/// Magic bytes identifying an ORGN envelope.
pub const MAGIC: &[u8; 4] = b"ORGN";

/// Current envelope version.
pub const VERSION: u8 = 1;

/// Header length: magic(4) + version(1) + payload_type(1) + flags(1) + tier(1) + salt(16) + nonce(24).
pub const HEADER_LEN: usize = 48;

/// Flag bits.
pub const FLAG_COMPRESSED: u8 = 0x01;
pub const FLAG_STREAMED: u8 = 0x02;
pub const FLAG_DUAL_SIGNED: u8 = 0x04;

/// Payload type — what's inside the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PayloadType {
    /// origin-pass vault entry.
    Vault = 0x01,
    /// origin-seal encrypted file.
    File = 0x02,
    /// Signed blob (origin-seal or origin-identity).
    Signed = 0x03,
    /// Seed blob (origin-seed).
    Seed = 0x04,
    /// Shard (origin-shard).
    Shard = 0x05,
    /// MMR proof (origin-proof).
    Proof = 0x06,
}

impl PayloadType {
    pub fn from_byte(b: u8) -> Result<Self, String> {
        match b {
            0x01 => Ok(PayloadType::Vault),
            0x02 => Ok(PayloadType::File),
            0x03 => Ok(PayloadType::Signed),
            0x04 => Ok(PayloadType::Seed),
            0x05 => Ok(PayloadType::Shard),
            0x06 => Ok(PayloadType::Proof),
            _ => Err(format!("unknown payload type: {b}")),
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Envelope type — encrypt or sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeType {
    Encrypted,
    Signed,
}

/// A parsed envelope header.
#[derive(Debug, Clone)]
pub struct EnvelopeHeader {
    pub version: u8,
    pub payload_type: PayloadType,
    pub flags: u8,
    pub tier: MemoryTier,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
}

/// An envelope — header + payload.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub header: EnvelopeHeader,
    pub payload: Vec<u8>,
}

impl Envelope {
    /// Create a new encrypted envelope.
    pub fn encrypt(
        plaintext: &[u8],
        key: &[u8; 32],
        tier: MemoryTier,
        payload_type: PayloadType,
        compress: bool,
    ) -> Result<Self, String> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let payload_data = if compress {
            origin_crypto_sdk::compression::compress(plaintext)
                .map_err(|e| format!("compression failed: {e}"))?
        } else {
            plaintext.to_vec()
        };

        let ciphertext = XChaCha20Poly1305::encrypt(key, &nonce, &payload_data)
            .map_err(|e| format!("encryption failed: {e}"))?;

        let flags = if compress { FLAG_COMPRESSED } else { 0 };

        Ok(Self {
            header: EnvelopeHeader {
                version: VERSION,
                payload_type,
                flags,
                tier,
                salt,
                nonce,
            },
            payload: ciphertext,
        })
    }

    /// Decrypt the envelope payload.
    pub fn decrypt(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let plaintext = XChaCha20Poly1305::decrypt(key, &self.header.nonce, &self.payload)
            .map_err(|_| "decryption failed (wrong key or corrupt data)")?;

        if self.header.flags & FLAG_COMPRESSED != 0 {
            origin_crypto_sdk::compression::decompress(&plaintext)
                .map_err(|e| format!("decompression failed: {e}"))
        } else {
            Ok(plaintext)
        }
    }

    /// Serialize the envelope to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(MAGIC);
        out.push(self.header.version);
        out.push(self.header.payload_type.to_byte());
        out.push(self.header.flags);
        out.push(tier_to_byte(self.header.tier));
        out.extend_from_slice(&self.header.salt);
        out.extend_from_slice(&self.header.nonce);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse an envelope from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_LEN {
            return Err(format!(
                "envelope too short ({} bytes, need at least {HEADER_LEN})",
                bytes.len()
            ));
        }

        if &bytes[..4] != MAGIC {
            return Err("not an ORGN envelope (wrong magic)".to_string());
        }

        let version = bytes[4];
        if version != VERSION {
            return Err(format!("unsupported envelope version: {version}"));
        }

        let payload_type = PayloadType::from_byte(bytes[5])?;
        let flags = bytes[6];
        let tier = tier_from_byte(bytes[7])?;

        let salt: [u8; 16] = bytes[8..24].try_into().unwrap();
        let nonce: [u8; 24] = bytes[24..48].try_into().unwrap();
        let payload = bytes[48..].to_vec();

        Ok(Self {
            header: EnvelopeHeader {
                version,
                payload_type,
                flags,
                tier,
                salt,
                nonce,
            },
            payload,
        })
    }
}
