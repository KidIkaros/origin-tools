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

/// Maximum payload size: 1 GiB. Prevents memory exhaustion from oversized inputs.
pub const MAX_PAYLOAD_LEN: usize = 1024 * 1024 * 1024;

/// Flag bits supported by the current ORGN v1 implementation.
pub const FLAG_COMPRESSED: u8 = 0x01;
const SUPPORTED_FLAGS: u8 = FLAG_COMPRESSED;

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
        crate::random_bytes(&mut salt)?;
        crate::random_bytes(&mut nonce)?;

        let payload_data = if compress {
            origin_crypto_sdk::compression::compress(plaintext)
                .map_err(|e| format!("compression failed: {e}"))?
        } else {
            plaintext.to_vec()
        };

        let flags = if compress { FLAG_COMPRESSED } else { 0 };

        // AAD: authenticate the header fields so they can't be tampered with
        let aad = Self::compute_aad(VERSION, payload_type, flags, tier, &salt, &nonce);

        let ciphertext = XChaCha20Poly1305::encrypt_aad(key, &nonce, &payload_data, &aad)
            .map_err(|e| format!("encryption failed: {e}"))?;

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
        // Reconstruct AAD from header to verify integrity
        let aad = Self::compute_aad(
            self.header.version,
            self.header.payload_type,
            self.header.flags,
            self.header.tier,
            &self.header.salt,
            &self.header.nonce,
        );

        let plaintext =
            XChaCha20Poly1305::decrypt_aad(key, &self.header.nonce, &self.payload, &aad)
                .map_err(|_| "decryption failed (wrong key or corrupt data)")?;

        if self.header.flags & FLAG_COMPRESSED != 0 {
            origin_crypto_sdk::compression::decompress(&plaintext)
                .map_err(|e| format!("decompression failed: {e}"))
        } else {
            Ok(plaintext)
        }
    }

    /// Compute the AAD for header authentication.
    fn compute_aad(
        version: u8,
        payload_type: PayloadType,
        flags: u8,
        tier: MemoryTier,
        salt: &[u8; 16],
        nonce: &[u8; 24],
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(48);
        aad.extend_from_slice(MAGIC);
        aad.push(version);
        aad.push(payload_type.to_byte());
        aad.push(flags);
        aad.push(tier_to_byte(tier));
        aad.extend_from_slice(salt);
        aad.extend_from_slice(nonce);
        aad
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
        if flags & !SUPPORTED_FLAGS != 0 {
            return Err(format!("unsupported envelope flags: 0x{flags:02x}"));
        }
        let tier = tier_from_byte(bytes[7])?;

        let salt: [u8; 16] = bytes[8..24]
            .try_into()
            .map_err(|_| "internal: salt slice has wrong length".to_string())?;
        let nonce: [u8; 24] = bytes[24..48]
            .try_into()
            .map_err(|_| "internal: nonce slice has wrong length".to_string())?;
        let payload = bytes[48..].to_vec();

        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(format!(
                "envelope payload too large ({} bytes, max {MAX_PAYLOAD_LEN})",
                payload.len()
            ));
        }

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
