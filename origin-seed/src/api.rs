// SPDX-License-Identifier: Apache-2.0

//! api — the typed library surface for origin-seed.
//!
//! Seed lifecycle as plain function calls: generate, derive (domain-
//! separated children), hex encode/decode, and passphrase-encrypted blob
//! seal/recover. The CLI (`commands.rs`) is a thin shell over this.
//!
//! Design rules (see ARCHITECTURE.md):
//! - One crypto provider: derivation and blob sealing go through
//!   `origin-crypto-sdk` — nothing is re-implemented here.
//! - Errors are typed (`SeedError`), never `String`.

use origin_common::{random_bytes, tier_from_str, MemoryTier};
use origin_crypto_sdk::blob::{create_blob, recover_seed};

use crate::error::{Result, SeedError};

/// Generate a fresh random 32-byte seed from the SDK CSPRNG.
pub fn generate() -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    random_bytes(&mut seed).map_err(|e| SeedError::Io(std::io::Error::other(e)))?;
    Ok(seed)
}

/// Parse a 32-byte seed from hex (rejects invalid hex and wrong lengths).
pub fn from_hex(hex_seed: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_seed.trim())
        .map_err(|e| SeedError::InvalidSeed(format!("invalid hex seed: {e}")))?;
    if bytes.len() != 32 {
        return Err(SeedError::InvalidSeed(format!(
            "seed must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Derive a deterministic child seed from a parent seed with domain
/// separation. Same parent + domain → same child; different domains →
/// unrelated children.
pub fn derive(parent_seed: &[u8; 32], domain: &str) -> Result<[u8; 32]> {
    let child = origin_crypto_sdk::derive_child_seed(parent_seed, domain)
        .map_err(|e| SeedError::Derivation(format!("{e}")))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&child);
    Ok(arr)
}

/// Hex-encode a seed (the suite's default interchange format).
pub fn to_hex(seed: &[u8; 32]) -> String {
    hex::encode(seed)
}

/// Seal a seed into a passphrase-protected blob (Argon2id at `tier`).
pub fn seal_blob(seed: &[u8; 32], passphrase: &[u8], tier: MemoryTier) -> Result<Vec<u8>> {
    create_blob(passphrase, tier, Some(seed))
        .map_err(|e| SeedError::Blob(format!("blob creation failed: {e:?}")))
}

/// Recover a seed from a passphrase-protected blob.
pub fn recover_blob(blob: &[u8], passphrase: &[u8], tier: MemoryTier) -> Result<[u8; 32]> {
    recover_seed(blob, passphrase, tier)
        .map_err(|_| SeedError::Blob("blob decryption failed (wrong passphrase or corrupt)".into()))
}

/// Parse a memory tier from its string form ("nano" | "standard" | "sovereign").
pub fn parse_tier(s: &str) -> Result<MemoryTier> {
    tier_from_str(s).map_err(|e| SeedError::Validation(format!("invalid tier: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_32_distinct_bytes() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_ne!(a, b, "two random seeds must differ");
    }

    #[test]
    fn from_hex_roundtrip() {
        let seed = [0x42u8; 32];
        assert_eq!(from_hex(&to_hex(&seed)).unwrap(), seed);
    }

    #[test]
    fn from_hex_rejects_bad_hex() {
        assert!(from_hex("not-hex").is_err());
        assert!(from_hex("0x42").is_err());
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        let short = hex::encode([0u8; 16]);
        let err = from_hex(&short).unwrap_err();
        assert!(matches!(err, SeedError::InvalidSeed(_)));
    }

    #[test]
    fn derive_is_deterministic() {
        let parent = [0x42u8; 32];
        assert_eq!(
            derive(&parent, "app:wallet:1").unwrap(),
            derive(&parent, "app:wallet:1").unwrap()
        );
    }

    #[test]
    fn derive_domains_differ() {
        let parent = [0x42u8; 32];
        assert_ne!(
            derive(&parent, "app:wallet:1").unwrap(),
            derive(&parent, "app:wallet:2").unwrap()
        );
    }

    #[test]
    fn derive_rejects_empty_domain() {
        let parent = [0x42u8; 32];
        assert!(derive(&parent, "").is_err());
    }

    #[test]
    fn blob_roundtrip() {
        let seed = [0x42u8; 32];
        let blob = seal_blob(&seed, b"pass", MemoryTier::Standard).unwrap();
        assert_eq!(recover_blob(&blob, b"pass", MemoryTier::Standard).unwrap(), seed);
    }

    #[test]
    fn blob_wrong_passphrase_fails() {
        let seed = [0x42u8; 32];
        let blob = seal_blob(&seed, b"right", MemoryTier::Standard).unwrap();
        let err = recover_blob(&blob, b"wrong", MemoryTier::Standard).unwrap_err();
        assert!(matches!(err, SeedError::Blob(_)));
    }

    #[test]
    fn blob_corrupt_data_fails() {
        let seed = [0x42u8; 32];
        let mut blob = seal_blob(&seed, b"pass", MemoryTier::Standard).unwrap();
        let mid = blob.len() / 2;
        blob[mid] ^= 0xFF;
        assert!(recover_blob(&blob, b"pass", MemoryTier::Standard).is_err());
    }

    #[test]
    fn parse_tier_variants() {
        assert_eq!(parse_tier("nano").unwrap(), MemoryTier::Nano);
        assert!(parse_tier("bogus").is_err());
    }
}
