//! Vault data structures and operations

use origin_crypto_sdk::kdf::Argon2idBuilder;
use serde::{Deserialize, Serialize};

/// Argon2id memory tier for vault KDF cost.
///
/// This is a local, serde-enabled mirror of
/// `origin_crypto_sdk::primitives::tier::MemoryTier`. The SDK owns the
/// authoritative definition; we convert to it for KDF parameter selection
/// via [`MemoryTier::to_sdk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryTier {
    /// 8 MB — IoT / edge / RPi Zero
    Nano,
    /// 64 MB — mid-tier laptop / server
    Standard,
    /// 256 MB — datacenter / high-security
    Sovereign,
}

impl MemoryTier {
    pub fn parse_tier(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "nano" => Ok(MemoryTier::Nano),
            "standard" => Ok(MemoryTier::Standard),
            "sovereign" => Ok(MemoryTier::Sovereign),
            _ => Err(format!("Invalid tier: {}", s)),
        }
    }

    /// Build a tier-aware Argon2id KDF builder from the SDK.
    pub fn argon2_builder(self) -> Argon2idBuilder {
        match self {
            MemoryTier::Nano => Argon2idBuilder::new()
                .memory_kib(8 * 1024)
                .iterations(2)
                .parallelism(1),
            MemoryTier::Standard => Argon2idBuilder::new()
                .memory_kib(64 * 1024)
                .iterations(3)
                .parallelism(2),
            MemoryTier::Sovereign => Argon2idBuilder::new()
                .memory_kib(256 * 1024)
                .iterations(5)
                .parallelism(4),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            MemoryTier::Nano => "nano",
            MemoryTier::Standard => "standard",
            MemoryTier::Sovereign => "sovereign",
        }
    }
}

impl std::fmt::Display for MemoryTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Vault metadata structure stored on disk
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Vault {
    pub version: u8,
    pub created_at: String,
    pub tier: MemoryTier,
    pub fingerprint: String,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_memory_tier_parse() {
        assert_eq!(MemoryTier::parse_tier("nano").unwrap(), MemoryTier::Nano);
        assert_eq!(
            MemoryTier::parse_tier("standard").unwrap(),
            MemoryTier::Standard
        );
        assert_eq!(
            MemoryTier::parse_tier("sovereign").unwrap(),
            MemoryTier::Sovereign
        );
        assert!(MemoryTier::parse_tier("invalid").is_err());
    }

    #[test]
    fn test_memory_tier_display() {
        assert_eq!(MemoryTier::Nano.to_string(), "nano");
        assert_eq!(MemoryTier::Standard.to_string(), "standard");
        assert_eq!(MemoryTier::Sovereign.to_string(), "sovereign");
    }

    #[test]
    fn test_memory_tier_label() {
        assert_eq!(MemoryTier::Nano.label(), "nano");
        assert_eq!(MemoryTier::Standard.label(), "standard");
        assert_eq!(MemoryTier::Sovereign.label(), "sovereign");
    }

    #[test]
    fn test_vault_serialization_roundtrip() {
        let vault = Vault {
            version: 1,
            created_at: "2026-07-30T21:27:45Z".to_string(),
            tier: MemoryTier::Standard,
            fingerprint: "3af4c01e".to_string(),
            salt: [1u8; 16],
            nonce: [2u8; 24],
            ciphertext: vec![3, 4, 5],
        };

        let serialized = serde_json::to_string(&vault).unwrap();
        let deserialized: Vault = serde_json::from_str(&serialized).unwrap();

        assert_eq!(vault.version, deserialized.version);
        assert_eq!(vault.tier, deserialized.tier);
        assert_eq!(vault.fingerprint, deserialized.fingerprint);
    }

    #[test]
    fn test_vault_write_and_read() {
        let vault = Vault {
            version: 1,
            created_at: "2026-07-30T21:27:45Z".to_string(),
            tier: MemoryTier::Standard,
            fingerprint: "3af4c01e".to_string(),
            salt: [1u8; 16],
            nonce: [2u8; 24],
            ciphertext: vec![3, 4, 5],
        };

        let temp_file = NamedTempFile::new().unwrap();
        let vault_path = temp_file.path();

        let serialized = serde_json::to_string(&vault).unwrap();
        std::fs::write(vault_path, serialized).unwrap();

        let read_data = std::fs::read_to_string(vault_path).unwrap();
        let read_vault: Vault = serde_json::from_str(&read_data).unwrap();

        assert_eq!(vault.version, read_vault.version);
        assert_eq!(vault.tier, read_vault.tier);
        assert_eq!(vault.fingerprint, read_vault.fingerprint);
    }

    #[test]
    fn test_vault_file_not_found() {
        let vault_path = "/tmp/nonexistent_vault_file_12345.json";
        let result = std::fs::read_to_string(vault_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_with_all_tiers() {
        for tier in [
            MemoryTier::Nano,
            MemoryTier::Standard,
            MemoryTier::Sovereign,
        ] {
            let vault = Vault {
                version: 1,
                created_at: "2026-07-30T21:27:45Z".to_string(),
                tier,
                fingerprint: "abc123".to_string(),
                salt: [1u8; 16],
                nonce: [2u8; 24],
                ciphertext: vec![1, 2, 3, 4],
            };

            let serialized = serde_json::to_string(&vault).unwrap();
            let deserialized: Vault = serde_json::from_str(&serialized).unwrap();

            assert_eq!(vault.tier, deserialized.tier);
        }
    }

    #[test]
    fn test_vault_with_empty_ciphertext() {
        let vault = Vault {
            version: 1,
            created_at: "2026-07-30T21:27:45Z".to_string(),
            tier: MemoryTier::Standard,
            fingerprint: "empty".to_string(),
            salt: [0u8; 16],
            nonce: [0u8; 24],
            ciphertext: vec![],
        };

        let serialized = serde_json::to_string(&vault).unwrap();
        let deserialized: Vault = serde_json::from_str(&serialized).unwrap();

        assert_eq!(vault.ciphertext, deserialized.ciphertext);
    }
}
