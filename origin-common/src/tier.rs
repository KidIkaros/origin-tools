//! Memory tiers for Argon2id key derivation.
//!
//! Three tiers: Nano (fast, low memory), Standard (balanced), Sovereign (paranoid).

use origin_crypto_sdk::kdf::Argon2idBuilder;
use serde::{Deserialize, Serialize};

/// Argon2id memory/computation tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryTier {
    /// Fast, low memory (~64 MiB). For testing or low-resource environments.
    Nano,
    /// Balanced (~512 MiB). Default for most use cases.
    Standard,
    /// Paranoid (~2 GiB). For high-security contexts.
    Sovereign,
}

impl MemoryTier {
    /// Convert to the byte encoding used in envelopes.
    pub fn to_byte(self) -> u8 {
        match self {
            MemoryTier::Nano => 1,
            MemoryTier::Standard => 2,
            MemoryTier::Sovereign => 3,
        }
    }

    /// Parse from the byte encoding used in envelopes.
    pub fn from_byte(b: u8) -> Result<Self, String> {
        match b {
            1 => Ok(MemoryTier::Nano),
            2 => Ok(MemoryTier::Standard),
            3 => Ok(MemoryTier::Sovereign),
            _ => Err(format!("unknown tier byte: {b}")),
        }
    }

    /// Parse from a string (case-insensitive).
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "nano" => Ok(MemoryTier::Nano),
            "standard" => Ok(MemoryTier::Standard),
            "sovereign" => Ok(MemoryTier::Sovereign),
            _ => Err(format!("unknown tier: {s}")),
        }
    }

    /// Build an Argon2id instance with this tier's parameters.
    pub fn argon2_builder(self) -> Argon2idBuilder {
        match self {
            MemoryTier::Nano => Argon2idBuilder::new()
                .memory_kib(65536)
                .iterations(2)
                .parallelism(1),
            MemoryTier::Standard => Argon2idBuilder::new()
                .memory_kib(524288)
                .iterations(3)
                .parallelism(4),
            MemoryTier::Sovereign => Argon2idBuilder::new()
                .memory_kib(2097152)
                .iterations(4)
                .parallelism(8),
        }
    }
}

impl std::fmt::Display for MemoryTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryTier::Nano => write!(f, "nano"),
            MemoryTier::Standard => write!(f, "standard"),
            MemoryTier::Sovereign => write!(f, "sovereign"),
        }
    }
}
