//! Extension methods for MemoryTier.
//!
//! The SDK's `MemoryTier` enum doesn't have serialization or byte conversion.
//! These helpers add those capabilities for the origin-tools envelope format.

use origin_crypto_sdk::tier::MemoryTier;

/// Convert a MemoryTier to a single byte for envelope storage.
pub fn tier_to_byte(t: MemoryTier) -> u8 {
    match t {
        MemoryTier::Nano => 0,
        MemoryTier::Standard => 1,
        MemoryTier::Sovereign => 2,
    }
}

/// Convert a byte back to MemoryTier.
pub fn tier_from_byte(b: u8) -> Result<MemoryTier, String> {
    match b {
        0 => Ok(MemoryTier::Nano),
        1 => Ok(MemoryTier::Standard),
        2 => Ok(MemoryTier::Sovereign),
        _ => Err(format!("unknown tier byte {b}")),
    }
}

/// Parse a MemoryTier from a string (case-insensitive).
pub fn tier_from_str(s: &str) -> Result<MemoryTier, String> {
    match s.to_lowercase().as_str() {
        "nano" => Ok(MemoryTier::Nano),
        "standard" | "std" => Ok(MemoryTier::Standard),
        "sovereign" | "sov" => Ok(MemoryTier::Sovereign),
        _ => Err(format!("unknown tier '{s}' (expected: nano, standard, sovereign)")),
    }
}
