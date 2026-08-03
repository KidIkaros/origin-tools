//! Shared adapters for the SDK-owned `MemoryTier`.
//!
//! The SDK remains authoritative for tier values and Argon2 parameters. This
//! module only supplies tool-suite serialization and builder ergonomics.

use origin_crypto_sdk::{kdf::Argon2idBuilder, tier::MemoryTier};
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize the SDK tier using the legacy origin-tools JSON representation.
pub mod serde_compat {
    use super::{Deserialize, Deserializer, MemoryTier, Serializer};

    pub fn serialize<S>(tier: &MemoryTier, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match tier {
            MemoryTier::Nano => "Nano",
            MemoryTier::Standard => "Standard",
            MemoryTier::Sovereign => "Sovereign",
        })
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<MemoryTier, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.to_ascii_lowercase().as_str() {
            "nano" => Ok(MemoryTier::Nano),
            "standard" | "std" => Ok(MemoryTier::Standard),
            "sovereign" | "sov" => Ok(MemoryTier::Sovereign),
            other => Err(serde::de::Error::custom(format!(
                "unknown memory tier '{other}'"
            ))),
        }
    }
}

/// Build the SDK Argon2id builder for a suite memory tier.
pub fn argon2_builder(tier: MemoryTier, output_len: usize) -> Argon2idBuilder {
    let params = tier.argon2_params(output_len);
    Argon2idBuilder::new()
        .memory_kib(params.m_cost())
        .iterations(params.t_cost())
        .parallelism(params.p_cost())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct TierRecord {
        #[serde(with = "serde_compat")]
        tier: MemoryTier,
    }

    #[test]
    fn legacy_json_tier_values_round_trip() {
        let record = TierRecord {
            tier: MemoryTier::Standard,
        };
        assert_eq!(
            serde_json::to_string(&record).unwrap(),
            r#"{"tier":"Standard"}"#
        );
        assert_eq!(
            serde_json::from_str::<TierRecord>(r#"{"tier":"standard"}"#).unwrap(),
            record
        );
    }

    #[test]
    fn tier_aliases_are_accepted() {
        for (value, expected) in [
            ("nano", MemoryTier::Nano),
            ("std", MemoryTier::Standard),
            ("sov", MemoryTier::Sovereign),
        ] {
            let json = format!(r#"{{"tier":"{value}"}}"#);
            assert_eq!(
                serde_json::from_str::<TierRecord>(&json).unwrap().tier,
                expected
            );
        }
    }

    #[test]
    fn argon2_builder_uses_sdk_tier_parameters() {
        let params = argon2_builder(MemoryTier::Sovereign, 32)
            .derive(b"passphrase", &[7u8; 16])
            .unwrap();
        assert_eq!(params.len(), 32);
    }
}
