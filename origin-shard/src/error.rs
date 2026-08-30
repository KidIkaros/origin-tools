// SPDX-License-Identifier: Apache-2.0

//! error — the one error type the origin-shard library API speaks.

/// Convenience alias used across the crate.
pub type Result<T> = std::result::Result<T, ShardError>;

/// The typed error for origin-shard's library surface.
#[derive(Debug, thiserror::Error)]
pub enum ShardError {
    /// Shard configuration failed validation (zero shards, mismatched counts).
    #[error("invalid shard configuration: {0}")]
    InvalidConfig(String),

    /// Reed-Solomon encode/decode failed inside the SDK.
    #[error("reed-solomon: {0}")]
    Codec(String),

    /// Recovery is impossible: more shards missing than parity can cover.
    #[error("not enough shards: {0}")]
    NotEnoughShards(String),

    /// A shard file has an unexpected size.
    #[error("shard size mismatch: {0}")]
    ShardSize(String),

    /// Filesystem or stdio failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_variant_displays() {
        let variants = [
            ShardError::InvalidConfig("zero data shards".into()),
            ShardError::Codec("encode failed".into()),
            ShardError::NotEnoughShards("have 1, need 3".into()),
            ShardError::ShardSize("shard 2 wrong size".into()),
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty(), "variant must render: {v:?}");
        }
    }

    #[test]
    fn io_error_converts() {
        let src = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err: ShardError = src.into();
        assert!(matches!(err, ShardError::Io(_)));
    }
}
