// SPDX-License-Identifier: Apache-2.0

//! error — the one error type the origin-seed library API speaks.

/// Convenience alias used across the crate.
pub type Result<T> = std::result::Result<T, SeedError>;

/// The typed error for origin-seed's library surface.
#[derive(Debug, thiserror::Error)]
pub enum SeedError {
    /// A seed is not 32 bytes, or is not valid hex.
    #[error("invalid seed: {0}")]
    InvalidSeed(String),

    /// Child-seed derivation failed (rejected by the SDK, e.g. empty domain).
    #[error("derivation: {0}")]
    Derivation(String),

    /// Blob encryption or decryption failed (wrong passphrase, corrupt data).
    #[error("blob: {0}")]
    Blob(String),

    /// A supplied parameter failed validation (tier, format, domain).
    #[error("invalid argument: {0}")]
    Validation(String),

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
            SeedError::InvalidSeed("short".into()),
            SeedError::Derivation("rejected".into()),
            SeedError::Blob("wrong passphrase".into()),
            SeedError::Validation("tier".into()),
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty(), "variant must render: {v:?}");
        }
    }

    #[test]
    fn io_error_converts() {
        let src = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err: SeedError = src.into();
        assert!(matches!(err, SeedError::Io(_)));
    }
}
