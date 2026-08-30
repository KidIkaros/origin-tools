// SPDX-License-Identifier: Apache-2.0

//! error — the one error type the origin-seal library API speaks.

/// Convenience alias used across the crate.
pub type Result<T> = std::result::Result<T, SealError>;

/// The typed error for origin-seal's library surface. Callers can match on
/// *what kind of thing failed* instead of parsing strings.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The input is not a valid sealed envelope (bad magic, too short,
    /// unsupported version/flags, or oversized).
    #[error("envelope: {0}")]
    Envelope(String),

    /// Decryption or signature verification failed (wrong key, tampered data).
    #[error("verification failed: {0}")]
    Verification(String),

    /// A cryptographic primitive failed (Argon2id, HKDF, random, compression).
    #[error("crypto: {0}")]
    Crypto(String),

    /// A signing key bundle could not be derived from the seed.
    #[error("key derivation: {0}")]
    KeyDerivation(String),

    /// A supplied parameter failed validation (tier, chunk size, key length).
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
            SealError::Envelope("short".into()),
            SealError::Verification("tampered".into()),
            SealError::Crypto("argon2".into()),
            SealError::KeyDerivation("bundle".into()),
            SealError::Validation("tier".into()),
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty(), "variant must render: {v:?}");
        }
    }

    #[test]
    fn io_error_converts() {
        let src = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err: SealError = src.into();
        assert!(matches!(err, SealError::Io(_)));
    }
}
