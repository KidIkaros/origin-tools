// SPDX-License-Identifier: Apache-2.0

//! error — the one error type the origin-entropy library API speaks.

/// Convenience alias used across the crate.
pub type Result<T> = std::result::Result<T, EntropyError>;

/// The typed error for origin-entropy's library surface.
#[derive(Debug, thiserror::Error)]
pub enum EntropyError {
    /// A supplied parameter failed validation (e.g. bits = 0).
    #[error("invalid parameter: {0}")]
    Validation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_variant_displays() {
        let err = EntropyError::Validation("bits must be >= 1".into());
        assert!(!err.to_string().is_empty());
    }
}
