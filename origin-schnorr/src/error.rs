// SPDX-License-Identifier: Apache-2.0

//! error — the one error type the origin-schnorr library API speaks.

/// Convenience alias used across the crate.
pub type Result<T> = std::result::Result<T, SchnorrError>;

/// The typed error for origin-schnorr's library surface.
#[derive(Debug, thiserror::Error)]
pub enum SchnorrError {
    /// A key or seed is not 32 bytes, or is not valid hex.
    #[error("invalid key material: {0}")]
    InvalidKey(String),

    /// Proof generation failed inside the SDK.
    #[error("proof generation failed: {0}")]
    Proof(String),

    /// Proof verification returned an error (as opposed to `false`).
    #[error("verification error: {0}")]
    Verification(String),

    /// A supplied parameter failed validation.
    #[error("invalid parameter: {0}")]
    Validation(String),
}
