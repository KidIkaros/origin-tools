//! Error types for origin-attest.

use thiserror::Error;

/// Errors that can occur during attestation operations.
#[derive(Debug, Error)]
pub enum AttestError {
    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Endorsement is invalid (bad signature, expired, wrong domain).
    #[error("invalid endorsement: {0}")]
    InvalidEndorsement(String),

    /// Hash chain is broken (prev_hash mismatch).
    #[error("chain broken at index {0}")]
    ChainBroken(usize),

    /// Claim or endorsement has expired.
    #[error("expired: {0}")]
    Expired(String),

    /// Claim or endorsement has been revoked.
    #[error("revoked: {0}")]
    Revoked(String),

    /// Serialization/deserialization failure.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Discovery operation failed.
    #[error("discovery error: {0}")]
    Discovery(String),

    /// Threshold not met (e.g. not enough endorsements).
    #[error("threshold not met: {0}")]
    Threshold(String),

    /// Invalid parameter.
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    /// Agent/record not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Audit chain integrity failure.
    #[error("audit chain broken at entry {0}")]
    AuditBroken(usize),
}

/// Convenience result type.
pub type Result<T> = std::result::Result<T, AttestError>;
