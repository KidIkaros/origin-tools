// SPDX-License-Identifier: Apache-2.0

//! Error types for origin-network (spec §6.4 taxonomy).

use thiserror::Error;

/// Result alias for origin-network operations.
pub type Result<T> = std::result::Result<T, NetworkError>;

/// Network-layer error taxonomy.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum NetworkError {
    /// Address parsing or formatting failure.
    #[error("address: {0}")]
    Address(String),

    /// Underlying transport failure (connect, bind, IO).
    #[error("transport: {0}")]
    Transport(String),

    /// Noise handshake failure.
    #[error("handshake: {0}")]
    Handshake(String),

    /// AUTH claim verification failure.
    #[error("auth: {0}")]
    Auth(String),

    /// Rate limit exceeded.
    #[error("rate limited: {0}")]
    RateLimited(String),

    /// Peer is in the eviction set.
    #[error("evicted: {0}")]
    Evicted(String),

    /// Relay at capacity.
    #[error("relay full: {0}")]
    RelayFull(String),

    /// Target peer is not registered / offline.
    #[error("target offline: {0}")]
    TargetOffline(String),

    /// Operation timed out.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Frame codec failure.
    #[error("codec: {0}")]
    Codec(String),

    /// Peer not authorized for the requested service.
    #[error("service denied: {0}")]
    ServiceDenied(String),

    /// Channel-layer error surfaced through the network.
    #[error("channel: {0}")]
    Channel(String),

    /// Cryptographic primitive failure (SDK).
    #[error("crypto: {0}")]
    Crypto(String),
}

impl From<origin_channel::ChannelError> for NetworkError {
    fn from(e: origin_channel::ChannelError) -> Self {
        NetworkError::Channel(e.to_string())
    }
}

impl From<origin_crypto_sdk::CryptoError> for NetworkError {
    fn from(e: origin_crypto_sdk::CryptoError) -> Self {
        NetworkError::Crypto(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_shapes() {
        assert_eq!(
            NetworkError::Evicted("abcd".into()).to_string(),
            "evicted: abcd"
        );
        assert_eq!(
            NetworkError::RelayFull("1000".into()).to_string(),
            "relay full: 1000"
        );
    }

    #[test]
    fn channel_error_converts() {
        let e = origin_channel::ChannelError::Codec("bad frame".into());
        let n: NetworkError = e.into();
        assert!(matches!(n, NetworkError::Channel(_)));
    }

    #[test]
    fn crypto_error_converts() {
        let e = origin_crypto_sdk::CryptoError::InvalidKeyLength {
            algorithm: "X25519",
            expected: 32,
            got: 4,
        };
        let n: NetworkError = e.into();
        assert!(matches!(n, NetworkError::Crypto(_)));
    }
}
