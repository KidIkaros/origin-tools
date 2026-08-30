// SPDX-License-Identifier: Apache-2.0

//! Error types for the origin-wallet crate.

use thiserror::Error;

/// Unified error type for wallet operations.
#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Insufficient entropy: required {required:.2}, got {actual:.2}")]
    InsufficientEntropy { required: f64, actual: f64 },

    #[error("Seed handle expired")]
    SeedExpired,

    #[error("Invalid passphrase")]
    InvalidPassphrase,

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Stoa network error: {0}")]
    Network(String),

    #[error("Backup error: {0}")]
    Backup(String),

    #[error("Recovery error: {0}")]
    Recovery(String),
}

/// Result type for wallet operations.
pub type Result<T> = std::result::Result<T, WalletError>;

impl From<origin_crypto_sdk::error::CryptoError> for WalletError {
    fn from(err: origin_crypto_sdk::error::CryptoError) -> Self {
        WalletError::Crypto(err.to_string())
    }
}

impl From<bincode::Error> for WalletError {
    fn from(err: bincode::Error) -> Self {
        WalletError::Serialization(err.to_string())
    }
}
