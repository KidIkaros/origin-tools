//! Error types for Origin Secrets

use std::path::PathBuf;
use thiserror::Error;

/// Origin Secrets error types
#[derive(Error, Debug)]
pub enum Error {
    // Vault errors
    #[error("Vault not found: {0}")]
    VaultNotFound(PathBuf),

    #[error("Vault already exists: {0}")]
    VaultAlreadyExists(PathBuf),

    #[error("Vault corrupted: {0}")]
    VaultCorrupted(String),

    #[error("Vault decryption failed: {0}")]
    VaultDecryptionFailed(String),

    #[error("Vault encryption failed: {0}")]
    VaultEncryptionFailed(String),

    // Key errors
    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },

    #[error("Key already exists: {key_id}")]
    KeyAlreadyExists { key_id: String },

    // Share errors
    #[error("Share not found: {share_number}")]
    ShareNotFound { share_number: u8 },

    #[error("Insufficient shares: need {needed}, got {provided}")]
    InsufficientShares { needed: u8, provided: u8 },

    #[error("Share verification failed: {share_number} - {details}")]
    ShareVerificationFailed { share_number: u8, details: String },

    #[error("Share corrupted: {share_number}")]
    ShareCorrupted { share_number: u8 },

    // Threshold errors
    #[error("Invalid threshold: threshold {threshold} > total shares {total_shares}")]
    InvalidThreshold { threshold: u8, total_shares: u8 },

    // Signature errors
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Signature generation failed: {0}")]
    SignatureGenerationFailed(String),

    // Compliance errors
    #[error("Compliance export failed: {framework} - {details}")]
    ComplianceExportFailed { framework: String, details: String },

    #[error("Audit log not found")]
    AuditLogNotFound,

    // I/O errors
    #[error("I/O error: {0}")]
    IoError(String),

    // Crypto errors
    #[error("Crypto error: {0}")]
    CryptoError(String),

    // User errors
    #[error("Passphrase too weak (minimum {min_length} characters)")]
    PassphraseTooWeak { min_length: usize },

    #[error("A passphrase is required: supply -p/--passphrase-file (interactive prompting is not yet supported)")]
    PassphraseRequired,

    #[error("Passphrase mismatch")]
    PassphraseMismatch,

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

impl Error {
    /// Process exit code for this error, by category:
    ///   1 = internal/runtime failure (crypto, I/O, corruption, unexpected)
    ///   2 = usage error (passphrase missing/weak) — fix the invocation
    ///   3 = not-found / input error (vault/share/key missing, bad threshold)
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::PassphraseRequired
            | Error::PassphraseTooWeak { .. }
            | Error::PassphraseMismatch => 2,
            Error::VaultNotFound(_)
            | Error::VaultAlreadyExists(_)
            | Error::ShareNotFound { .. }
            | Error::KeyNotFound { .. }
            | Error::KeyAlreadyExists { .. }
            | Error::AuditLogNotFound
            | Error::InsufficientShares { .. }
            | Error::InvalidThreshold { .. } => 3,
            _ => 1,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::IoError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::VaultNotFound("/tmp/test.vault".into());
        assert_eq!(err.to_string(), "Vault not found: /tmp/test.vault");
    }

    #[test]
    fn test_error_key_not_found() {
        let err = Error::KeyNotFound {
            key_id: "test-key".to_string(),
        };
        assert_eq!(err.to_string(), "Key not found: test-key");
    }

    #[test]
    fn test_error_insufficient_shares() {
        let err = Error::InsufficientShares {
            needed: 3,
            provided: 2,
        };
        assert_eq!(err.to_string(), "Insufficient shares: need 3, got 2");
    }

    #[test]
    fn test_error_passphrase_too_weak() {
        let err = Error::PassphraseTooWeak { min_length: 12 };
        assert_eq!(
            err.to_string(),
            "Passphrase too weak (minimum 12 characters)"
        );
    }

    #[test]
    fn test_error_display_all_variants() {
        let errors = vec![
            Error::VaultNotFound("/tmp/test.vault".into()),
            Error::VaultAlreadyExists("/tmp/test.vault".into()),
            Error::VaultCorrupted("bad data".to_string()),
            Error::VaultDecryptionFailed("wrong key".to_string()),
            Error::VaultEncryptionFailed("kdf failed".to_string()),
            Error::KeyNotFound {
                key_id: "k1".to_string(),
            },
            Error::KeyAlreadyExists {
                key_id: "k1".to_string(),
            },
            Error::ShareNotFound { share_number: 1 },
            Error::InsufficientShares {
                needed: 3,
                provided: 2,
            },
            Error::ShareVerificationFailed {
                share_number: 1,
                details: "bad sig".to_string(),
            },
            Error::ShareCorrupted { share_number: 1 },
            Error::InvalidThreshold {
                threshold: 5,
                total_shares: 3,
            },
            Error::SignatureVerificationFailed("invalid".to_string()),
            Error::SignatureGenerationFailed("failed".to_string()),
            Error::ComplianceExportFailed {
                framework: "SOC2".to_string(),
                details: "io".to_string(),
            },
            Error::AuditLogNotFound,
            Error::IoError("disk full".to_string()),
            Error::CryptoError("argon2 failed".to_string()),
            Error::PassphraseTooWeak { min_length: 8 },
            Error::PassphraseMismatch,
            Error::NotImplemented("feature".to_string()),
        ];

        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        match err {
            Error::IoError(msg) => assert!(msg.contains("file not found")),
            _ => panic!("Expected IoError"),
        }
    }

    #[test]
    fn test_from_serde_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let err: Error = json_err.into();
        match err {
            Error::IoError(msg) => {
                assert!(msg.contains("control character") || msg.contains("expected"))
            }
            _ => panic!("Expected IoError from serde"),
        }
    }

    #[test]
    fn test_error_debug_format() {
        let err = Error::VaultNotFound("/tmp/test.vault".into());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("VaultNotFound"));
    }
}
