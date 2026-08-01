//! Error types for Origin Secrets

use serde::{Deserialize, Serialize};
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
    #[error("Share not found: {share_number} ({path})")]
    ShareNotFound { share_number: u8, path: PathBuf },

    #[error("Insufficient shares: need {needed}, got {provided}")]
    InsufficientShares { needed: u8, provided: u8 },

    #[error("Share verification failed: {share_number} - {details}")]
    ShareVerificationFailed { share_number: u8, details: String },

    #[error("Share corrupted: {share_number} ({path})")]
    ShareCorrupted { share_number: u8, path: PathBuf },

    // Output-file conflicts
    #[error("Output file already exists: {0} (refusing to overwrite; remove it or pass --force)")]
    FileAlreadyExists(PathBuf),

    #[error("Refusing to print the recovered master seed to stdout. Pass -o/--out <FILE> to write it to a file, or use --json for machine capture.")]
    StdoutSecretRefused,

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

/// Failure severity, for triage and the failure journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
    Critical,
}

impl Error {
    /// Process exit code for this error, by category:
    ///   1 = internal/runtime failure (crypto, I/O, corruption, unexpected)
    ///   2 = operator-fixable input/auth error (passphrase missing/weak, wrong
    ///      passphrase) — fix the invocation and retry
    ///   3 = not-found / input error (vault/share/key missing, bad threshold)
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::PassphraseRequired
            | Error::PassphraseTooWeak { .. }
            | Error::PassphraseMismatch
            | Error::VaultDecryptionFailed(_) => 2,
            Error::VaultNotFound(_)
            | Error::VaultAlreadyExists(_)
            | Error::ShareNotFound { .. }
            | Error::KeyNotFound { .. }
            | Error::KeyAlreadyExists { .. }
            | Error::AuditLogNotFound
            | Error::InsufficientShares { .. }
            | Error::InvalidThreshold { .. }
            | Error::FileAlreadyExists(_) => 3,
            _ => 1,
        }
    }

    /// Stable, machine-readable error code (e.g. `VAULT_DECRYPT_FAILED`).
    /// Used by the failure journal and `--json` output so failures are
    /// correlated and queryable rather than dying in stderr as prose.
    pub fn code(&self) -> &'static str {
        match self {
            Error::VaultNotFound(_) => "VAULT_NOT_FOUND",
            Error::VaultAlreadyExists(_) => "VAULT_ALREADY_EXISTS",
            Error::VaultCorrupted(_) => "VAULT_CORRUPTED",
            Error::VaultDecryptionFailed(_) => "VAULT_DECRYPTION_FAILED",
            Error::VaultEncryptionFailed(_) => "VAULT_ENCRYPTION_FAILED",
            Error::KeyNotFound { .. } => "KEY_NOT_FOUND",
            Error::KeyAlreadyExists { .. } => "KEY_ALREADY_EXISTS",
            Error::ShareNotFound { .. } => "SHARE_NOT_FOUND",
            Error::InsufficientShares { .. } => "INSUFFICIENT_SHARES",
            Error::ShareVerificationFailed { .. } => "SHARE_VERIFICATION_FAILED",
            Error::ShareCorrupted { .. } => "SHARE_CORRUPTED",
            Error::FileAlreadyExists(_) => "FILE_ALREADY_EXISTS",
            Error::StdoutSecretRefused => "STDOUT_SECRET_REFUSED",
            Error::InvalidThreshold { .. } => "INVALID_THRESHOLD",
            Error::SignatureVerificationFailed(_) => "SIGNATURE_VERIFICATION_FAILED",
            Error::SignatureGenerationFailed(_) => "SIGNATURE_GENERATION_FAILED",
            Error::ComplianceExportFailed { .. } => "COMPLIANCE_EXPORT_FAILED",
            Error::AuditLogNotFound => "AUDIT_LOG_NOT_FOUND",
            Error::IoError(_) => "IO_ERROR",
            Error::CryptoError(_) => "CRYPTO_ERROR",
            Error::PassphraseTooWeak { .. } => "PASSPHRASE_TOO_WEAK",
            Error::PassphraseRequired => "PASSPHRASE_REQUIRED",
            Error::PassphraseMismatch => "PASSPHRASE_MISMATCH",
            Error::NotImplemented(_) => "NOT_IMPLEMENTED",
        }
    }

    /// Severity for triage and the failure journal.
    pub fn severity(&self) -> Severity {
        match self {
            // Usage errors are operator-fixable, not system faults.
            Error::PassphraseRequired
            | Error::PassphraseTooWeak { .. }
            | Error::PassphraseMismatch => Severity::Warn,
            // Not-found / input errors are expected-class failures.
            Error::VaultNotFound(_)
            | Error::VaultAlreadyExists(_)
            | Error::ShareNotFound { .. }
            | Error::KeyNotFound { .. }
            | Error::KeyAlreadyExists { .. }
            | Error::AuditLogNotFound
            | Error::InsufficientShares { .. }
            | Error::InvalidThreshold { .. }
            | Error::FileAlreadyExists(_)
            | Error::StdoutSecretRefused => Severity::Warn,
            // Corruption / tamper / signature failure = security-relevant.
            Error::VaultCorrupted(_)
            | Error::ShareCorrupted { .. }
            | Error::ShareVerificationFailed { .. }
            | Error::SignatureVerificationFailed(_) => Severity::Critical,
            // Crypto / IO / decrypt failures are serious but often input-driven.
            Error::VaultDecryptionFailed(_)
            | Error::VaultEncryptionFailed(_)
            | Error::CryptoError(_)
            | Error::IoError(_) => Severity::Error,
            Error::ComplianceExportFailed { .. }
            | Error::SignatureGenerationFailed(_)
            | Error::NotImplemented(_) => Severity::Error,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::IoError(err.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
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
            Error::ShareNotFound {
                share_number: 1,
                path: PathBuf::from("/"),
            },
            Error::InsufficientShares {
                needed: 3,
                provided: 2,
            },
            Error::ShareVerificationFailed {
                share_number: 1,
                details: "bad sig".to_string(),
            },
            Error::ShareCorrupted {
                share_number: 1,
                path: PathBuf::from("/"),
            },
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

    #[test]
    fn test_exit_code_vault_decryption_failed_is_2() {
        let err = Error::VaultDecryptionFailed("wrong key".to_string());
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn test_exit_code_passphrase_required_is_2() {
        let err = Error::PassphraseRequired;
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn test_exit_code_passphrase_too_weak_is_2() {
        let err = Error::PassphraseTooWeak { min_length: 12 };
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn test_exit_code_passphrase_mismatch_is_2() {
        let err = Error::PassphraseMismatch;
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn test_exit_code_vault_not_found_is_3() {
        let err = Error::VaultNotFound("/tmp/test.vault".into());
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn test_exit_code_share_not_found_is_3() {
        let err = Error::ShareNotFound {
            share_number: 1,
            path: PathBuf::from("/"),
        };
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn test_exit_code_generic_crypto_error_is_1() {
        let err = Error::CryptoError("generic failure".to_string());
        assert_eq!(err.exit_code(), 1);
    }
}
