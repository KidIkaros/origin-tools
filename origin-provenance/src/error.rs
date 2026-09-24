// SPDX-License-Identifier: Apache-2.0

//! Error types for origin-provenance.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, ProvenanceError>;

#[derive(Error, Debug)]
pub enum ProvenanceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("hash mismatch for {path}: expected {expected}, got {actual}")]
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },

    #[error("invalid stamp: {0}")]
    InvalidStamp(String),

    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    #[error(
        "anchor file exists at {0} — refusing to overwrite (publish it, or delete it to re-anchor)"
    )]
    AnchorExists(String),

    #[error("manifest already exists at {0} — refusing to overwrite (delete it to start over; re-sealing wipes prior history)")]
    ManifestExists(String),

    #[error("invalid license: {0}")]
    InvalidLicense(String),

    #[error("signature verification failed: {0}")]
    SignatureError(String),

    #[error("file not found: {0}")]
    NotFound(String),

    #[error("{0}")]
    Other(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] origin_crypto_sdk::Error),
}
