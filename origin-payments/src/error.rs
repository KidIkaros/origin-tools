// SPDX-License-Identifier: Apache-2.0

//! Error types for Origin Payments (design §7).

use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Origin Payments error types.
#[derive(Error, Debug)]
pub enum Error {
    // Store
    #[error("Order already exists (idempotent replay): {payment_order_id}")]
    OrderAlreadyExists { payment_order_id: String },

    #[error("Order not found: {payment_order_id}")]
    OrderNotFound { payment_order_id: String },

    #[error("Event not found: {event_id}")]
    EventNotFound { event_id: String },

    #[error("Store corrupted: {details}")]
    StoreCorrupted { details: String },

    #[error("Payments root already initialized: {0}")]
    AlreadyInitialized(PathBuf),

    // State machine
    #[error("Invalid order status transition: {from} -> {to}")]
    InvalidTransition { from: String, to: String },

    // Identity / signatures (P2)
    #[error("No operator identity at ~/.origin/identity.seed — run origin-identity keygen first")]
    IdentityNotFound,

    #[error("Signature failed: {details}")]
    SignatureFailed { details: String },

    #[error("Order is unsigned: {payment_order_id}")]
    Unsigned { payment_order_id: String },

    #[error("Wallet error: {details}")]
    WalletError { details: String },

    #[error("TOTP 2FA is not configured — run `admin-2fa init` first")]
    TwofaNotConfigured,

    #[error("TOTP 2FA code invalid or expired")]
    TwofaInvalid,

    #[error("Operator 2FA required for this admin command (--totp <code>)")]
    TwofaRequired,

    #[error("Custody operation failed: {details}")]
    CustodyError { details: String },

    // Amounts / journal
    #[error("Invalid amount: {0} (expected a decimal string, e.g. \"3.15\", max 2 decimals)")]
    InvalidAmount(String),

    #[error("Journal batch not balanced (sum != 0): {details}")]
    JournalNotBalanced { details: String },

    // Rails
    #[error("Rail unavailable: {rail} — {details}")]
    RailUnavailable { rail: String, details: String },

    #[error("Receipt verification failed: {details}")]
    ReceiptVerificationFailed { details: String },

    #[error("Rail not enabled/configured: {rail} — {details}")]
    RailNotConfigured { rail: String, details: String },

    #[error("Policy refused: {details}")]
    PolicyRefused { details: String },

    // Reconciliation
    #[error("Settlement file invalid: {path} — {details}")]
    SettlementFileInvalid { path: PathBuf, details: String },

    #[error("Settlement file provenance stamp mismatch: {path}")]
    SettlementStampMismatch { path: PathBuf },

    // I/O and crypto
    #[error("I/O error: {details}")]
    IoError { details: String },

    #[error("Crypto error: {details}")]
    CryptoError { details: String },

    // User
    #[error("Feature not yet implemented (design phase {phase}): {feature}")]
    NotImplemented {
        phase: &'static str,
        feature: String,
    },
}

impl Error {
    /// CLI exit codes (PAYMENT_SYSTEM_DESIGN.md §6).
    pub fn exit_code(&self) -> i32 {
        match self {
            // 2: operator-fixable input/auth
            Error::OrderAlreadyExists { .. }
            | Error::AlreadyInitialized(_)
            | Error::IdentityNotFound
            | Error::TwofaNotConfigured
            | Error::TwofaInvalid
            | Error::TwofaRequired => 2,
            // 3: not found / input error
            Error::OrderNotFound { .. }
            | Error::EventNotFound { .. }
            | Error::SettlementFileInvalid { .. } => 3,
            Error::SettlementStampMismatch { .. } => 3,
            // 4: payment-domain error
            Error::InvalidTransition { .. }
            | Error::InvalidAmount(_)
            | Error::JournalNotBalanced { .. }
            | Error::RailUnavailable { .. }
            | Error::ReceiptVerificationFailed { .. }
            | Error::SignatureFailed { .. }
            | Error::Unsigned { .. }
            | Error::RailNotConfigured { .. }
            | Error::PolicyRefused { .. } => 4,
            // 1: internal / runtime / crypto / not-yet-wired
            Error::StoreCorrupted { .. }
            | Error::IoError { .. }
            | Error::CryptoError { .. }
            | Error::WalletError { .. }
            | Error::CustodyError { .. }
            | Error::NotImplemented { .. } => 1,
        }
    }

    /// Machine-readable code for `--json` error payloads.
    pub fn code(&self) -> &'static str {
        match self {
            Error::OrderAlreadyExists { .. } => "ORDER_ALREADY_EXISTS",
            Error::OrderNotFound { .. } => "ORDER_NOT_FOUND",
            Error::EventNotFound { .. } => "EVENT_NOT_FOUND",
            Error::StoreCorrupted { .. } => "STORE_CORRUPTED",
            Error::AlreadyInitialized(_) => "ALREADY_INITIALIZED",
            Error::InvalidTransition { .. } => "INVALID_TRANSITION",
            Error::IdentityNotFound => "IDENTITY_NOT_FOUND",
            Error::SignatureFailed { .. } => "SIGNATURE_FAILED",
            Error::Unsigned { .. } => "UNSIGNED",
            Error::WalletError { .. } => "WALLET_ERROR",
            Error::TwofaNotConfigured => "TWOFACTOR_NOT_CONFIGURED",
            Error::TwofaInvalid => "TWOFACTOR_INVALID",
            Error::TwofaRequired => "TWOFACTOR_REQUIRED",
            Error::CustodyError { .. } => "CUSTODY_ERROR",
            Error::InvalidAmount(_) => "INVALID_AMOUNT",
            Error::JournalNotBalanced { .. } => "JOURNAL_NOT_BALANCED",
            Error::RailUnavailable { .. } => "RAIL_UNAVAILABLE",
            Error::RailNotConfigured { .. } => "RAIL_NOT_CONFIGURED",
            Error::PolicyRefused { .. } => "POLICY_REFUSED",
            Error::ReceiptVerificationFailed { .. } => "RECEIPT_VERIFICATION_FAILED",
            Error::SettlementFileInvalid { .. } => "SETTLEMENT_FILE_INVALID",
            Error::SettlementStampMismatch { .. } => "SETTLEMENT_STAMP_MISMATCH",
            Error::IoError { .. } => "IO_ERROR",
            Error::CryptoError { .. } => "CRYPTO_ERROR",
            Error::NotImplemented { .. } => "NOT_IMPLEMENTED",
        }
    }
}
