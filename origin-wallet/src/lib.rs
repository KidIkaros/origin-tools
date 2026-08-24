// SPDX-License-Identifier: Apache-2.0

//! # Origin Wallet
//!
//! A post-quantum secure Digital Wallet built on the OriginSDK.
//!
//! This crate composes existing OriginSDK primitives into a cohesive wallet product:
//! - **Hybrid signatures** (Ed25519 + Falcon-1024) for PQC security
//! - **Stealth addresses** for privacy-preserving payments
//! - **MMR transaction history** with membership proofs
//! - **AEAD encryption** for state and memo confidentiality
//! - **Entropy validation** for seed quality assurance
//!
//! ## Quick Start
//!
//! ```ignore
//! use origin_wallet::Wallet;
//!
//! // Create a new wallet with fresh seed
//! let wallet = Wallet::create("my-secure-passphrase")?;
//!
//! // Derive an account
//! let account = wallet.derive_account(0)?;
//!
//! // Get address
//! println!("Address: {}", account.address());
//!
//! // Save wallet
//! wallet.save(std::path::Path::new("wallet.dat"), "my-secure-passphrase")?;
//! ```

pub mod account;
pub mod address;
pub mod contacts;
pub mod error;
pub mod network;
pub mod transaction;
pub mod wallet;

// Re-exports for convenience
pub use account::Account;
pub use address::{Address, AddressType, Network};
pub use contacts::Contacts;
pub use error::{Result, WalletError};
pub use transaction::Transaction;
pub use wallet::{Shard, Wallet};

// The native mesh rail's public surface, re-exported so downstream
// origin-suite crates (e.g. origin-payments) need not depend on the
// external stoa crate directly for the types they already reach through
// the wallet. `Wallet` embeds stoa as a library; these are the shared
// wire types a payer/payee bind and settle against.
pub use stoa::{ledger::LedgerEntry, Mesh, MeshId};

/// Encode a signed ledger entry to its wire bytes — the receipt evidence
/// a settle presents (Stoa §10.1). Thin passthrough so callers do not
/// reach into the external stoa crate for the encoding step.
pub fn encode_ledger_entry(entry: &LedgerEntry) -> Result<Vec<u8>> {
    stoa::ledger::encode_ledger_entry(entry).map_err(|e| WalletError::Network(e.to_string()))
}

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(VERSION, "0.1.0");
        assert_eq!(NAME, "origin-wallet");
    }
}
