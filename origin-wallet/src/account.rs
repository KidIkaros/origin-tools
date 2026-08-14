// SPDX-License-Identifier: Apache-2.0

//! Account management with key derivation.

use crate::address::{Address, AddressType, Network};
use crate::error::{Result, WalletError};
use origin_crypto_sdk::signing::hybrid::Ed25519Falcon1024;

/// An account in the wallet.
#[derive(Debug, Clone)]
pub struct Account {
    /// Account name
    name: String,
    /// Account index (BIP-32 style)
    index: u32,
    /// Ed25519 signing key (32 bytes)
    ed25519_sk: Vec<u8>,
    /// Falcon-1024 signing key (2305 bytes)
    falcon_sk: Vec<u8>,
    /// Derived address
    address: Address,
    /// Current balance (synced from network)
    balance: u64,
    /// Transaction nonce
    nonce: u64,
}

impl Account {
    /// Create a new account.
    pub fn new(
        name: String,
        index: u32,
        ed25519_sk: Vec<u8>,
        falcon_sk: Vec<u8>,
        address: Address,
    ) -> Self {
        Self {
            name,
            index,
            ed25519_sk,
            falcon_sk,
            address,
            balance: 0,
            nonce: 0,
        }
    }

    /// Get account name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get account index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Get account address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get current balance.
    pub fn balance(&self) -> u64 {
        self.balance
    }

    /// Get current nonce.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Update balance.
    pub fn set_balance(&mut self, balance: u64) {
        self.balance = balance;
    }

    /// Increment nonce.
    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
    }

    /// Sign data with hybrid signature (Ed25519 + Falcon-1024).
    pub fn sign(&self, data: &[u8]) -> Result<Ed25519Falcon1024> {
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(
            self.ed25519_sk
                .as_slice()
                .try_into()
                .map_err(|_| WalletError::KeyDerivation("Invalid Ed25519 key length".into()))?,
        );
        let falcon_sk = origin_crypto_sdk::pqc::falcon1024::FalconPrivateKey::from_bytes(
            &self.falcon_sk,
        )
        .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;

        Ok(Ed25519Falcon1024::sign(&ed_sk, &falcon_sk, data))
    }

    /// Get Ed25519 public key bytes.
    pub fn ed25519_pk(&self) -> Result<[u8; 32]> {
        let sk = ed25519_dalek::SigningKey::from_bytes(
            self.ed25519_sk
                .as_slice()
                .try_into()
                .map_err(|_| WalletError::KeyDerivation("Invalid Ed25519 key length".into()))?,
        );
        Ok(*sk.verifying_key().as_bytes())
    }
}

impl std::fmt::Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Account {} ({}): {} | Balance: {} | Nonce: {}",
            self.index, self.name, self.address, self.balance, self.nonce
        )
    }
}
