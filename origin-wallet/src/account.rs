// SPDX-License-Identifier: Apache-2.0

//! Account management with key derivation.

use crate::address::{Address, AddressType, Network};
use crate::error::{Result, WalletError};
use origin_crypto_sdk::signing::hybrid::Ed25519Falcon1024;

/// Stealth address keys derived for a specific index.
#[derive(Debug, Clone)]
pub struct StealthAddress {
    /// Viewing secret for this address
    pub viewing_secret: [u8; 32],
    /// Spending secret for this address
    pub spending_secret: [u8; 32],
    /// Ephemeral secret for this address
    pub ephemeral_secret: [u8; 32],
    /// The derived address
    pub address: Address,
    /// Index used for derivation
    pub index: u64,
}

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
    /// Stealth master keys (viewing, spending, ephemeral)
    stealth_master: Option<origin_crypto_sdk::stealth::kdf::StealthMasterKeys>,
}

impl Account {
    /// Create a new account.
    pub fn new(
        name: impl Into<String>,
        index: u32,
        ed25519_sk: Vec<u8>,
        falcon_sk: Vec<u8>,
        address: Address,
    ) -> Self {
        Self {
            name: name.into(),
            index,
            ed25519_sk,
            falcon_sk,
            address,
            balance: 0,
            nonce: 0,
            stealth_master: None,
        }
    }

    /// Create a new account with stealth master keys.
    pub fn with_stealth(
        name: impl Into<String>,
        index: u32,
        ed25519_sk: Vec<u8>,
        falcon_sk: Vec<u8>,
        address: Address,
        stealth_master: origin_crypto_sdk::stealth::kdf::StealthMasterKeys,
    ) -> Self {
        Self {
            name: name.into(),
            index,
            ed25519_sk,
            falcon_sk,
            address,
            balance: 0,
            nonce: 0,
            stealth_master: Some(stealth_master),
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

    /// Set nonce.
    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
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
        let falcon_sk =
            origin_crypto_sdk::pqc::falcon1024::FalconPrivateKey::from_bytes(&self.falcon_sk)
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

    /// Get Ed25519 secret key bytes.
    pub fn ed25519_sk(&self) -> &[u8] {
        &self.ed25519_sk
    }

    /// Get Falcon-1024 secret key bytes.
    pub fn falcon_sk(&self) -> &[u8] {
        &self.falcon_sk
    }

    /// Generate a stealth address for one-time payments.
    ///
    /// Each call with a different index produces a unique address that can only
    /// be spent by the holder of the spending secret.
    pub fn generate_stealth_address(&self, index: u64) -> Result<StealthAddress> {
        let master = self.stealth_master.as_ref().ok_or_else(|| {
            WalletError::KeyDerivation("Stealth master keys not initialized".into())
        })?;

        // Derive stealth keys at the given index
        let keys = origin_crypto_sdk::stealth::kdf::derive_stealth_at_index(master, index)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;

        // Generate address from spending secret
        let spending_sk = ed25519_dalek::SigningKey::from_bytes(&keys.spending_secret);
        let address = Address::from_ed25519(
            &spending_sk.verifying_key(),
            AddressType::Bech32,
            Network::Mainnet,
        );

        Ok(StealthAddress {
            viewing_secret: keys.viewing_secret,
            spending_secret: keys.spending_secret,
            ephemeral_secret: keys.ephemeral_secret,
            address,
            index,
        })
    }

    /// Check if stealth address generation is available.
    pub fn has_stealth_support(&self) -> bool {
        self.stealth_master.is_some()
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
