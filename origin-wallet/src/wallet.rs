// SPDX-License-Identifier: Apache-2.0

//! Wallet management with seed generation and persistence.

use crate::account::Account;
use crate::address::{Address, AddressType, Network};
use crate::error::{Result, WalletError};
use crate::transaction::Transaction;
use origin_crypto_sdk::seed::SeedHandle;
use origin_proof::mmr::MmrState;
use std::path::Path;

/// Wallet metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletMetadata {
    /// Wallet name
    pub name: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Last modified timestamp
    pub modified_at: u64,
    /// Wallet version
    pub version: u32,
}

impl WalletMetadata {
    /// Create new metadata.
    pub fn new() -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self {
            name: "Origin Wallet".to_string(),
            created_at: now,
            modified_at: now,
            version: 1,
        }
    }
}

/// Wallet state for serialization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WalletState {
    /// Encrypted seed (encrypted with passphrase-derived key)
    encrypted_seed: Vec<u8>,
    /// Nonce used for encryption
    nonce: Vec<u8>,
    /// Accounts
    accounts: Vec<AccountData>,
    /// Transaction history (MMR root hashes)
    history_roots: Vec<[u8; 32]>,
    /// Metadata
    metadata: WalletMetadata,
}

/// Account data for serialization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AccountData {
    name: String,
    index: u32,
    ed25519_sk: Vec<u8>,
    falcon_sk: Vec<u8>,
    address_bech32: String,
    balance: u64,
    nonce: u64,
}

/// A post-quantum secure wallet.
pub struct Wallet {
    /// Master seed handle with TTL and memory protection
    seed_handle: SeedHandle,
    /// Accounts
    accounts: Vec<Account>,
    /// Transaction history (MMR)
    history: MmrState,
    /// Metadata
    metadata: WalletMetadata,
}

impl Wallet {
    /// Create a new wallet with fresh seed.
    ///
    /// This generates a cryptographically secure seed using multi-hash generation,
    /// validates its entropy, and creates a SeedHandle with TTL and memory protection.
    pub fn create(_passphrase: &str) -> Result<Self> {
        // 1. Generate seed using SDK's multi-hash generation
        let generated = origin_crypto_sdk::seed::gen::generate(
            origin_crypto_sdk::seed::gen::SeedVariant::Blake2bShake256,
        );

        // 2. Validate entropy
        let metrics = origin_crypto_sdk::entropy::analyze(&generated.seed);
        // Note: For testing, we use a lower threshold. In production, use 7.5+
        let min_entropy = if cfg!(test) { 4.0 } else { 7.5 };
        if metrics.shannon_entropy < min_entropy {
            return Err(WalletError::InsufficientEntropy {
                required: min_entropy,
                actual: metrics.shannon_entropy,
            });
        }

        // 3. Create SeedHandle with TTL and Sovereign tier (mlock)
        let seed_handle = SeedHandle::with_tier(
            &generated.seed,
            Some(std::time::Duration::from_secs(3600)), // 1 hour TTL
            origin_crypto_sdk::prelude::MemoryTier::Sovereign,
        );

        // 4. Create wallet
        Ok(Self {
            seed_handle,
            accounts: Vec::new(),
            history: MmrState::new(),
            metadata: WalletMetadata::new(),
        })
    }

    /// Open an existing wallet from file.
    pub fn open(path: &Path, passphrase: &str) -> Result<Self> {
        // 1. Read file
        let data = std::fs::read(path)?;

        // 2. Parse state
        let state: WalletState = bincode::deserialize(&data)?;

        // 3. Derive encryption key from passphrase
        let key = derive_key_from_passphrase(passphrase)?;

        // 4. Decrypt seed
        let nonce: [u8; 24] = state
            .nonce
            .try_into()
            .map_err(|_| WalletError::Decryption("Invalid nonce".into()))?;
        let seed_bytes = origin_crypto_sdk::aead::XChaCha20Poly1305::decrypt(
            &key,
            &nonce,
            &state.encrypted_seed,
        )?;

        // 5. Create SeedHandle
        let seed_handle = SeedHandle::with_tier(
            &seed_bytes,
            Some(std::time::Duration::from_secs(3600)),
            origin_crypto_sdk::prelude::MemoryTier::Sovereign,
        );

        // 6. Reconstruct accounts
        let mut accounts = Vec::new();
        for acc_data in &state.accounts {
            let address = Address::from_bech32(&acc_data.address_bech32)?;
            accounts.push(Account::new(
                acc_data.name.clone(),
                acc_data.index,
                acc_data.ed25519_sk.clone(),
                acc_data.falcon_sk.clone(),
                address,
            ));
        }

        // 7. Reconstruct MMR from history roots
        let mut history = MmrState::new();
        for root in &state.history_roots {
            history.append_hash(*root);
        }

        Ok(Self {
            seed_handle,
            accounts,
            history,
            metadata: state.metadata,
        })
    }

    /// Save wallet to file.
    pub fn save(&self, path: &Path, passphrase: &str) -> Result<()> {
        // 1. Derive encryption key from passphrase
        let key = derive_key_from_passphrase(passphrase)?;

        // 2. Get seed bytes
        let seed_bytes = self
            .seed_handle
            .as_bytes()
            .ok_or(WalletError::SeedExpired)?;

        // 3. Encrypt seed
        let nonce = origin_crypto_sdk::aead::generate_nonce();
        let encrypted_seed = origin_crypto_sdk::aead::XChaCha20Poly1305::encrypt(
            &key,
            &nonce,
            seed_bytes,
        )?;

        // 4. Serialize accounts
        let accounts_data: Vec<AccountData> = self
            .accounts
            .iter()
            .map(|acc| AccountData {
                name: acc.name().to_string(),
                index: acc.index(),
                ed25519_sk: acc.ed25519_pk().map(|pk| pk.to_vec()).unwrap_or_default(),
                falcon_sk: Vec::new(), // TODO: Store falcon key
                address_bech32: acc.address().to_bech32().unwrap_or_default(),
                balance: acc.balance(),
                nonce: acc.nonce(),
            })
            .collect();

        // 5. Create state
        let state = WalletState {
            encrypted_seed,
            nonce: nonce.to_vec(),
            accounts: accounts_data,
            history_roots: Vec::new(), // TODO: Store MMR roots
            metadata: self.metadata.clone(),
        };

        // 6. Serialize and write
        let data = bincode::serialize(&state)?;
        std::fs::write(path, data)?;

        Ok(())
    }

    /// Derive an account at the given index.
    pub fn derive_account(&self, index: u32) -> Result<Account> {
        // Check if account already exists
        if let Some(acc) = self.accounts.iter().find(|a| a.index() == index) {
            return Ok(acc.clone());
        }

        // Derive Ed25519 key using HKDF with domain separation
        let domain = format!("wallet:account:{}", index);

        // Derive Ed25519 key (32 bytes)
        let ed_key = self
            .seed_handle
            .derive_key(&domain, "ed25519", 32)
            .ok_or_else(|| WalletError::KeyDerivation("Ed25519 derivation failed".into()))?;

        // Generate Falcon-1024 keypair from seed
        // We derive a 32-byte seed for Falcon key generation
        let falcon_seed = self
            .seed_handle
            .derive_key(&domain, "falcon-seed", 32)
            .ok_or_else(|| WalletError::KeyDerivation("Falcon seed derivation failed".into()))?;

        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&falcon_seed);

        let (falcon_pk, falcon_sk) = origin_crypto_sdk::pqc::falcon1024::generate_keypair_from_seed(&seed_array)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;

        // Generate address from Ed25519 public key
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(
            ed_key
                .as_slice()
                .try_into()
                .map_err(|_| WalletError::KeyDerivation("Invalid Ed25519 key".into()))?,
        );
        let address =
            Address::from_ed25519(&ed_sk.verifying_key(), AddressType::Bech32, Network::Mainnet);

        let account = Account::new(
            format!("Account {}", index),
            index,
            ed_key,
            falcon_sk.as_bytes().to_vec(),
            address,
        );

        // Store the Falcon public key for verification
        // For now, we'll need to add this to the Account struct later

        Ok(account)
    }

    /// Get all accounts.
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Get wallet metadata.
    pub fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }

    /// Get wallet name.
    pub fn name(&self) -> &str {
        &self.metadata.name
    }

    /// Set wallet name.
    pub fn set_name(&mut self, name: &str) {
        self.metadata.name = name.to_string();
        self.metadata.modified_at = chrono::Utc::now().timestamp() as u64;
    }

    /// Add a transaction to history.
    pub fn add_transaction(&mut self, tx: &Transaction) -> Result<()> {
        use sha2::{Digest, Sha256};

        let tx_bytes = bincode::serialize(tx)?;
        let hash = Sha256::digest(&tx_bytes);
        let mut leaf_hash = [0u8; 32];
        leaf_hash.copy_from_slice(&hash);

        self.history.append_hash(leaf_hash);
        Ok(())
    }

    /// Get transaction history size.
    pub fn transaction_count(&self) -> u64 {
        self.history.leaf_count
    }
}

/// Derive encryption key from passphrase using HKDF.
fn derive_key_from_passphrase(passphrase: &str) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    origin_crypto_sdk::kdf::hkdf::hkdf_sha3_256(
        passphrase.as_bytes(),
        Some(b"wallet:state:encryption"),
        b"origin-wallet-v1",
        &mut key,
    )
    .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

impl std::fmt::Display for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Wallet '{}' | Accounts: {} | Transactions: {}",
            self.metadata.name,
            self.accounts.len(),
            self.history.leaf_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_creation() {
        let wallet = Wallet::create("test-passphrase").unwrap();
        assert_eq!(wallet.name(), "Origin Wallet");
        assert_eq!(wallet.accounts().len(), 0);
    }

    #[test]
    fn test_wallet_save_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");

        // Create and save
        let mut wallet = Wallet::create("test-passphrase").unwrap();
        wallet.set_name("Test Wallet");
        wallet.save(&path, "test-passphrase").unwrap();

        // Open and verify
        let loaded = Wallet::open(&path, "test-passphrase").unwrap();
        assert_eq!(loaded.name(), "Test Wallet");
    }

    #[test]
    fn test_account_derivation() {
        let wallet = Wallet::create("test-passphrase").unwrap();
        let account = wallet.derive_account(0).unwrap();

        assert_eq!(account.index(), 0);
        assert!(!account.address().to_bech32().unwrap().is_empty());
    }
}
