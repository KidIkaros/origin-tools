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

impl Default for WalletMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Current on-disk wallet format version.
///
/// v2 encrypts the *entire* payload (seed + accounts + history + metadata)
/// as a single AEAD blob keyed by an Argon2id-stretched passphrase.
const WALLET_FORMAT_VERSION: u32 = 2;

/// Wallet state for serialization — the on-disk envelope.
///
/// Everything sensitive lives inside [`WalletPayload`], which is encrypted
/// as a single XChaCha20-Poly1305 blob. The envelope carries only the
/// version, the Argon2id salt, the AEAD nonce, and the ciphertext.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WalletState {
    /// Format version (must equal [`WALLET_FORMAT_VERSION`])
    version: u32,
    /// Random 16-byte Argon2id salt (unique per wallet file)
    argon2_salt: [u8; 16],
    /// XChaCha20-Poly1305 nonce
    nonce: [u8; 24],
    /// bincode([`WalletPayload`]), AEAD-encrypted with passphrase-derived key
    ciphertext: Vec<u8>,
}

/// The plaintext wallet payload, encrypted at rest inside [`WalletState`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WalletPayload {
    /// Master seed
    seed: Vec<u8>,
    /// Accounts (includes private keys — encrypted at rest)
    accounts: Vec<AccountData>,
    /// Transaction history (full MMR state)
    history: MmrState,
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

/// An encrypted shard for wallet backup.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Shard {
    /// Shard index (0-based)
    pub index: u32,
    /// Shard data
    pub data: Vec<u8>,
    /// Total number of shards created
    pub total_shards: u32,
    /// Threshold for recovery
    pub threshold: u32,
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
        // The empirical Shannon entropy of an n-byte sample caps at
        // log2(n) (all bytes distinct) — for a 32-byte seed that is
        // exactly 5.0, so a 7.5 threshold is unreachable and would make
        // `create` fail on every run. 4.5 cleanly separates a random
        // seed (≈4.7–4.9) from a biased one while remaining achievable.
        let min_entropy = 4.5;
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

        // 2. Parse envelope
        let state: WalletState = bincode::deserialize(&data)?;

        // 3. Reject unknown formats
        if state.version != WALLET_FORMAT_VERSION {
            return Err(WalletError::Decryption(format!(
                "Unsupported wallet format version {}",
                state.version
            )));
        }

        // 4. Derive encryption key from passphrase (Argon2id)
        let key = derive_key_from_passphrase(passphrase, &state.argon2_salt)?;

        // 5. Decrypt the full payload — a wrong passphrase fails AEAD auth here
        let plaintext = origin_crypto_sdk::aead::XChaCha20Poly1305::decrypt(
            &key,
            &state.nonce,
            &state.ciphertext,
        )?;
        let payload: WalletPayload = bincode::deserialize(&plaintext)?;

        // 6. Create SeedHandle
        let seed_handle = SeedHandle::with_tier(
            &payload.seed,
            Some(std::time::Duration::from_secs(3600)),
            origin_crypto_sdk::prelude::MemoryTier::Sovereign,
        );

        // 7. Reconstruct accounts
        let accounts: Vec<Account> = payload
            .accounts
            .iter()
            .map(|acc_data| {
                let address = Address::from_bech32(&acc_data.address_bech32)?;
                let mut account = Account::new(
                    acc_data.name.clone(),
                    acc_data.index,
                    acc_data.ed25519_sk.clone(),
                    acc_data.falcon_sk.clone(),
                    address,
                );
                account.set_balance(acc_data.balance);
                account.set_nonce(acc_data.nonce);
                Ok(account)
            })
            .collect::<Result<Vec<Account>>>()?;

        Ok(Self {
            seed_handle,
            accounts,
            history: payload.history,
            metadata: payload.metadata,
        })
    }

    /// Save wallet to file.
    ///
    /// The entire wallet (seed + account keys + history + metadata) is
    /// serialized and encrypted as a single AEAD payload, keyed by an
    /// Argon2id-stretched passphrase. Nothing sensitive is written in
    /// plaintext.
    pub fn save(&self, path: &Path, passphrase: &str) -> Result<()> {
        // 1. Random Argon2id salt for this file
        let salt_bytes = origin_crypto_sdk::aead::generate_key(); // 32 random bytes
        let mut argon2_salt = [0u8; 16];
        argon2_salt.copy_from_slice(&salt_bytes[..16]);

        // 2. Derive encryption key from passphrase (memory-hard KDF)
        let key = derive_key_from_passphrase(passphrase, &argon2_salt)?;

        // 3. Get seed bytes
        let seed_bytes = self
            .seed_handle
            .as_bytes()
            .ok_or(WalletError::SeedExpired)?;

        // 4. Serialize accounts
        let accounts_data: Vec<AccountData> = self
            .accounts
            .iter()
            .map(|acc| AccountData {
                name: acc.name().to_string(),
                index: acc.index(),
                ed25519_sk: acc.ed25519_sk().to_vec(),
                falcon_sk: acc.falcon_sk().to_vec(),
                address_bech32: acc.address().to_bech32().unwrap_or_default(),
                balance: acc.balance(),
                nonce: acc.nonce(),
            })
            .collect();

        // 5. Build and serialize the plaintext payload
        let payload = WalletPayload {
            seed: seed_bytes.to_vec(),
            accounts: accounts_data,
            history: self.history.clone(),
            metadata: self.metadata.clone(),
        };
        let plaintext = bincode::serialize(&payload)?;

        // 6. Encrypt the whole payload
        let nonce = origin_crypto_sdk::aead::generate_nonce();
        let ciphertext = origin_crypto_sdk::aead::XChaCha20Poly1305::encrypt(
            &key,
            &nonce,
            &plaintext,
        )?;

        // 7. Serialize envelope and write
        let state = WalletState {
            version: WALLET_FORMAT_VERSION,
            argon2_salt,
            nonce,
            ciphertext,
        };
        let data = bincode::serialize(&state)?;
        std::fs::write(path, data)?;

        Ok(())
    }

    /// Derive an account at the given index.
    pub fn derive_account(&mut self, index: u32) -> Result<Account> {
        // Check if account already exists
        if let Some(acc) = self.accounts.iter().find(|a| a.index() == index) {
            return Ok(acc.clone());
        }

        // Derive Ed25519 key using HKDF with domain separation
        let domain = format!("wallet:account:{index}");

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

        let (_falcon_pk, falcon_sk) = origin_crypto_sdk::pqc::falcon1024::generate_keypair_from_seed(&seed_array)
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

        // Derive stealth master keys for this account
        let stealth_domain = format!("wallet:account:{index}:stealth");
        let stealth_seed = self
            .seed_handle
            .derive_key(&stealth_domain, "stealth-master", 32)
            .ok_or_else(|| WalletError::KeyDerivation("Stealth seed derivation failed".into()))?;

        let mut stealth_seed_array = [0u8; 32];
        stealth_seed_array.copy_from_slice(&stealth_seed);
        let stealth_handle = origin_crypto_sdk::seed::SeedHandle::new(&stealth_seed_array, None);

        let stealth_master = origin_crypto_sdk::stealth::kdf::derive_stealth_master(&stealth_handle)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;

        let account = Account::with_stealth(
            format!("Account {index}"),
            index,
            ed_key,
            falcon_sk.as_bytes().to_vec(),
            address,
            stealth_master,
        );

        // Add account to wallet
        self.accounts.push(account.clone());
        self.metadata.modified_at = chrono::Utc::now().timestamp() as u64;

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
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.metadata.name = name.into();
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

    /// Update account balance.
    pub fn update_balance(&mut self, account_index: u32, new_balance: u64) -> Result<()> {
        let account = self
            .accounts
            .iter_mut()
            .find(|a| a.index() == account_index)
            .ok_or_else(|| WalletError::AccountNotFound(format!("Account {}", account_index)))?;

        account.set_balance(new_balance);
        self.metadata.modified_at = chrono::Utc::now().timestamp() as u64;
        Ok(())
    }

    /// Get account balance.
    pub fn get_balance(&self, account_index: u32) -> Result<u64> {
        let account = self
            .accounts
            .iter()
            .find(|a| a.index() == account_index)
            .ok_or_else(|| WalletError::AccountNotFound(format!("Account {}", account_index)))?;

        Ok(account.balance())
    }

    /// Get total wallet balance across all accounts.
    pub fn total_balance(&self) -> u64 {
        self.accounts.iter().map(|a| a.balance()).sum()
    }

    /// Derive this wallet's Stoa node identity (INTEGRATION.md §2).
    ///
    /// The node is a pure function of the master seed, domain-separated from
    /// account keys — so the `MeshId` (and the at-rest store key that lets a
    /// node re-decrypt its own `$STOA_HOME` state) are stable across unlock
    /// cycles. This is step 1 of the embedding: prove key derivation is
    /// stable; binding a `Mesh` comes later.
    pub fn stoa_node_keys(&self) -> Result<stoa::NodeKeys> {
        let seed = self
            .seed_handle
            .as_bytes()
            .ok_or(WalletError::SeedExpired)?;
        if seed.len() != 32 {
            return Err(WalletError::KeyDerivation(format!(
                "Stoa node identity requires a 32-byte seed, got {}",
                seed.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed);
        stoa::NodeKeys::from_seed(&arr)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))
    }

    /// Generate a transaction proof for a specific leaf in the MMR.
    pub fn prove_transaction(&self, leaf_index: u64) -> Result<origin_proof::mmr::MembershipProof> {
        if leaf_index >= self.history.leaf_count {
            return Err(WalletError::Transaction(format!(
                "Leaf index {} out of range ({} leaves)",
                leaf_index, self.history.leaf_count
            )));
        }

        self.history
            .prove(leaf_index)
            .map_err(WalletError::Transaction)
    }

    /// Verify a transaction proof against the current MMR root.
    pub fn verify_transaction_proof(
        &self,
        proof: &origin_proof::mmr::MembershipProof,
    ) -> Result<bool> {
        let root = self.history.root();
        Ok(self.history.verify_proof(proof, &root))
    }
}

/// Derive encryption key from passphrase using Argon2id.
///
/// Argon2id is memory-hard: brute-forcing a weak passphrase costs ~64 MiB and
/// 4 passes per guess instead of a single fast HKDF evaluation. The salt is
/// random per file and stored in the envelope so the key can be re-derived.
fn derive_key_from_passphrase(passphrase: &str, argon2_salt: &[u8; 16]) -> Result<[u8; 32]> {
    Ok(origin_crypto_sdk::kdf::Argon2id::derive_key(
        passphrase.as_bytes(),
        argon2_salt,
        false,
    )?)
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

impl Wallet {
    /// Split wallet seed into N shards using Reed-Solomon error correction.
    ///
    /// Any `threshold` shards can reconstruct the original seed.
    /// Shards store metadata about total/threshold for self-describing recovery.
    pub fn backup(&self, shards: u32, threshold: u32) -> Result<Vec<Shard>> {
        if threshold == 0 || threshold > shards {
            return Err(WalletError::Backup(
                "Threshold must be between 1 and shards".into(),
            ));
        }

        // Get seed bytes
        let seed_bytes = self
            .seed_handle
            .as_bytes()
            .ok_or(WalletError::SeedExpired)?;

        // Create Reed-Solomon encoder
        let encoder =
            origin_crypto_sdk::error_correction::ReedSolomonCodec::new(threshold as usize, (shards - threshold) as usize);

        // Encode seed into shards
        let encoded = encoder.encode_shards(seed_bytes)?;

        // Convert to Shard structs
        let result = encoded
            .iter()
            .enumerate()
            .map(|(i, shard_data)| Shard {
                index: i as u32,
                data: shard_data.clone(),
                total_shards: shards,
                threshold,
            })
            .collect();

        Ok(result)
    }

    /// Reconstruct wallet seed from shards.
    ///
    /// Requires at least `threshold` shards. Each shard must have matching
    /// total_shards/threshold metadata (from the same backup).
    pub fn recover_from_shards(shards: &[Shard]) -> Result<Vec<u8>> {
        if shards.is_empty() {
            return Err(WalletError::Recovery("No shards provided".into()));
        }

        // Use metadata from first shard
        let threshold = shards[0].threshold;
        let total_shards = shards[0].total_shards;

        if shards.len() < threshold as usize {
            return Err(WalletError::Recovery(format!(
                "Need {} shards, got {}",
                threshold,
                shards.len()
            )));
        }

        // Create Reed-Solomon decoder with correct parameters
        let decoder =
            origin_crypto_sdk::error_correction::ReedSolomonCodec::new(threshold as usize, (total_shards - threshold) as usize);

        // Prepare shards for decoding (pad with None for missing shards)
        let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; total_shards as usize];
        for shard in shards {
            if (shard.index as usize) < shard_data.len() {
                shard_data[shard.index as usize] = Some(shard.data.clone());
            }
        }

        // Decode shards (seed is 32 bytes)
        let recovered = decoder.decode_shards(&shard_data, 32)?;

        Ok(recovered)
    }

    /// Export wallet as a recovery phrase (human-readable).
    ///
    /// The phrase encodes the full 256-bit (32-byte) seed. Shard backup
    /// remains available for threshold-based recovery.
    ///
    /// Note: the wallet's 32-byte seed is stored encrypted in the wallet
    /// file; the phrase is a second, independent copy of the same seed.
    pub fn export_phrase(&self) -> Result<String> {
        let seed_bytes = self
            .seed_handle
            .as_bytes()
            .ok_or(WalletError::SeedExpired)?;

        // Use SDK's unicode cipher to encode first 32 bytes as phrase
        let wordlist = origin_crypto_sdk::recovery::unicode_cipher::UnicodeWordlist::default();
        let phrase_length = origin_crypto_sdk::recovery::unicode_cipher::PhraseLength::Words24;
        let encoded = origin_crypto_sdk::recovery::unicode_cipher::encode_phrase(&seed_bytes[..32], &wordlist, phrase_length)
            .map_err(|e| WalletError::Recovery(e.to_string()))?;

        // Convert Vec<char> to String
        Ok(encoded.into_iter().collect())
    }

    /// Reconstruct a wallet from raw seed bytes (e.g. recovered from shards
    /// or decoded from a recovery phrase).
    ///
    /// Accounts are re-derived deterministically from the seed on demand, so
    /// a recovered wallet reproduces the original account keys exactly.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed_handle = SeedHandle::with_tier(
            seed,
            Some(std::time::Duration::from_secs(3600)),
            origin_crypto_sdk::prelude::MemoryTier::Sovereign,
        );

        Ok(Self {
            seed_handle,
            accounts: Vec::new(),
            history: MmrState::new(),
            metadata: WalletMetadata::new(),
        })
    }

    /// Reconstruct wallet from a recovery phrase.
    ///
    /// The phrase encodes the full 256-bit seed. The exact decoded bytes are
    /// used as the seed — no padding — so derived account keys match the
    /// original wallet.
    pub fn from_phrase(phrase: &str, _passphrase: &str) -> Result<Self> {
        // Decode phrase to seed bytes
        let chars: Vec<char> = phrase.chars().collect();
        let wordlist = origin_crypto_sdk::recovery::unicode_cipher::UnicodeWordlist::default();
        let seed_bytes = origin_crypto_sdk::recovery::unicode_cipher::decode_phrase(&chars, &wordlist)
            .map_err(|e| WalletError::Recovery(e.to_string()))?;

        Self::from_seed(&seed_bytes)
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
        let mut wallet = Wallet::create("test-passphrase").unwrap();
        let account = wallet.derive_account(0).unwrap();

        assert_eq!(account.index(), 0);
        assert!(!account.address().to_bech32().unwrap().is_empty());
    }

    #[test]
    fn test_balance_tracking() {
        let mut wallet = Wallet::create("test-passphrase").unwrap();
        wallet.derive_account(0).unwrap();

        // Initial balance should be 0
        assert_eq!(wallet.get_balance(0).unwrap(), 0);
        assert_eq!(wallet.total_balance(), 0);

        // Update balance
        wallet.update_balance(0, 1000).unwrap();
        assert_eq!(wallet.get_balance(0).unwrap(), 1000);
        assert_eq!(wallet.total_balance(), 1000);

        // Update again
        wallet.update_balance(0, 2500).unwrap();
        assert_eq!(wallet.get_balance(0).unwrap(), 2500);
        assert_eq!(wallet.total_balance(), 2500);
    }

    #[test]
    fn test_multi_account_balance() {
        let mut wallet = Wallet::create("test-passphrase").unwrap();

        // Create multiple accounts
        wallet.derive_account(0).unwrap();
        wallet.derive_account(1).unwrap();
        wallet.derive_account(2).unwrap();

        // Set different balances
        wallet.update_balance(0, 1000).unwrap();
        wallet.update_balance(1, 2000).unwrap();
        wallet.update_balance(2, 3000).unwrap();

        // Total should be sum of all
        assert_eq!(wallet.total_balance(), 6000);
    }

    #[test]
    fn test_balance_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");

        // Create wallet with balance
        let mut wallet = Wallet::create("test-passphrase").unwrap();
        wallet.derive_account(0).unwrap();
        wallet.update_balance(0, 12345).unwrap();
        wallet.save(&path, "test-passphrase").unwrap();

        // Load and verify balance persists
        let loaded = Wallet::open(&path, "test-passphrase").unwrap();
        assert_eq!(loaded.get_balance(0).unwrap(), 12345);
        assert_eq!(loaded.total_balance(), 12345);
    }

    #[test]
    fn test_balance_nonexistent_account() {
        let mut wallet = Wallet::create("test-passphrase").unwrap();

        // Try to update non-existent account
        let result = wallet.update_balance(999, 1000);
        assert!(result.is_err());

        // Try to get balance of non-existent account
        let result = wallet.get_balance(999);
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_history() {
        let mut wallet = Wallet::create("test-passphrase").unwrap();
        let account = wallet.derive_account(0).unwrap();

        // Initial history should be empty
        assert_eq!(wallet.transaction_count(), 0);

        // Create and add transactions
        for i in 0..10 {
            let from = account.address().clone();
            let to = account.address().clone();
            let tx = crate::transaction::Transaction::new(&from, &to, 100 * (i + 1), 10, i);
            wallet.add_transaction(&tx).unwrap();
        }

        // History should have 10 transactions
        assert_eq!(wallet.transaction_count(), 10);
    }

    #[test]
    fn test_transaction_proof() {
        let mut wallet = Wallet::create("test-passphrase").unwrap();
        let account = wallet.derive_account(0).unwrap();

        // Add a transaction
        let from = account.address().clone();
        let to = account.address().clone();
        let tx = crate::transaction::Transaction::new(&from, &to, 1000, 10, 0);
        wallet.add_transaction(&tx).unwrap();

        // Generate proof
        let proof = wallet.prove_transaction(0).unwrap();

        // Verify proof
        let valid = wallet.verify_transaction_proof(&proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_transaction_proof_invalid_index() {
        let wallet = Wallet::create("test-passphrase").unwrap();

        // Try to prove non-existent leaf
        let result = wallet.prove_transaction(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_backup_shards() {
        let wallet = Wallet::create("test-passphrase").unwrap();

        // Create backup with 5 shards, threshold 3
        let shards = wallet.backup(5, 3).unwrap();
        assert_eq!(shards.len(), 5);

        // Each shard should have unique index and metadata
        for (i, shard) in shards.iter().enumerate() {
            assert_eq!(shard.index, i as u32);
            assert!(!shard.data.is_empty());
            assert_eq!(shard.total_shards, 5);
            assert_eq!(shard.threshold, 3);
        }
    }

    #[test]
    fn test_backup_invalid_threshold() {
        let wallet = Wallet::create("test-passphrase").unwrap();

        // Threshold 0 should fail
        assert!(wallet.backup(5, 0).is_err());

        // Threshold > shards should fail
        assert!(wallet.backup(3, 5).is_err());
    }

    #[test]
    fn test_recover_from_shards() {
        let wallet = Wallet::create("test-passphrase").unwrap();
        let original_seed = wallet.seed_handle.as_bytes().unwrap().to_vec();

        // Create backup
        let shards = wallet.backup(5, 3).unwrap();

        // Recover with exactly threshold shards (first 3)
        let recovered = Wallet::recover_from_shards(&shards[..3]).unwrap();
        assert_eq!(recovered, original_seed);

        // Recover with all shards
        let recovered = Wallet::recover_from_shards(&shards).unwrap();
        assert_eq!(recovered, original_seed);

        // Recover with different subset (last 3)
        let recovered = Wallet::recover_from_shards(&shards[2..]).unwrap();
        assert_eq!(recovered, original_seed);
    }

    #[test]
    fn test_recover_insufficient_shards() {
        let shards = vec![
            Shard { index: 0, data: vec![1, 2, 3], total_shards: 5, threshold: 3 },
            Shard { index: 1, data: vec![4, 5, 6], total_shards: 5, threshold: 3 },
        ];

        // Need 3 shards but only have 2
        let result = Wallet::recover_from_shards(&shards);
        assert!(result.is_err());
    }

    #[test]
    fn test_export_import_phrase_roundtrip() {
        let wallet = Wallet::create("test-passphrase").unwrap();
        let original_seed = wallet.seed_handle.as_bytes().unwrap().to_vec();

        // Export phrase
        let phrase = wallet.export_phrase().unwrap();
        assert!(!phrase.is_empty());

        // Import phrase
        let restored = Wallet::from_phrase(&phrase, "test-passphrase").unwrap();
        let restored_seed = restored.seed_handle.as_bytes().unwrap().to_vec();

        // Full seed must match exactly (phrase encodes the entire 256-bit seed)
        assert_eq!(original_seed, restored_seed);
    }

    #[test]
    fn test_phrase_recovery_reproduces_account_keys() {
        let mut wallet = Wallet::create("test-passphrase").unwrap();
        let account = wallet.derive_account(0).unwrap();
        let expected_ed = account.ed25519_sk().to_vec();
        let expected_falcon = account.falcon_sk().to_vec();

        let phrase = wallet.export_phrase().unwrap();
        let mut restored = Wallet::from_phrase(&phrase, "test-passphrase").unwrap();

        // Re-derive account 0 on the restored wallet — keys must match exactly
        let restored_account = restored.derive_account(0).unwrap();
        assert_eq!(expected_ed, restored_account.ed25519_sk().to_vec());
        assert_eq!(expected_falcon, restored_account.falcon_sk().to_vec());
        assert_eq!(account.address(), restored_account.address());
    }

    #[test]
    fn test_shard_recovery_reproduces_account_keys() {
        let mut wallet = Wallet::create("test-passphrase").unwrap();
        let account = wallet.derive_account(0).unwrap();
        let expected_ed = account.ed25519_sk().to_vec();
        let expected_falcon = account.falcon_sk().to_vec();
        let expected_address = account.address().clone();

        let shards = wallet.backup(5, 3).unwrap();
        let recovered_seed = Wallet::recover_from_shards(&shards[..3]).unwrap();
        assert_eq!(recovered_seed, wallet.seed_handle.as_bytes().unwrap().to_vec());

        let mut restored = Wallet::from_seed(&recovered_seed).unwrap();
        let restored_account = restored.derive_account(0).unwrap();
        assert_eq!(expected_ed, restored_account.ed25519_sk().to_vec());
        assert_eq!(expected_falcon, restored_account.falcon_sk().to_vec());
        assert_eq!(expected_address, restored_account.address().clone());
    }

    #[test]
    fn test_wallet_file_contains_no_plaintext_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");

        let mut wallet = Wallet::create("test-passphrase").unwrap();
        let account = wallet.derive_account(0).unwrap();
        let ed_sk = account.ed25519_sk().to_vec();
        let falcon_sk = account.falcon_sk().to_vec();
        let seed = wallet.seed_handle.as_bytes().unwrap().to_vec();

        wallet.save(&path, "test-passphrase").unwrap();
        let data = std::fs::read(&path).unwrap();

        // None of the secret material may appear verbatim in the file
        assert!(!data.windows(ed_sk.len()).any(|w| w == ed_sk.as_slice()));
        assert!(!data.windows(falcon_sk.len()).any(|w| w == falcon_sk.as_slice()));
        assert!(!data.windows(seed.len()).any(|w| w == seed.as_slice()));
    }

    #[test]
    fn test_open_wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");

        let wallet = Wallet::create("right-passphrase").unwrap();
        wallet.save(&path, "right-passphrase").unwrap();

        let result = Wallet::open(&path, "wrong-passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_history_persists_across_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");

        let mut wallet = Wallet::create("test-passphrase").unwrap();
        let account = wallet.derive_account(0).unwrap();
        let from = account.address().clone();
        let to = account.address().clone();

        // Add transactions before saving
        for i in 0..10 {
            let tx = crate::transaction::Transaction::new(&from, &to, 100 * (i + 1), 10, i);
            wallet.add_transaction(&tx).unwrap();
        }
        assert_eq!(wallet.transaction_count(), 10);

        wallet.save(&path, "test-passphrase").unwrap();

        // Reload — history must survive
        let loaded = Wallet::open(&path, "test-passphrase").unwrap();
        assert_eq!(loaded.transaction_count(), 10);

        // Membership proofs must still verify against the restored MMR
        let proof = loaded.prove_transaction(3).unwrap();
        assert!(loaded.verify_transaction_proof(&proof).unwrap());
    }

    #[test]
    fn test_stoa_node_identity_stable_across_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");

        // Unlock 1: derive the node identity, then lock (save + drop).
        let wallet = Wallet::create("test-passphrase").unwrap();
        let first = wallet.stoa_node_keys().unwrap();
        let first_id = *first.mesh_id();
        wallet.save(&path, "test-passphrase").unwrap();
        drop(wallet);

        // Unlock 2: re-open and re-derive — the identity (and store key,
        // which gates re-decrypting the node's own persisted state) must
        // be identical, or the node could never read its own $STOA_HOME.
        let reopened = Wallet::open(&path, "test-passphrase").unwrap();
        let second = reopened.stoa_node_keys().unwrap();
        assert_eq!(second.mesh_id(), &first_id);
        assert_eq!(second.store_key(), first.store_key());
        assert_eq!(second.public_keys(), first.public_keys());
    }

    #[test]
    fn test_stoa_node_identity_differs_per_wallet() {
        let a = Wallet::create("pass-a").unwrap();
        let b = Wallet::create("pass-b").unwrap();
        assert_ne!(
            a.stoa_node_keys().unwrap().mesh_id(),
            b.stoa_node_keys().unwrap().mesh_id()
        );
    }

    #[tokio::test]
    async fn test_stoa_node_binds_and_reports_metrics() {
        // INTEGRATION.md step 2: unlock → derive node keys → bind a Mesh →
        // read live metrics. The bound node's identity must match the
        // wallet's derived identity (stable across unlocks), and the
        // metrics API must round-trip real actor state.
        let wallet = Wallet::create("test-passphrase").unwrap();
        let keys = wallet.stoa_node_keys().unwrap();
        let (mesh, _addr) =
            stoa::Mesh::bind(keys, "127.0.0.1:0".parse().unwrap()).expect("bind");

        // The bound node is this wallet's node — same MeshId.
        let again = wallet.stoa_node_keys().unwrap();
        assert_eq!(mesh.local_mesh_id(), *again.mesh_id());

        // Fresh node: zeroed health signals.
        let before = mesh.metrics().await;
        assert_eq!(before.connected_peers, 0);
        assert_eq!(before.dht_records, 0);
        assert_eq!(before.sync_lag_secs, u64::MAX, "never synced");
        assert_eq!(before.gossip_received, 0);

        // A heartbeat lands in the live set; the metrics reflect it.
        mesh.publish_pulse().await.expect("pulse");
        let after = mesh.metrics().await;
        assert!(after.pulse_live >= 1, "self heartbeat counted live");
        assert_eq!(after.sync_lag_secs, u64::MAX, "still never synced (no peers)");
    }
}
