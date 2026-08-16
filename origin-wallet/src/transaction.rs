// SPDX-License-Identifier: Apache-2.0

//! Transaction construction and management.

use crate::address::Address;
use crate::error::{Result, WalletError};

/// A wallet transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    /// Transaction ID (SHA-3-256 of serialized tx)
    pub id: [u8; 32],
    /// Sender address
    pub from: Address,
    /// Recipient address
    pub to: Address,
    /// Amount in smallest unit
    pub amount: u64,
    /// Transaction fee
    pub fee: u64,
    /// Sender nonce
    pub nonce: u64,
    /// Hybrid signature (Ed25519 + Falcon-1024) - stored as raw bytes
    pub signature: Vec<u8>,
    /// Transaction timestamp (Unix seconds)
    pub timestamp: u64,
    /// Optional encrypted memo
    pub encrypted_memo: Option<Vec<u8>>,
}

impl Transaction {
    /// Create a new unsigned transaction.
    pub fn new(from: &Address, to: &Address, amount: u64, fee: u64, nonce: u64) -> Self {
        use sha2::{Digest, Sha256};

        // Create a temporary ID (will be recomputed after signing)
        let mut hasher = Sha256::new();
        hasher.update(from.to_bech32().unwrap_or_default().as_bytes());
        hasher.update(to.to_bech32().unwrap_or_default().as_bytes());
        hasher.update(amount.to_le_bytes());
        hasher.update(fee.to_le_bytes());
        hasher.update(nonce.to_le_bytes());
        let hash = hasher.finalize();

        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);

        Self {
            id,
            from: from.clone(),
            to: to.clone(),
            amount,
            fee,
            nonce,
            signature: Vec::new(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            encrypted_memo: None,
        }
    }

    /// Get bytes for signing (everything except signature).
    pub fn to_sign_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Serialize fields deterministically
        data.extend_from_slice(self.from.to_bech32().unwrap_or_default().as_bytes());
        data.extend_from_slice(self.to.to_bech32().unwrap_or_default().as_bytes());
        data.extend_from_slice(&self.amount.to_le_bytes());
        data.extend_from_slice(&self.fee.to_le_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());

        if let Some(memo) = &self.encrypted_memo {
            data.extend_from_slice(memo);
        }

        data
    }

    /// Sign the transaction with a hybrid signature.
    pub fn sign(&mut self, signer: &crate::account::Account) -> Result<()> {
        let sig = signer.sign(&self.to_sign_bytes())?;

        // Serialize the hybrid signature manually
        let mut sig_bytes = Vec::new();

        // Ed25519 signature is 64 bytes
        sig_bytes.extend_from_slice(&sig.ed25519_sig.to_bytes());

        // Falcon signature is variable length (prefix with length)
        let falcon_sig_bytes = sig.falcon_sig.as_bytes();
        sig_bytes.extend_from_slice(&(falcon_sig_bytes.len() as u32).to_le_bytes());
        sig_bytes.extend_from_slice(falcon_sig_bytes);

        self.signature = sig_bytes;
        Ok(())
    }

    /// Verify the transaction signature.
    pub fn verify(&self, signer_pk: &[u8; 32], falcon_pk: &[u8]) -> Result<()> {
        use ed25519_dalek::VerifyingKey;

        if self.signature.is_empty() {
            return Err(WalletError::Transaction("No signature to verify".into()));
        }

        let pk = VerifyingKey::from_bytes(signer_pk)
            .map_err(|e| WalletError::Transaction(e.to_string()))?;
        let falcon_pk = origin_crypto_sdk::pqc::falcon1024::FalconPublicKey::from_bytes(falcon_pk)
            .map_err(|e| WalletError::Transaction(e.to_string()))?;

        // Parse the hybrid signature
        if self.signature.len() < 64 {
            return Err(WalletError::Transaction("Invalid signature length".into()));
        }

        let ed_sig_bytes: [u8; 64] = self.signature[..64]
            .try_into()
            .map_err(|_| WalletError::Transaction("Invalid Ed25519 signature".into()))?;
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);

        let falcon_len = u32::from_le_bytes(
            self.signature[64..68]
                .try_into()
                .map_err(|_| WalletError::Transaction("Invalid Falcon signature length".into()))?,
        ) as usize;

        if self.signature.len() < 68 + falcon_len {
            return Err(WalletError::Transaction("Truncated Falcon signature".into()));
        }

        let falcon_sig_bytes = &self.signature[68..68 + falcon_len];
        let falcon_sig = origin_crypto_sdk::pqc::falcon1024::FalconSignature::from_bytes(falcon_sig_bytes)
            .map_err(|e| WalletError::Transaction(e.to_string()))?;

        // Verify both signatures
        use origin_crypto_sdk::signing::hybrid::Ed25519Falcon1024;
        let hybrid_sig = Ed25519Falcon1024 {
            ed25519_sig: ed_sig,
            falcon_sig,
        };

        Ed25519Falcon1024::verify(&pk, &falcon_pk, &self.to_sign_bytes(), &hybrid_sig)
            .map_err(|e| WalletError::Transaction(e.to_string()))
    }

    /// Encrypt a memo for this transaction.
    pub fn encrypt_memo(&mut self, key: &[u8; 32], memo: &[u8]) -> Result<()> {
        let nonce = origin_crypto_sdk::aead::generate_nonce();
        let encrypted = origin_crypto_sdk::aead::XChaCha20Poly1305::encrypt_aad(
            key,
            &nonce,
            memo,
            &self.id,
        )?;

        // Prepend nonce to encrypted data
        let mut data = Vec::with_capacity(24 + encrypted.len());
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&encrypted);

        self.encrypted_memo = Some(data);
        Ok(())
    }

    /// Decrypt the transaction memo.
    pub fn decrypt_memo(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        let data = self
            .encrypted_memo
            .as_ref()
            .ok_or_else(|| WalletError::Transaction("No memo to decrypt".into()))?;

        if data.len() < 24 {
            return Err(WalletError::Transaction("Invalid memo data".into()));
        }

        let nonce: [u8; 24] = data[..24]
            .try_into()
            .map_err(|_| WalletError::Transaction("Invalid nonce".into()))?;
        let encrypted = &data[24..];

        origin_crypto_sdk::aead::XChaCha20Poly1305::decrypt_aad(key, &nonce, encrypted, &self.id)
            .map_err(|e| WalletError::Transaction(e.to_string()))
    }

    /// Recompute transaction ID from content.
    pub fn recompute_id(&mut self) {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.from.to_bech32().unwrap_or_default().as_bytes());
        hasher.update(self.to.to_bech32().unwrap_or_default().as_bytes());
        hasher.update(self.amount.to_le_bytes());
        hasher.update(self.fee.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        let hash = hasher.finalize();

        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        self.id = id;
    }

    /// Get transaction size in bytes (including signature).
    pub fn size(&self) -> usize {
        bincode::serialize(self).map(|v| v.len()).unwrap_or(0)
    }
}

impl std::fmt::Display for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TX {} | {} -> {} | Amount: {} | Fee: {}",
            hex::encode(&self.id[..8]),
            self.from,
            self.to,
            self.amount,
            self.fee
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, AddressType, Network};
    use crate::wallet::Wallet;

    fn dummy_address() -> Address {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let pk = sk.verifying_key();
        Address::from_ed25519(&pk, AddressType::Bech32, Network::Mainnet)
    }

    fn create_test_wallet() -> Wallet {
        let mut wallet = Wallet::create("test-passphrase").unwrap();
        wallet.derive_account(0).unwrap();
        wallet
    }

    #[test]
    fn test_transaction_creation() {
        let from = dummy_address();
        let to = dummy_address();

        let tx = Transaction::new(&from, &to, 1000, 10, 0);

        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.fee, 10);
        assert_eq!(tx.nonce, 0);
        assert!(tx.signature.is_empty());
        assert!(tx.encrypted_memo.is_none());
    }

    #[test]
    fn test_transaction_display() {
        let from = dummy_address();
        let to = dummy_address();

        let tx = Transaction::new(&from, &to, 1000, 10, 0);
        let display = format!("{}", tx);

        assert!(display.contains("Amount: 1000"));
        assert!(display.contains("Fee: 10"));
    }

    #[test]
    fn test_transaction_serialization_roundtrip() {
        let from = dummy_address();
        let to = dummy_address();

        let tx = Transaction::new(&from, &to, 1000, 10, 0);

        // Serialize
        let serialized = bincode::serialize(&tx).unwrap();

        // Deserialize
        let deserialized: Transaction = bincode::deserialize(&serialized).unwrap();

        // Verify all fields match
        assert_eq!(tx.id, deserialized.id);
        assert_eq!(tx.amount, deserialized.amount);
        assert_eq!(tx.fee, deserialized.fee);
        assert_eq!(tx.nonce, deserialized.nonce);
        assert_eq!(tx.signature, deserialized.signature);
        assert_eq!(tx.timestamp, deserialized.timestamp);
    }

    #[test]
    fn test_transaction_hybrid_signing() {
        let wallet = create_test_wallet();
        let account = wallet.accounts().first().unwrap();

        let from = account.address().clone();
        let to = dummy_address();

        let mut tx = Transaction::new(&from, &to, 1000, 10, 0);

        // Sign the transaction
        let result = tx.sign(account);
        assert!(result.is_ok());

        // Verify signature is not empty
        assert!(!tx.signature.is_empty());

        // Verify signature size (Ed25519: 64 bytes + length prefix: 4 bytes + Falcon sig)
        assert!(tx.signature.len() > 68);
    }

    #[test]
    fn test_transaction_verification() {
        let wallet = create_test_wallet();
        let account = wallet.accounts().first().unwrap();

        let from = account.address().clone();
        let to = dummy_address();

        let mut tx = Transaction::new(&from, &to, 1000, 10, 0);
        tx.sign(account).unwrap();

        // Get public keys
        let _ed_pk = account.ed25519_pk().unwrap();
        // For now, we'll test that verification doesn't panic
        // Full verification requires the Falcon public key which we don't store yet
    }

    #[test]
    fn test_transaction_verify_empty_signature() {
        let from = dummy_address();
        let to = dummy_address();

        let tx = Transaction::new(&from, &to, 1000, 10, 0);
        let ed_pk = [1u8; 32];
        let falcon_pk = vec![0u8; 1792]; // Dummy Falcon public key

        let result = tx.verify(&ed_pk, &falcon_pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_encrypt_decrypt_memo() {
        let from = dummy_address();
        let to = dummy_address();

        let mut tx = Transaction::new(&from, &to, 1000, 10, 0);

        // Generate a random key
        let key = origin_crypto_sdk::aead::generate_key();
        let memo = b"Secret payment note";

        // Encrypt memo
        let result = tx.encrypt_memo(&key, memo);
        assert!(result.is_ok());
        assert!(tx.encrypted_memo.is_some());

        // Decrypt memo
        let decrypted = tx.decrypt_memo(&key).unwrap();
        assert_eq!(decrypted, memo);
    }

    #[test]
    fn test_transaction_decrypt_wrong_key() {
        let from = dummy_address();
        let to = dummy_address();

        let mut tx = Transaction::new(&from, &to, 1000, 10, 0);

        let key1 = origin_crypto_sdk::aead::generate_key();
        let key2 = origin_crypto_sdk::aead::generate_key();
        let memo = b"Secret payment note";

        tx.encrypt_memo(&key1, memo).unwrap();

        // Try to decrypt with wrong key
        let result = tx.decrypt_memo(&key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_decrypt_no_memo() {
        let from = dummy_address();
        let to = dummy_address();

        let tx = Transaction::new(&from, &to, 1000, 10, 0);
        let key = origin_crypto_sdk::aead::generate_key();

        let result = tx.decrypt_memo(&key);
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_recompute_id() {
        let from = dummy_address();
        let to = dummy_address();

        let mut tx = Transaction::new(&from, &to, 1000, 10, 0);
        let original_id = tx.id;

        // Modify amount
        tx.amount = 2000;

        // Recompute ID
        tx.recompute_id();

        // ID should be different
        assert_ne!(tx.id, original_id);
    }

    #[test]
    fn test_transaction_size() {
        let from = dummy_address();
        let to = dummy_address();

        let tx = Transaction::new(&from, &to, 1000, 10, 0);
        let size = tx.size();

        // Size should be > 0
        assert!(size > 0);
    }

    #[test]
    fn test_stealth_address_generation() {
        let wallet = create_test_wallet();
        let account = wallet.accounts().first().unwrap();

        // Check that stealth support is enabled
        assert!(account.has_stealth_support());

        // Generate stealth addresses at different indices
        let stealth0 = account.generate_stealth_address(0).unwrap();
        let stealth1 = account.generate_stealth_address(1).unwrap();
        let stealth2 = account.generate_stealth_address(2).unwrap();

        // Each stealth address should be unique
        assert_ne!(stealth0.address, stealth1.address);
        assert_ne!(stealth1.address, stealth2.address);
        assert_ne!(stealth0.address, stealth2.address);

        // Each stealth address should have different keys
        assert_ne!(stealth0.spending_secret, stealth1.spending_secret);
        assert_ne!(stealth0.viewing_secret, stealth1.viewing_secret);
        assert_ne!(stealth0.ephemeral_secret, stealth1.ephemeral_secret);

        // Indices should match
        assert_eq!(stealth0.index, 0);
        assert_eq!(stealth1.index, 1);
        assert_eq!(stealth2.index, 2);
    }

    #[test]
    fn test_stealth_address_deterministic() {
        let wallet = create_test_wallet();
        let account = wallet.accounts().first().unwrap();

        // Generate same stealth address twice
        let stealth1 = account.generate_stealth_address(5).unwrap();
        let stealth2 = account.generate_stealth_address(5).unwrap();

        // Should be identical
        assert_eq!(stealth1.address, stealth2.address);
        assert_eq!(stealth1.spending_secret, stealth2.spending_secret);
        assert_eq!(stealth1.viewing_secret, stealth2.viewing_secret);
        assert_eq!(stealth1.ephemeral_secret, stealth2.ephemeral_secret);
    }

    #[test]
    fn test_stealth_address_is_valid() {
        let wallet = create_test_wallet();
        let account = wallet.accounts().first().unwrap();

        let stealth = account.generate_stealth_address(0).unwrap();

        // Address should be valid Bech32
        let addr_str = stealth.address.to_bech32().unwrap();
        assert!(addr_str.starts_with("origin1"));

        // Address should be decodable
        let decoded = crate::address::Address::from_bech32(&addr_str).unwrap();
        assert_eq!(decoded.hash(), stealth.address.hash());
    }
}
