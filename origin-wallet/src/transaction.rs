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
        data.extend_from_slice(&self.from.to_bech32().unwrap_or_default().as_bytes());
        data.extend_from_slice(&self.to.to_bech32().unwrap_or_default().as_bytes());
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

    fn dummy_address() -> Address {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let pk = sk.verifying_key();
        Address::from_ed25519(&pk, AddressType::Bech32, Network::Mainnet)
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
}
