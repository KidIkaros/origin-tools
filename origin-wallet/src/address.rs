// SPDX-License-Identifier: Apache-2.0

//! Address encoding (Bech32, Base58Check).

use crate::error::{Result, WalletError};
use bech32::{Bech32m, Hrp};

/// Network type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Network {
    /// Mainnet
    Mainnet,
    /// Testnet
    Testnet,
}

/// Address encoding type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AddressType {
    /// Bech32 encoding (modern, recommended)
    Bech32,
    /// Bech32m encoding (explicit version)
    Bech32m,
    /// Base58Check encoding (legacy compatibility)
    Base58Check,
}

/// A wallet address.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Address {
    /// 20-byte pubkey hash (RIPEMD-160(SHA-256(pubkey)))
    pubkey_hash: [u8; 20],
    /// Address encoding type
    address_type: AddressType,
    /// Network
    network: Network,
}

impl Address {
    /// Create address from Ed25519 public key.
    pub fn from_ed25519(
        pk: &origin_crypto_sdk::Ed25519VerifyingKey,
        address_type: AddressType,
        network: Network,
    ) -> Self {
        use ripemd::Ripemd160;
        use sha2::{Digest, Sha256};

        let pubkey_bytes = pk.as_bytes();
        let sha_hash = Sha256::digest(pubkey_bytes);
        let hash = Ripemd160::digest(sha_hash);

        let mut pubkey_hash = [0u8; 20];
        pubkey_hash.copy_from_slice(&hash);

        Self {
            pubkey_hash,
            address_type,
            network,
        }
    }

    /// Create address from raw pubkey hash.
    pub fn from_hash(hash: [u8; 20], address_type: AddressType, network: Network) -> Self {
        Self {
            pubkey_hash: hash,
            address_type,
            network,
        }
    }

    /// Get the HRP (Human-Readable Part) for Bech32 encoding.
    fn hrp(&self) -> &str {
        match self.network {
            Network::Mainnet => "origin",
            Network::Testnet => "torigin",
        }
    }

    /// Encode address as Bech32 string.
    pub fn to_bech32(&self) -> Result<String> {
        let hrp = Hrp::parse(self.hrp()).map_err(|e| WalletError::InvalidAddress(e.to_string()))?;

        let encoded = bech32::encode::<Bech32m>(hrp, &self.pubkey_hash)
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;

        Ok(encoded)
    }

    /// Decode address from Bech32 string.
    pub fn from_bech32(s: &str) -> Result<Self> {
        let (hrp, data) =
            bech32::decode(s).map_err(|e| WalletError::InvalidAddress(e.to_string()))?;

        if data.len() != 20 {
            return Err(WalletError::InvalidAddress(
                "Invalid data length".to_string(),
            ));
        }

        let network = match hrp.as_str() {
            "origin" => Network::Mainnet,
            "torigin" => Network::Testnet,
            _ => return Err(WalletError::InvalidAddress(format!("Unknown HRP: {}", hrp))),
        };

        let mut pubkey_hash = [0u8; 20];
        pubkey_hash.copy_from_slice(&data);

        Ok(Self {
            pubkey_hash,
            address_type: AddressType::Bech32m,
            network,
        })
    }

    /// Encode address as Base58Check string.
    pub fn to_base58check(&self) -> String {
        use base58::ToBase58;
        use sha2::{Digest, Sha256};

        // Version byte
        let version = match self.network {
            Network::Mainnet => 0x00,
            Network::Testnet => 0x6F,
        };

        // Payload: version + pubkey_hash
        let mut payload = Vec::with_capacity(21);
        payload.push(version);
        payload.extend_from_slice(&self.pubkey_hash);

        // Double SHA-256 for checksum
        let hash1 = Sha256::digest(&payload);
        let hash2 = Sha256::digest(hash1);
        let checksum = &hash2[..4];

        // Append checksum
        payload.extend_from_slice(checksum);

        // Base58 encode
        payload.to_base58()
    }

    /// Decode address from Base58Check string.
    pub fn from_base58check(s: &str) -> Result<Self> {
        use base58::FromBase58;
        use sha2::{Digest, Sha256};

        let decoded = s
            .from_base58()
            .map_err(|_| WalletError::InvalidAddress("Invalid Base58".into()))?;

        if decoded.len() != 25 {
            return Err(WalletError::InvalidAddress(
                "Invalid decoded length".to_string(),
            ));
        }

        let version = decoded[0];
        let pubkey_hash = &decoded[1..21];
        let checksum = &decoded[21..25];

        // Verify checksum
        let hash1 = Sha256::digest(&decoded[..21]);
        let hash2 = Sha256::digest(hash1);

        if checksum != &hash2[..4] {
            return Err(WalletError::InvalidAddress("Invalid checksum".to_string()));
        }

        let network = match version {
            0x00 => Network::Mainnet,
            0x6F => Network::Testnet,
            _ => {
                return Err(WalletError::InvalidAddress(format!(
                    "Unknown version: {}",
                    version
                )))
            }
        };

        let mut hash = [0u8; 20];
        hash.copy_from_slice(pubkey_hash);

        Ok(Self {
            pubkey_hash: hash,
            address_type: AddressType::Base58Check,
            network,
        })
    }

    /// Get the raw pubkey hash.
    pub fn hash(&self) -> &[u8; 20] {
        &self.pubkey_hash
    }

    /// Get address type.
    pub fn address_type(&self) -> AddressType {
        self.address_type
    }

    /// Get network.
    pub fn network(&self) -> Network {
        self.network
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.address_type {
            AddressType::Bech32 | AddressType::Bech32m => {
                write!(
                    f,
                    "{}",
                    self.to_bech32().unwrap_or_else(|_| "invalid".to_string())
                )
            }
            AddressType::Base58Check => {
                write!(f, "{}", self.to_base58check())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_bech32_roundtrip() {
        // Create a dummy public key
        let sk = origin_crypto_sdk::Ed25519SigningKey::from_bytes(&[1u8; 32]);
        let pk = sk.verifying_key();

        let addr = Address::from_ed25519(&pk, AddressType::Bech32, Network::Mainnet);
        let encoded = addr.to_bech32().unwrap();
        let decoded = Address::from_bech32(&encoded).unwrap();

        // Note: AddressType may differ after decode, but pubkey_hash should match
        assert_eq!(addr.hash(), decoded.hash());
        assert_eq!(addr.network(), decoded.network());
    }

    #[test]
    fn test_address_base58check_roundtrip() {
        let sk = origin_crypto_sdk::Ed25519SigningKey::from_bytes(&[1u8; 32]);
        let pk = sk.verifying_key();

        let addr = Address::from_ed25519(&pk, AddressType::Base58Check, Network::Mainnet);
        let encoded = addr.to_base58check();
        let decoded = Address::from_base58check(&encoded).unwrap();

        assert_eq!(addr, decoded);
    }
}
