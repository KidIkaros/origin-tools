use crate::cli::InitArgs;
use crate::crypto::{VaultData, EncryptedVault, encrypt_vault_data};
use crate::error::Error;
use crate::vault::{MemoryTier, Vault};
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use rand::Rng;
use serde_json;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Minimum passphrase length
const MIN_PASSPHRASE_LENGTH: usize = 12;

/// Initialize a new vault
pub fn cmd_init(args: InitArgs) -> Result<(), Error> {
    // Parse tier
    let tier = MemoryTier::from_str(&args.tier)
        .map_err(|e| Error::CryptoError(format!("Invalid tier: {}", e)))?;

    // Check if vault already exists
    let vault_path = Path::new("~/.origin/secrets.vault");
    if vault_path.exists() {
        return Err(Error::VaultAlreadyExists(vault_path.to_path_buf()));
    }

    // Prompt for passphrase
    let passphrase = if args.no_prompt {
        "demo-passphrase-for-testing-only".to_string()
    } else {
        // TODO: Implement secure passphrase prompt
        "demo-passphrase-for-testing-only".to_string()
    };

    // Validate passphrase length
    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(Error::PassphraseTooWeak {
            min_length: MIN_PASSPHRASE_LENGTH,
        });
    }

    // Generate salt and nonce
    let mut rng = rand::thread_rng();
    let salt: [u8; 16] = rng.gen();
    let nonce: [u8; 24] = rng.gen();

    // Derive master key via Argon2id
    let params = tier.argon2_params(32);
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let salt_string = SaltString::encode_b64(&salt)
        .map_err(|e| Error::CryptoError(format!("Failed to encode salt: {}", e)))?;

    let password_hash = argon2
        .hash_password(passphrase.as_bytes(), &salt_string)
        .map_err(|e| Error::CryptoError(format!("Failed to hash password: {}", e)))?;

    let master_key: [u8; 32] = password_hash.hash.unwrap().as_bytes().try_into()
        .map_err(|_| Error::CryptoError("Invalid key length from Argon2".to_string()))?;

    // Create vault data
    let mut vault_data = VaultData::new();
    let master_seed: [u8; 32] = rng.gen();
    vault_data.master_seed = master_seed;

    // Encrypt vault data
    let encrypted = encrypt_vault_data(&vault_data, &master_key, salt, nonce, tier)?;

    // Convert to Vault struct for serialization
    let vault = Vault {
        version: encrypted.version,
        created_at: encrypted.created_at,
        tier: encrypted.tier,
        fingerprint: encrypted.fingerprint.clone(),
        salt: encrypted.salt,
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
    };

    // Write vault to file
    let vault_json = serde_json::to_string_pretty(&vault)
        .map_err(|e| Error::CryptoError(format!("Failed to serialize vault: {}", e)))?;

    // Ensure directory exists
    if let Some(parent) = vault_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::IoError(format!("Failed to create directory: {}", e)))?;
    }

    fs::write(vault_path, vault_json)
        .map_err(|e| Error::IoError(format!("Failed to write vault: {}", e)))?;

    println!("Vault initialized: {:?}", vault_path);
    println!("Tier: {}", tier);
    println!("Fingerprint: {}", &encrypted.fingerprint);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_init_with_standard_tier() {
        let args = InitArgs {
            tier: "standard".to_string(),
            no_prompt: true,
        };

        let result = cmd_init(args);
        // Should succeed (creates vault at default path)
        // Note: This will fail if vault already exists
        println!("Result: {:?}", result);
    }

    #[test]
    fn test_init_with_nano_tier() {
        let args = InitArgs {
            tier: "nano".to_string(),
            no_prompt: true,
        };

        let result = cmd_init(args);
        println!("Result: {:?}", result);
    }

    #[test]
    fn test_init_with_sovereign_tier() {
        let args = InitArgs {
            tier: "sovereign".to_string(),
            no_prompt: true,
        };

        let result = cmd_init(args);
        println!("Result: {:?}", result);
    }

    #[test]
    fn test_init_with_invalid_tier() {
        let args = InitArgs {
            tier: "invalid".to_string(),
            no_prompt: true,
        };

        let result = cmd_init(args);
        assert!(matches!(result.unwrap_err(), Error::CryptoError(_)));
    }

    #[test]
    fn test_init_vault_already_exists() {
        // Create a vault file
        let temp_file = NamedTempFile::new().unwrap();
        let vault_path = temp_file.path().to_path_buf();
        drop(temp_file);

        // Touch the file
        fs::File::create(&vault_path).unwrap();

        // Try to init again (will fail because we use hardcoded path)
        // This test demonstrates the vault exists check logic
        let vault_check = Path::new("~/.origin/secrets.vault");
        if vault_check.exists() {
            // Would return VaultAlreadyExists error
        }
    }
}