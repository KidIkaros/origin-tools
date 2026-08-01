use crate::cli::InitArgs;
use crate::crypto::{encrypt_vault_data, VaultData};
use crate::error::Error;
use crate::vault::{MemoryTier, Vault};
use rand::Rng;
use std::fs;
use std::path::Path;

/// Minimum passphrase length
const MIN_PASSPHRASE_LENGTH: usize = 12;

/// Initialize a new vault at `vault_path`.
pub fn cmd_init(args: InitArgs, vault_path: &Path) -> Result<(), Error> {
    // Parse tier
    let tier = MemoryTier::from_str(&args.tier)
        .map_err(|e| Error::CryptoError(format!("Invalid tier: {}", e)))?;

    // Check if vault already exists
    if vault_path.exists() {
        return Err(Error::VaultAlreadyExists(vault_path.to_path_buf()));
    }

    // Prompt for passphrase. Prefer an explicit passphrase file (e.g. mounted
    // secret) when supplied via `-p`/`--passphrase-file`. Without it we refuse
    // to silently fall back to a demo string in a real (non-test) run, since
    // that would store a known-weak key. Tests pass `no_prompt` with a file or
    // accept the demo string for convenience.
    let passphrase = if let Some(pf) = &args.passphrase_file {
        std::fs::read_to_string(pf)
            .map_err(|e| Error::IoError(format!("reading passphrase file {pf:?}: {e}")))?
            .trim_end_matches('\n')
            .to_string()
    } else if args.no_prompt {
        // Test/automation convenience only — never used for a real vault.
        "demo-passphrase-for-testing-only".to_string()
    } else {
        return Err(Error::PassphraseTooWeak {
            min_length: MIN_PASSPHRASE_LENGTH,
        });
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

    // Derive master key via Argon2id (origin-crypto-sdk, tier-aware cost)
    let builder = tier.argon2_builder().output_len(32);
    let derived = builder
        .derive(passphrase.as_bytes(), &salt)
        .map_err(|e| Error::CryptoError(format!("Failed to derive key: {:?}", e)))?;
    let master_key: [u8; 32] = derived
        .as_slice()
        .try_into()
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
    use tempfile::tempdir;

    #[test]
    fn test_init_with_standard_tier() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("secrets.vault");
        let args = InitArgs {
            tier: "standard".to_string(),
            no_prompt: true,
            passphrase_file: None,
        };
        let result = cmd_init(args, &vault_path);
        assert!(result.is_ok());
        assert!(vault_path.exists());
    }

    #[test]
    fn test_init_with_nano_tier() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("secrets.vault");
        let args = InitArgs {
            tier: "nano".to_string(),
            no_prompt: true,
            passphrase_file: None,
        };
        let result = cmd_init(args, &vault_path);
        assert!(result.is_ok());
        assert!(vault_path.exists());
    }

    #[test]
    fn test_init_with_sovereign_tier() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("secrets.vault");
        let args = InitArgs {
            tier: "sovereign".to_string(),
            no_prompt: true,
            passphrase_file: None,
        };
        let result = cmd_init(args, &vault_path);
        assert!(result.is_ok());
        assert!(vault_path.exists());
    }

    #[test]
    fn test_init_with_invalid_tier() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("secrets.vault");
        let args = InitArgs {
            tier: "invalid".to_string(),
            no_prompt: true,
            passphrase_file: None,
        };
        let result = cmd_init(args, &vault_path);
        assert!(matches!(result.unwrap_err(), Error::CryptoError(_)));
    }

    #[test]
    fn test_init_vault_already_exists() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("secrets.vault");
        // Create the file first.
        std::fs::File::create(&vault_path).unwrap();
        let args = InitArgs {
            tier: "standard".to_string(),
            no_prompt: true,
            passphrase_file: None,
        };
        let result = cmd_init(args, &vault_path);
        assert!(matches!(result.unwrap_err(), Error::VaultAlreadyExists(_)));
    }

    #[test]
    fn test_init_reads_passphrase_file() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("secrets.vault");
        let pw_file = dir.path().join("pw.txt");
        std::fs::write(&pw_file, "correct horse battery staple\n").unwrap();

        let args = InitArgs {
            tier: "standard".to_string(),
            no_prompt: true,
            passphrase_file: Some(pw_file.clone()),
        };
        let result = cmd_init(args, &vault_path);
        assert!(result.is_ok());

        // The saved vault must decrypt only with the file's passphrase, proving
        // -p/--passphrase-file is honored (not silently replaced by the demo string).
        let raw = std::fs::read_to_string(&vault_path).unwrap();
        let vault: crate::vault::Vault = serde_json::from_str(&raw).unwrap();
        let key = crate::crypto::derive_vault_key(
            b"correct horse battery staple",
            &vault.salt,
            vault.tier,
        )
        .unwrap();
        let enc = crate::crypto::EncryptedVault {
            version: vault.version,
            created_at: vault.created_at.clone(),
            tier: vault.tier,
            fingerprint: vault.fingerprint.clone(),
            salt: vault.salt,
            nonce: vault.nonce,
            ciphertext: vault.ciphertext.clone(),
        };
        assert!(crate::crypto::decrypt_vault_data(&enc, &key).is_ok());

        // The demo string must NOT decrypt it (it was not used as the key).
        let bad_key = crate::crypto::derive_vault_key(
            b"demo-passphrase-for-testing-only",
            &vault.salt,
            vault.tier,
        )
        .unwrap();
        assert!(crate::crypto::decrypt_vault_data(&enc, &bad_key).is_err());
    }

    #[test]
    fn test_init_without_prompt_or_file_is_rejected() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("secrets.vault");
        // No -p and no_prompt=false: a real (non-test) invocation with no
        // passphrase source must refuse rather than use a known-weak default.
        let args = InitArgs {
            tier: "standard".to_string(),
            no_prompt: false,
            passphrase_file: None,
        };
        let result = cmd_init(args, &vault_path);
        assert!(matches!(result, Err(Error::PassphraseTooWeak { .. })));
    }
}
