use crate::cli::InitArgs;
use crate::crypto::{encrypt_vault_data, VaultData};
use crate::error::Error;
use crate::vault::{MemoryTier, Vault};
use std::fs;
use std::path::Path;

/// Minimum passphrase length
const MIN_PASSPHRASE_LENGTH: usize = 12;

/// Initialize a new vault at `vault_path`.
///
/// `passphrase_file` is the GLOBAL `-p/--passphrase-file` flag (resolved by the
/// dispatcher), kept consistent with every other subcommand. Its contents are
/// used as the vault passphrase. A passphrase source is mandatory — when absent,
/// initialization is refused (`PassphraseRequired`) rather than silently storing
/// a known-weak key.
pub fn cmd_init(
    args: InitArgs,
    vault_path: &Path,
    passphrase_file: Option<&Path>,
    json: bool,
) -> Result<(), Error> {
    // Parse tier
    let tier = MemoryTier::parse_tier(&args.tier)
        .map_err(|e| Error::CryptoError(format!("Invalid tier: {}", e)))?;

    // Check if vault already exists
    if vault_path.exists() {
        return Err(Error::VaultAlreadyExists(vault_path.to_path_buf()));
    }

    // Resolve passphrase. Prefer the global -p/--passphrase-file (e.g. a mounted
    // secret). Interactive prompting is not yet implemented; without a passphrase
    // source we refuse rather than store a known-weak key.
    let passphrase = if let Some(pf) = passphrase_file {
        std::fs::read_to_string(pf)
            .map_err(|e| Error::IoError(format!("reading passphrase file {pf:?}: {e}")))?
            .trim_end_matches('\n')
            .to_string()
    } else {
        return Result::Err(Error::PassphraseRequired);
    };

    // Validate passphrase length
    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(Error::PassphraseTooWeak {
            min_length: MIN_PASSPHRASE_LENGTH,
        });
    }

    // Generate salt and nonce via the SDK CSPRNG (single audited RNG source).
    let salt: [u8; 16] = super::super::crypto::random_array()?;
    let nonce: [u8; 24] = super::super::crypto::random_array()?;

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
    let master_seed: [u8; 32] = super::super::crypto::random_array()?;
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

    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "command": "init",
                "vault": vault_path.display().to_string(),
                "tier": tier.to_string(),
                "fingerprint": encrypted.fingerprint,
            })
        );
    } else {
        println!("Vault initialized: {:?}", vault_path);
        println!("Tier: {}", tier);
        println!("Fingerprint: {}", &encrypted.fingerprint);
    }

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
        let pw_file = dir.path().join("pw.txt");
        std::fs::write(&pw_file, "correct horse battery staple\n").unwrap();
        let args = InitArgs {
            tier: "standard".to_string(),
        };
        let result = cmd_init(args, &vault_path, Some(pw_file.as_path()), false);
        assert!(result.is_ok());
        assert!(vault_path.exists());
    }

    #[test]
    fn test_init_with_nano_tier() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("secrets.vault");
        let pw_file = dir.path().join("pw.txt");
        std::fs::write(&pw_file, "correct horse battery staple\n").unwrap();
        let args = InitArgs {
            tier: "nano".to_string(),
        };
        let result = cmd_init(args, &vault_path, Some(pw_file.as_path()), false);
        assert!(result.is_ok());
        assert!(vault_path.exists());
    }

    #[test]
    fn test_init_with_sovereign_tier() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("secrets.vault");
        let pw_file = dir.path().join("pw.txt");
        std::fs::write(&pw_file, "correct horse battery staple\n").unwrap();
        let args = InitArgs {
            tier: "sovereign".to_string(),
        };
        let result = cmd_init(args, &vault_path, Some(pw_file.as_path()), false);
        assert!(result.is_ok());
        assert!(vault_path.exists());
    }

    #[test]
    fn test_init_with_invalid_tier() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("secrets.vault");
        let pw_file = dir.path().join("pw.txt");
        std::fs::write(&pw_file, "correct horse battery staple\n").unwrap();
        let args = InitArgs {
            tier: "bogus".to_string(),
        };
        // With a passphrase supplied, tier validation runs and rejects the
        // unknown tier as a CryptoError (wrapping the parse error).
        let result = cmd_init(args, &vault_path, Some(pw_file.as_path()), false);
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
        };
        let result = cmd_init(args, &vault_path, None, false);
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
        };
        // Pass the passphrase file via the GLOBAL -p mechanism (third arg), the
        // same path the dispatcher uses. This must become the vault key.
        let result = cmd_init(args, &vault_path, Some(pw_file.as_path()), false);
        assert!(result.is_ok());

        // The saved vault must decrypt only with the file's passphrase, proving
        // the global -p/--passphrase-file is honored (not the demo string).
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
        // No -p: a real (non-test) invocation with no passphrase source must
        // passphrase source must refuse rather than use a known-weak default.
        let args = InitArgs {
            tier: "standard".to_string(),
        };
        let result = cmd_init(args, &vault_path, None, false);
        assert!(matches!(result, Result::Err(Error::PassphraseRequired)));
    }
}
