//! Recover command — reconstruct a vault master seed from K threshold shares.

use crate::cli::RecoverArgs;
use crate::error::Error;
use crate::share::{HybridSignature, Share};
use origin_crypto_sdk::error_correction::ReedSolomonCodec;
use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle};
use std::path::Path;

/// Domain separation label — must match `shard`.
const SHARE_SIGNING_DOMAIN: &str = "origin-secrets/share/v1";

/// Recover the 32-byte master seed from a set of share files.
///
/// At least `threshold` shares (as recorded in each share) must be supplied.
/// The first `threshold` shares are used for erasure decoding; every supplied
/// share's hybrid (Ed25519 + Falcon-1024) signature is verified against the
/// key bundle derived from the recovered seed, rejecting tampered shares.
///
/// If `args.vault_out` is set, a fresh vault is rebuilt from the recovered seed
/// and written to that path, encrypted with `new_passphrase` at the requested
/// tier — giving the operator a usable vault again after a loss.
pub fn cmd_recover(args: RecoverArgs, new_passphrase: &str) -> Result<Vec<u8>, Error> {
    if args.shares.is_empty() {
        return Err(Error::InsufficientShares {
            needed: 1,
            provided: 0,
        });
    }

    // Load all share files.
    let mut shares: Vec<Share> = Vec::with_capacity(args.shares.len());
    for path in &args.shares {
        let raw = std::fs::read_to_string(path)
            .map_err(|_| Error::ShareNotFound { share_number: 0 })?;
        let share: Share =
            serde_json::from_str(&raw).map_err(|e| Error::ShareCorrupted { share_number: 0 })?;
        shares.push(share);
    }

    // Threshold / total are embedded identically in every share.
    let threshold = shares[0].threshold as usize;
    let total = shares[0].total_shares as usize;

    if shares.len() < threshold {
        return Err(Error::InsufficientShares {
            needed: threshold as u8,
            provided: shares.len() as u8,
        });
    }

    // Build the full N-length Option vec: Some for supplied, None for missing.
    let mut opts: Vec<Option<Vec<u8>>> = vec![None; total];
    for share in &shares {
        let idx = (share.share_number as usize).saturating_sub(1);
        if idx < total {
            opts[idx] = Some(share.share_data.clone());
        } else {
            return Err(Error::ShareCorrupted {
                share_number: share.share_number,
            });
        }
    }

    let codec = ReedSolomonCodec::new(threshold, total - threshold);
    let recovered = codec
        .decode_shards(&opts, 32)
        .map_err(|e| Error::CryptoError(format!("Reed-Solomon decode failed: {e}")))?;

    // Verify each supplied share's hybrid signature against the recovered seed.
    let seed: &[u8; 32] = recovered
        .as_slice()
        .try_into()
        .map_err(|_| Error::CryptoError("recovered seed wrong length".to_string()))?;
    let signer = HybridSigningKeyBundle::from_seed_cached(seed, SHARE_SIGNING_DOMAIN)
        .map_err(|e| Error::SignatureGenerationFailed(format!("{e:?}")))?;
    let ed_pk = signer.ed25519_pk();
    let falcon_pk = signer.falcon1024_pk();

    for share in &shares {
        let sig: Ed25519Falcon1024 = HybridSignature::to_sdk(&share.signature)
            .map_err(|e| Error::SignatureVerificationFailed(format!("{e:?}")))?;
        Ed25519Falcon1024::verify(&ed_pk, &falcon_pk, &share.share_data, &sig).map_err(|_| {
            Error::ShareVerificationFailed {
                share_number: share.share_number,
                details: "hybrid signature mismatch".to_string(),
            }
        })?;
    }

    // Optional: rebuild a usable vault from the recovered seed.
    if let Some(vault_out) = &args.vault_out {
        let tier = parse_tier(&args.tier)?;
        write_recovered_vault(vault_out, seed, new_passphrase, tier)?;
        println!("Recovered vault written to: {}", vault_out.display());
    }

    // Emit the recovered seed.
    match &args.out {
        Some(path) => {
            std::fs::write(path, hex::encode(&recovered))
                .map_err(|e| Error::IoError(e.to_string()))?;
            println!("Recovered master seed written to: {}", path.display());
        }
        None => {
            println!("Recovered master seed (hex): {}", hex::encode(&recovered));
        }
    }

    Ok(recovered)
}

/// Parse a tier string into [`MemoryTier`].
fn parse_tier(s: &str) -> Result<crate::vault::MemoryTier, Error> {
    match s.to_ascii_lowercase().as_str() {
        "nano" => Ok(crate::vault::MemoryTier::Nano),
        "standard" => Ok(crate::vault::MemoryTier::Standard),
        "sovereign" => Ok(crate::vault::MemoryTier::Sovereign),
        other => Err(Error::InvalidThreshold {
            threshold: 0,
            total_shares: 0,
        })
        .map_err(|_| Error::CryptoError(format!("unknown tier: {other}")))?,
    }
}

/// Encrypt `seed` into a fresh vault file at `path`.
fn write_recovered_vault(
    path: &Path,
    seed: &[u8; 32],
    passphrase: &str,
    tier: crate::vault::MemoryTier,
) -> Result<(), Error> {
    use crate::crypto::{encrypt_vault_data, VaultData};
    use crate::vault::Vault;

    let salt: [u8; 16] = rand::random();
    let nonce: [u8; 24] = rand::random();
    let key = crate::crypto::derive_vault_key(passphrase.as_bytes(), &salt, tier)?;
    let mut vd = VaultData::new();
    vd.master_seed = *seed;
    let enc = encrypt_vault_data(&vd, &key, salt, nonce, tier)?;
    let vault = Vault {
        version: enc.version,
        created_at: enc.created_at.clone(),
        tier: enc.tier,
        fingerprint: enc.fingerprint.clone(),
        salt: enc.salt,
        nonce: enc.nonce,
        ciphertext: enc.ciphertext,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::IoError(format!("create vault dir: {e}")))?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&vault).map_err(|e| Error::IoError(e.to_string()))?)
        .map_err(|e| Error::IoError(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ShardArgs;
    use crate::commands::shard::cmd_shard;
    use crate::crypto::{decrypt_vault_data, derive_vault_key, encrypt_vault_data, VaultData};
    use crate::vault::{MemoryTier, Vault};
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn build_vault(dir: &std::path::Path) -> (PathBuf, String) {
        let passphrase = "recover-passphrase-test";
        let salt = [7u8; 16];
        let nonce = [8u8; 24];
        let tier = MemoryTier::Standard;
        let key = derive_vault_key(passphrase.as_bytes(), &salt, tier).unwrap();
        let mut vd = VaultData::new();
        vd.master_seed = [99u8; 32];
        let enc = encrypt_vault_data(&vd, &key, salt, nonce, tier).unwrap();
        let vault = Vault {
            version: enc.version,
            created_at: enc.created_at.clone(),
            tier: enc.tier,
            fingerprint: enc.fingerprint.clone(),
            salt: enc.salt,
            nonce: enc.nonce,
            ciphertext: enc.ciphertext,
        };
        let path = dir.join("secrets.vault");
        std::fs::write(&path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();
        (path, passphrase.to_string())
    }

    fn shard_dir(dir: &std::path::Path, threshold: u8, total: u8) -> (PathBuf, String) {
        let (vault_path, passphrase) = build_vault(dir);
        let args = ShardArgs {
            key: "master".to_string(),
            threshold,
            shares: total,
        };
        cmd_shard(args, &vault_path, &passphrase).unwrap();
        (vault_path, passphrase)
    }

    fn share_paths(dir: &std::path::Path, n: u8) -> Vec<PathBuf> {
        (1..=n)
            .map(|i| dir.join("shares").join(format!("share_{:03}.json", i)))
            .collect()
    }

    #[test]
    fn test_recover_from_threshold_shares() {
        let dir = tempdir().unwrap();
        shard_dir(dir.path(), 3, 5);

        let args = RecoverArgs {
            shares: share_paths(dir.path(), 3),
            out: None,
            vault_out: None,
            tier: "standard".to_string(),
        };
        let recovered = cmd_recover(args, "new-pass").unwrap();
        assert_eq!(recovered, vec![99u8; 32]); // build_vault uses [99;32] as master seed
    }

    #[test]
    fn test_recover_insufficient_shares() {
        let dir = tempdir().unwrap();
        shard_dir(dir.path(), 3, 5);

        let args = RecoverArgs {
            shares: share_paths(dir.path(), 2),
            out: None,
            vault_out: None,
            tier: "standard".to_string(),
        };
        let result = cmd_recover(args, "new-pass");
        assert!(matches!(
            result,
            Err(Error::InsufficientShares { needed: 3, provided: 2 })
        ));
    }

    #[test]
    fn test_recover_writes_to_out_file() {
        let dir = tempdir().unwrap();
        shard_dir(dir.path(), 2, 4);

        let out = dir.path().join("recovered.txt");
        let args = RecoverArgs {
            shares: share_paths(dir.path(), 2),
            out: Some(out.clone()),
            vault_out: None,
            tier: "standard".to_string(),
        };
        let recovered = cmd_recover(args, "new-pass").unwrap();
        let written = std::fs::read_to_string(&out).unwrap();
        assert_eq!(written, hex::encode(&recovered));
    }

    #[test]
    fn test_recover_rebuilds_vault() {
        let dir = tempdir().unwrap();
        shard_dir(dir.path(), 3, 5);

        let vault_out = dir.path().join("recovered.vault");
        let args = RecoverArgs {
            shares: share_paths(dir.path(), 3),
            out: None,
            vault_out: Some(vault_out.clone()),
            tier: "sovereign".to_string(),
        };
        let recovered = cmd_recover(args, "rebuilt-passphrase").unwrap();
        assert_eq!(recovered, vec![99u8; 32]);

        // The rebuilt vault must decrypt and yield the same master seed.
        let raw = std::fs::read_to_string(&vault_out).unwrap();
        let vault: Vault = serde_json::from_str(&raw).unwrap();
        assert_eq!(vault.tier, MemoryTier::Sovereign);
        let key = derive_vault_key(
            "rebuilt-passphrase".as_bytes(),
            &vault.salt,
            MemoryTier::Sovereign,
        )
        .unwrap();
        let enc = crate::crypto::EncryptedVault {
            version: vault.version,
            created_at: vault.created_at.clone(),
            tier: vault.tier,
            fingerprint: vault.fingerprint.clone(),
            salt: vault.salt,
            nonce: vault.nonce,
            ciphertext: vault.ciphertext,
        };
        let vd = decrypt_vault_data(&enc, &key).unwrap();
        assert_eq!(vd.master_seed, [99u8; 32]);
    }

    #[test]
    fn test_recover_wrong_tier_string() {
        let dir = tempdir().unwrap();
        shard_dir(dir.path(), 2, 4);

        let args = RecoverArgs {
            shares: share_paths(dir.path(), 2),
            out: None,
            vault_out: Some(dir.path().join("x.vault")),
            tier: "bogus".to_string(),
        };
        // Only fails because of the bad tier (seed recovery itself would succeed).
        let result = cmd_recover(args, "p");
        assert!(result.is_err());
    }

    #[test]
    fn test_recover_rejects_tampered_share() {
        let dir = tempdir().unwrap();
        shard_dir(dir.path(), 2, 4);

        // Load share 1, flip a byte in its data, rewrite it.
        let p = dir.path().join("shares").join("share_001.json");
        let mut share: Share = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        share.share_data[0] ^= 0xFF;
        std::fs::write(&p, serde_json::to_string_pretty(&share).unwrap()).unwrap();

        let args = RecoverArgs {
            shares: share_paths(dir.path(), 2),
            out: None,
            vault_out: None,
            tier: "standard".to_string(),
        };
        let result = cmd_recover(args, "new-pass");
        assert!(matches!(
            result,
            Err(Error::ShareVerificationFailed { share_number: 1, .. })
        ));
    }

    #[test]
    fn test_recover_no_shares() {
        let args = RecoverArgs {
            shares: vec![],
            out: None,
            vault_out: None,
            tier: "standard".to_string(),
        };
        let result = cmd_recover(args, "new-pass");
        assert!(matches!(
            result,
            Err(Error::InsufficientShares { needed: 1, provided: 0 })
        ));
    }
}
