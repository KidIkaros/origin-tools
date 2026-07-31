//! Recover command — reconstruct a vault master seed from K threshold shares.

use crate::cli::RecoverArgs;
use crate::error::Error;
use crate::share::{HybridSignature, Share};
use origin_crypto_sdk::error_correction::ReedSolomonCodec;
use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle};

/// Domain separation label — must match `shard`.
const SHARE_SIGNING_DOMAIN: &str = "origin-secrets/share/v1";

/// Recover the 32-byte master seed from a set of share files.
///
/// At least `threshold` shares (as recorded in each share) must be supplied.
/// The first `threshold` shares are used for erasure decoding; every supplied
/// share's hybrid (Ed25519 + Falcon-1024) signature is verified against the
/// key bundle derived from the recovered seed, rejecting tampered shares.
pub fn cmd_recover(args: RecoverArgs) -> Result<Vec<u8>, Error> {
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
    let signer = HybridSigningKeyBundle::from_seed(seed, SHARE_SIGNING_DOMAIN)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::shard::cmd_shard;
    use crate::cli::ShardArgs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn build_vault(dir: &std::path::Path) -> (PathBuf, String) {
        use crate::crypto::{encrypt_vault_data, VaultData};
        use crate::vault::{MemoryTier, Vault};

        let passphrase = "recover-passphrase-test";
        let salt = [7u8; 16];
        let nonce = [8u8; 24];
        let tier = MemoryTier::Standard;
        let key = crate::crypto::derive_vault_key(passphrase.as_bytes(), &salt, tier).unwrap();
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

    #[test]
    fn test_recover_from_threshold_shares() {
        let dir = tempdir().unwrap();
        shard_dir(dir.path(), 3, 5);

        let shares: Vec<PathBuf> = (1..=3)
            .map(|n| dir.path().join("shares").join(format!("share_{:03}.json", n)))
            .collect();
        let args = RecoverArgs {
            shares,
            out: None,
        };
        let recovered = cmd_recover(args).unwrap();
        assert_eq!(recovered, vec![99u8; 32]); // build_vault uses [99;32] as master seed
    }

    #[test]
    fn test_recover_insufficient_shares() {
        let dir = tempdir().unwrap();
        shard_dir(dir.path(), 3, 5);

        let shares: Vec<PathBuf> = (1..=2)
            .map(|n| dir.path().join("shares").join(format!("share_{:03}.json", n)))
            .collect();
        let args = RecoverArgs {
            shares,
            out: None,
        };
        let result = cmd_recover(args);
        assert!(matches!(
            result,
            Err(Error::InsufficientShares { needed: 3, provided: 2 })
        ));
    }

    #[test]
    fn test_recover_writes_to_out_file() {
        let dir = tempdir().unwrap();
        shard_dir(dir.path(), 2, 4);

        let shares: Vec<PathBuf> = (1..=2)
            .map(|n| dir.path().join("shares").join(format!("share_{:03}.json", n)))
            .collect();
        let out = dir.path().join("recovered.txt");
        let args = RecoverArgs {
            shares,
            out: Some(out.clone()),
        };
        let recovered = cmd_recover(args).unwrap();
        let written = std::fs::read_to_string(&out).unwrap();
        assert_eq!(written, hex::encode(&recovered));
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

        let shares: Vec<PathBuf> = (1..=2)
            .map(|n| dir.path().join("shares").join(format!("share_{:03}.json", n)))
            .collect();
        let args = RecoverArgs {
            shares,
            out: None,
        };
        let result = cmd_recover(args);
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
        };
        let result = cmd_recover(args);
        assert!(matches!(
            result,
            Err(Error::InsufficientShares { needed: 1, provided: 0 })
        ));
    }
}
