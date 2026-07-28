// SPDX-License-Identifier: Apache-2.0

use origin_common::{resolve_passphrase, tier_from_str};
use origin_crypto_sdk::blob::{create_blob, recover_seed};

use crate::cli::{
    BlobCreateArgs, BlobRecoverArgs, Commands, DecodeArgs, DeriveArgs, EncodeArgs, GenerateArgs,
};

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Generate(args) => cmd_generate(args),
        Commands::Derive(args) => cmd_derive(args),
        Commands::Encode(args) => cmd_encode(args),
        Commands::Decode(args) => cmd_decode(args),
        Commands::BlobCreate(args) => cmd_blob_create(args),
        Commands::BlobRecover(args) => cmd_blob_recover(args),
    }
}

fn cmd_generate(args: GenerateArgs) -> Result<(), String> {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    output_seed(&seed, &args.format)
}

fn cmd_derive(args: DeriveArgs) -> Result<(), String> {
    let parent_seed = if args.identity {
        let home = origin_common::OriginHome::load()?;
        let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;
        let store = origin_common::IdentityStore::load(&home, &passphrase)?;
        store.seed_bytes().to_vec()
    } else {
        let hex_seed = args.seed.as_ref().ok_or("--seed or --identity required")?;
        let bytes = hex::decode(hex_seed.trim()).map_err(|e| format!("invalid hex seed: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("seed must be 32 bytes, got {}", bytes.len()));
        }
        bytes
    };

    let child = origin_crypto_sdk::derive_child_seed(&parent_seed, &args.domain)
        .map_err(|e| format!("derivation failed: {e}"))?;

    println!("{}", hex::encode(&child));
    Ok(())
}

fn cmd_encode(args: EncodeArgs) -> Result<(), String> {
    let bytes = hex::decode(args.seed.trim()).map_err(|e| format!("invalid hex seed: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("seed must be 32 bytes, got {}", bytes.len()));
    }
    match args.format.as_str() {
        "hex" => println!("{}", hex::encode(&bytes)),
        _ => return Err(format!("unknown format: {} (use hex)", args.format)),
    }
    Ok(())
}

fn cmd_decode(args: DecodeArgs) -> Result<(), String> {
    let bytes = match args.format.as_str() {
        "hex" => hex::decode(args.input.trim()).map_err(|e| format!("invalid hex: {e}"))?,
        _ => return Err(format!("unknown format: {} (use hex)", args.format)),
    };
    if bytes.len() != 32 {
        return Err(format!(
            "decoded seed must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    println!("{}", hex::encode(&bytes));
    Ok(())
}

fn cmd_blob_create(args: BlobCreateArgs) -> Result<(), String> {
    let tier = tier_from_str(&args.tier)?;
    let seed_bytes = hex::decode(args.seed.trim()).map_err(|e| format!("invalid hex seed: {e}"))?;
    if seed_bytes.len() != 32 {
        return Err(format!("seed must be 32 bytes, got {}", seed_bytes.len()));
    }
    let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let blob = create_blob(passphrase.as_bytes(), tier, Some(&seed))
        .map_err(|e| format!("blob creation failed: {e:?}"))?;

    std::fs::write(&args.output, &blob)
        .map_err(|e| format!("cannot write '{}': {e}", args.output))?;
    eprintln!(
        "encrypted seed blob written to {} ({} bytes)",
        args.output,
        blob.len()
    );
    Ok(())
}

fn cmd_blob_recover(args: BlobRecoverArgs) -> Result<(), String> {
    let tier = tier_from_str(&args.tier)?;
    let blob =
        std::fs::read(&args.input).map_err(|e| format!("cannot read '{}': {e}", args.input))?;
    let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;

    let seed = recover_seed(&blob, passphrase.as_bytes(), tier)
        .map_err(|_| "blob decryption failed (wrong passphrase or corrupt)".to_string())?;

    println!("{}", hex::encode(seed));
    Ok(())
}

fn output_seed(seed: &[u8], format: &str) -> Result<(), String> {
    match format {
        "hex" => println!("{}", hex::encode(seed)),
        "raw" => {
            use std::io::Write;
            std::io::stdout()
                .write_all(seed)
                .map_err(|e| format!("stdout: {e}"))?;
        }
        _ => return Err(format!("unknown format: {format} (use hex or raw)")),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use origin_crypto_sdk::blob::{create_blob, recover_seed};
    use origin_crypto_sdk::tier::MemoryTier;

    fn test_seed() -> [u8; 32] {
        [0x42u8; 32]
    }

    // --- Derive tests ---

    #[test]
    fn derive_child_deterministic() {
        let parent = test_seed();
        let c1 = origin_crypto_sdk::derive_child_seed(&parent, "domain-a").unwrap();
        let c2 = origin_crypto_sdk::derive_child_seed(&parent, "domain-a").unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn derive_child_different_domains() {
        let parent = test_seed();
        let c1 = origin_crypto_sdk::derive_child_seed(&parent, "domain-a").unwrap();
        let c2 = origin_crypto_sdk::derive_child_seed(&parent, "domain-b").unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn derive_child_different_parents() {
        let p1 = [1u8; 32];
        let p2 = [2u8; 32];
        let c1 = origin_crypto_sdk::derive_child_seed(&p1, "same").unwrap();
        let c2 = origin_crypto_sdk::derive_child_seed(&p2, "same").unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn derive_child_differs_from_parent() {
        let parent = test_seed();
        let child = origin_crypto_sdk::derive_child_seed(&parent, "child").unwrap();
        assert_ne!(child, parent);
    }

    #[test]
    fn derive_child_empty_domain_rejected() {
        let parent = test_seed();
        // Empty domain is rejected by the SDK
        let result = origin_crypto_sdk::derive_child_seed(&parent, "");
        assert!(result.is_err());
    }

    #[test]
    fn derive_child_long_domain() {
        let parent = test_seed();
        let long_domain = "a".repeat(1000);
        let child = origin_crypto_sdk::derive_child_seed(&parent, &long_domain).unwrap();
        assert_ne!(child, parent);
    }

    // --- Encode/decode tests ---

    #[test]
    fn hex_roundtrip() {
        let seed = test_seed();
        let encoded = hex::encode(seed);
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, seed);
    }

    #[test]
    fn invalid_hex_rejected() {
        assert!(hex::decode("not-hex-at-all").is_err());
        assert!(hex::decode("0x42").is_err()); // 0x prefix not valid
        assert!(hex::decode("GG").is_err());
    }

    #[test]
    fn wrong_length_rejected() {
        // 16 bytes instead of 32
        let short = hex::encode([0u8; 16]);
        let decoded = hex::decode(&short).unwrap();
        assert_ne!(decoded.len(), 32);
    }

    // --- Blob create/recover tests ---

    #[test]
    fn blob_create_recover_roundtrip() {
        let seed = test_seed();
        let passphrase = b"test-passphrase-for-blob";
        let tier = MemoryTier::Standard;

        let blob = create_blob(passphrase, tier, Some(&seed)).unwrap();
        assert!(!blob.is_empty());

        let recovered = recover_seed(&blob, passphrase, tier).unwrap();
        assert_eq!(recovered, seed);
    }

    #[test]
    fn blob_wrong_passphrase_fails() {
        let seed = test_seed();
        let tier = MemoryTier::Standard;

        let blob = create_blob(b"correct-pass", tier, Some(&seed)).unwrap();
        let result = recover_seed(&blob, b"wrong-pass", tier);
        assert!(result.is_err());
    }

    #[test]
    fn blob_corrupt_data_fails() {
        let seed = test_seed();
        let tier = MemoryTier::Standard;

        let mut blob = create_blob(b"pass", tier, Some(&seed)).unwrap();
        // Corrupt a byte in the middle
        if blob.len() > 50 {
            blob[50] ^= 0xFF;
        }
        let result = recover_seed(&blob, b"pass", tier);
        assert!(result.is_err());
    }

    #[test]
    fn blob_truncated_fails() {
        let seed = test_seed();
        let tier = MemoryTier::Standard;

        let blob = create_blob(b"pass", tier, Some(&seed)).unwrap();
        let truncated = &blob[..blob.len() / 2];
        let result = recover_seed(truncated, b"pass", tier);
        assert!(result.is_err());
    }

    #[test]
    fn blob_empty_fails() {
        let result = recover_seed(&[], b"pass", MemoryTier::Standard);
        assert!(result.is_err());
    }

    #[test]
    fn blob_deterministic_with_same_seed() {
        let seed = test_seed();
        let pass = b"same-pass";
        let tier = MemoryTier::Standard;

        let b1 = create_blob(pass, tier, Some(&seed)).unwrap();
        let b2 = create_blob(pass, tier, Some(&seed)).unwrap();
        // Blobs use random salt/nonce, so they should differ
        assert_ne!(b1, b2);
        // But both recover the same seed
        assert_eq!(recover_seed(&b1, pass, tier).unwrap(), seed);
        assert_eq!(recover_seed(&b2, pass, tier).unwrap(), seed);
    }

    #[test]
    fn blob_different_seeds_different_blobs() {
        let pass = b"pass";
        let tier = MemoryTier::Standard;

        let b1 = create_blob(pass, tier, Some(&[1u8; 32])).unwrap();
        let b2 = create_blob(pass, tier, Some(&[2u8; 32])).unwrap();

        let r1 = recover_seed(&b1, pass, tier).unwrap();
        let r2 = recover_seed(&b2, pass, tier).unwrap();
        assert_ne!(r1, r2);
    }

    // --- Generate tests ---

    #[test]
    fn generate_produces_32_bytes() {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        // Extremely unlikely to be all zeros
        assert!(seed.iter().any(|&b| b != 0));
    }

    #[test]
    fn generate_two_seeds_differ() {
        let mut s1 = [0u8; 32];
        let mut s2 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut s1);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut s2);
        assert_ne!(s1, s2);
    }
}
