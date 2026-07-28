// SPDX-License-Identifier: Apache-2.0

use origin_common::resolve_passphrase;
use origin_crypto_sdk::seed::SeedHandle;
use origin_crypto_sdk::stealth;

use crate::cli::{AddressArgs, Commands, MasterArgs, SolveArgs, VerifyArgs};

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Master(args) => cmd_master(args),
        Commands::Address(args) => cmd_address(args),
        Commands::Solve(args) => cmd_solve(args),
        Commands::Verify(args) => cmd_verify(args),
    }
}

fn resolve_seed_handle(
    seed_hex: &Option<String>,
    identity: bool,
    passphrase_file: &Option<String>,
) -> Result<SeedHandle, String> {
    let seed = if identity {
        let home = origin_common::OriginHome::load()?;
        let passphrase = resolve_passphrase(passphrase_file.as_deref())?;
        let store = origin_common::IdentityStore::load(&home, &passphrase)?;
        *store.seed_bytes()
    } else {
        let hex_str = seed_hex.as_ref().ok_or("--seed or --identity required")?;
        let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("invalid hex seed: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("seed must be 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    };
    Ok(SeedHandle::new(&seed, None))
}

/// Derive the identity public key from a seed (SHA3-256 of seed bytes).
/// This must match the derivation used in cmd_solve for PoW binding.
fn identity_pk_from_seed(seed_bytes: &[u8]) -> [u8; 32] {
    origin_crypto_sdk::sha3_256(seed_bytes)
}

fn cmd_master(args: MasterArgs) -> Result<(), String> {
    let handle = resolve_seed_handle(&args.seed, args.identity, &args.passphrase_file)?;
    let master = stealth::kdf::derive_stealth_master(&handle)
        .map_err(|e| format!("derivation failed: {e}"))?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "viewing": hex::encode(master.viewing),
            "spending": hex::encode(master.spending),
            "ephemeral": hex::encode(master.ephemeral),
        }))
        .unwrap()
    );
    Ok(())
}

fn cmd_address(args: AddressArgs) -> Result<(), String> {
    let handle = resolve_seed_handle(&args.seed, args.identity, &args.passphrase_file)?;
    let addr = stealth::kdf::derive_stealth_from_seed(&handle, args.index)
        .map_err(|e| format!("address derivation failed: {e}"))?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "index": args.index,
            "viewing_secret": hex::encode(addr.viewing_secret),
            "spending_secret": hex::encode(addr.spending_secret),
            "ephemeral_secret": hex::encode(addr.ephemeral_secret),
        }))
        .unwrap()
    );
    Ok(())
}

fn cmd_solve(args: SolveArgs) -> Result<(), String> {
    let handle = resolve_seed_handle(&args.seed, args.identity, &args.passphrase_file)?;
    let seed_bytes = handle.as_bytes().ok_or("seed expired")?;

    // Derive identity public key from seed (deterministic binding)
    let pk = identity_pk_from_seed(seed_bytes);
    let dest_hint = args.index.to_le_bytes();

    let (proof, iterations) = stealth::pow::solve(&pk, &dest_hint, args.difficulty)
        .map_err(|e| format!("PoW solve failed: {e}"))?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "index": args.index,
            "difficulty": args.difficulty,
            "iterations": iterations,
            "nonce": hex::encode(proof.nonce),
            "extra": hex::encode(proof.extra),
            "counter": proof.counter,
            "identity_pk": hex::encode(pk),
        }))
        .unwrap()
    );
    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<(), String> {
    let content = std::fs::read_to_string(&args.proof)
        .map_err(|e| format!("cannot read '{}': {e}", args.proof))?;
    let proof_json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("cannot parse proof: {e}"))?;

    // Extract proof fields
    let nonce_hex = proof_json["nonce"]
        .as_str()
        .ok_or("proof missing 'nonce' field")?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| format!("invalid nonce hex: {e}"))?;
    if nonce_bytes.len() != 32 {
        return Err(format!("nonce must be 32 bytes, got {}", nonce_bytes.len()));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);

    let extra_hex = proof_json["extra"]
        .as_str()
        .ok_or("proof missing 'extra' field")?;
    let extra_bytes = hex::decode(extra_hex).map_err(|e| format!("invalid extra hex: {e}"))?;
    if extra_bytes.len() != 16 {
        return Err(format!("extra must be 16 bytes, got {}", extra_bytes.len()));
    }
    let mut extra = [0u8; 16];
    extra.copy_from_slice(&extra_bytes);

    let counter = proof_json["counter"]
        .as_u64()
        .ok_or("proof missing 'counter' field")?;
    let difficulty = proof_json["difficulty"]
        .as_u64()
        .ok_or("proof missing 'difficulty' field")? as u32;

    // Reconstruct identity_pk: either from the proof JSON or from --seed/--identity
    let identity_pk: [u8; 32] = if let Some(pk_hex) = proof_json["identity_pk"].as_str() {
        let pk_bytes = hex::decode(pk_hex).map_err(|e| format!("invalid identity_pk hex: {e}"))?;
        if pk_bytes.len() != 32 {
            return Err(format!(
                "identity_pk must be 32 bytes, got {}",
                pk_bytes.len()
            ));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);
        pk
    } else if args.seed.is_some() || args.identity {
        let handle = resolve_seed_handle(&args.seed, args.identity, &args.passphrase_file)?;
        let seed_bytes = handle.as_bytes().ok_or("seed expired")?;
        identity_pk_from_seed(seed_bytes)
    } else {
        return Err(
            "proof has no 'identity_pk' field; provide --seed or --identity to reconstruct it"
                .to_string(),
        );
    };

    let dest_hint = args.index.to_le_bytes();

    let proof = stealth::pow::StealthPowProof {
        nonce,
        extra,
        counter,
        difficulty,
    };

    let valid = stealth::pow::verify(&proof, &identity_pk, &dest_hint)
        .map_err(|e| format!("verification error: {e}"))?;

    if valid {
        println!("VALID (difficulty={}, counter={})", difficulty, counter);
        Ok(())
    } else {
        println!(
            "INVALID (difficulty={}, counter={} does not satisfy target)",
            difficulty, counter
        );
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use origin_crypto_sdk::seed::SeedHandle;
    use origin_crypto_sdk::stealth;

    fn test_seed() -> [u8; 32] {
        [0xABu8; 32]
    }

    #[test]
    fn master_derivation_deterministic() {
        let handle = SeedHandle::new(&test_seed(), None);
        let m1 = stealth::kdf::derive_stealth_master(&handle).unwrap();
        let m2 = stealth::kdf::derive_stealth_master(&handle).unwrap();
        assert_eq!(m1.viewing, m2.viewing);
        assert_eq!(m1.spending, m2.spending);
        assert_eq!(m1.ephemeral, m2.ephemeral);
    }

    #[test]
    fn master_keys_are_distinct() {
        let handle = SeedHandle::new(&test_seed(), None);
        let m = stealth::kdf::derive_stealth_master(&handle).unwrap();
        assert_ne!(m.viewing, m.spending);
        assert_ne!(m.viewing, m.ephemeral);
        assert_ne!(m.spending, m.ephemeral);
    }

    #[test]
    fn different_seeds_different_masters() {
        let h1 = SeedHandle::new(&[1u8; 32], None);
        let h2 = SeedHandle::new(&[2u8; 32], None);
        let m1 = stealth::kdf::derive_stealth_master(&h1).unwrap();
        let m2 = stealth::kdf::derive_stealth_master(&h2).unwrap();
        assert_ne!(m1.viewing, m2.viewing);
        assert_ne!(m1.spending, m2.spending);
    }

    #[test]
    fn address_derivation_deterministic() {
        let handle = SeedHandle::new(&test_seed(), None);
        let a1 = stealth::kdf::derive_stealth_from_seed(&handle, 7).unwrap();
        let a2 = stealth::kdf::derive_stealth_from_seed(&handle, 7).unwrap();
        assert_eq!(a1.viewing_secret, a2.viewing_secret);
        assert_eq!(a1.spending_secret, a2.spending_secret);
        assert_eq!(a1.ephemeral_secret, a2.ephemeral_secret);
    }

    #[test]
    fn different_indices_different_addresses() {
        let handle = SeedHandle::new(&test_seed(), None);
        let a0 = stealth::kdf::derive_stealth_from_seed(&handle, 0).unwrap();
        let a1 = stealth::kdf::derive_stealth_from_seed(&handle, 1).unwrap();
        let a_max = stealth::kdf::derive_stealth_from_seed(&handle, u64::MAX).unwrap();
        assert_ne!(a0.viewing_secret, a1.viewing_secret);
        assert_ne!(a1.viewing_secret, a_max.viewing_secret);
        assert_ne!(a0.spending_secret, a_max.spending_secret);
    }

    #[test]
    fn address_keys_within_index_are_distinct() {
        let handle = SeedHandle::new(&test_seed(), None);
        let a = stealth::kdf::derive_stealth_from_seed(&handle, 42).unwrap();
        assert_ne!(a.viewing_secret, a.spending_secret);
        assert_ne!(a.viewing_secret, a.ephemeral_secret);
        assert_ne!(a.spending_secret, a.ephemeral_secret);
    }

    #[test]
    fn pow_difficulty_zero_trivial() {
        let pk = [42u8; 32];
        let hint = b"test";
        let (proof, iterations) = stealth::pow::solve(&pk, hint, 0).unwrap();
        assert_eq!(iterations, 0);
        assert_eq!(proof.difficulty, 0);
        assert!(stealth::pow::verify(&proof, &pk, hint).unwrap());
    }

    #[test]
    fn pow_difficulty_too_high_rejected() {
        let pk = [42u8; 32];
        let hint = b"test";
        let result = stealth::pow::solve(&pk, hint, 33);
        assert!(result.is_err());
    }

    #[test]
    fn pow_solve_verify_roundtrip_low_difficulty() {
        let pk = identity_pk_from_seed(&test_seed());
        let hint = 5u64.to_le_bytes();
        let (proof, iterations) = stealth::pow::solve(&pk, &hint, 8).unwrap();
        assert!(iterations > 0);
        assert_eq!(proof.difficulty, 8);
        assert!(stealth::pow::verify(&proof, &pk, &hint).unwrap());
    }

    #[test]
    fn pow_solve_verify_roundtrip_medium_difficulty() {
        let pk = identity_pk_from_seed(&test_seed());
        let hint = 100u64.to_le_bytes();
        let (proof, _) = stealth::pow::solve(&pk, &hint, 16).unwrap();
        assert!(stealth::pow::verify(&proof, &pk, &hint).unwrap());
    }

    #[test]
    fn pow_wrong_identity_fails_verification() {
        let pk = identity_pk_from_seed(&test_seed());
        let wrong_pk = identity_pk_from_seed(&[0xCDu8; 32]);
        let hint = 1u64.to_le_bytes();
        let (proof, _) = stealth::pow::solve(&pk, &hint, 12).unwrap();
        assert!(!stealth::pow::verify(&proof, &wrong_pk, &hint).unwrap());
    }

    #[test]
    fn pow_wrong_index_fails_verification() {
        let pk = identity_pk_from_seed(&test_seed());
        let hint = 1u64.to_le_bytes();
        let wrong_hint = 2u64.to_le_bytes();
        let (proof, _) = stealth::pow::solve(&pk, &hint, 12).unwrap();
        assert!(!stealth::pow::verify(&proof, &pk, &wrong_hint).unwrap());
    }

    #[test]
    fn pow_tampered_nonce_fails() {
        let pk = identity_pk_from_seed(&test_seed());
        let hint = 3u64.to_le_bytes();
        let (mut proof, _) = stealth::pow::solve(&pk, &hint, 12).unwrap();
        proof.nonce[0] ^= 0xFF; // flip bits
        assert!(!stealth::pow::verify(&proof, &pk, &hint).unwrap());
    }

    #[test]
    fn pow_tampered_counter_fails() {
        let pk = identity_pk_from_seed(&test_seed());
        let hint = 4u64.to_le_bytes();
        let (mut proof, _) = stealth::pow::solve(&pk, &hint, 12).unwrap();
        proof.counter += 1;
        assert!(!stealth::pow::verify(&proof, &pk, &hint).unwrap());
    }

    #[test]
    fn pow_verify_rejects_difficulty_over_32() {
        let proof = stealth::pow::StealthPowProof {
            nonce: [0u8; 32],
            extra: [0u8; 16],
            counter: 0,
            difficulty: 33,
        };
        let result = stealth::pow::verify(&proof, &[1u8; 32], b"hint");
        // difficulty > 32 returns Ok(false)
        assert!(!result.unwrap());
    }

    #[test]
    fn identity_pk_deterministic() {
        let seed = test_seed();
        let pk1 = identity_pk_from_seed(&seed);
        let pk2 = identity_pk_from_seed(&seed);
        assert_eq!(pk1, pk2);
        // Different seed → different pk
        let pk3 = identity_pk_from_seed(&[0u8; 32]);
        assert_ne!(pk1, pk3);
    }

    #[test]
    fn effective_difficulty_capped() {
        let config = stealth::pow::StealthPowConfig {
            base_difficulty: 20,
            per_address_increment: 5,
            max_difficulty: 32,
        };
        // index 0 → 20
        assert_eq!(stealth::pow::effective_difficulty(&config, 0), 20);
        // index 1 → 25
        assert_eq!(stealth::pow::effective_difficulty(&config, 1), 25);
        // index 2 → 30
        assert_eq!(stealth::pow::effective_difficulty(&config, 2), 30);
        // index 3 → 35 → capped at 32
        assert_eq!(stealth::pow::effective_difficulty(&config, 3), 32);
        // index 100 → capped
        assert_eq!(stealth::pow::effective_difficulty(&config, 100), 32);
    }
}
