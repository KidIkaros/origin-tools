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
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| format!("invalid hex seed: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("seed must be 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    };
    Ok(SeedHandle::new(&seed, None))
}

fn cmd_master(args: MasterArgs) -> Result<(), String> {
    let handle = resolve_seed_handle(&args.seed, args.identity, &args.passphrase_file)?;
    let master = stealth::kdf::derive_stealth_master(&handle)
        .map_err(|e| format!("derivation failed: {e}"))?;

    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "viewing": hex::encode(&master.viewing),
        "spending": hex::encode(&master.spending),
        "ephemeral": hex::encode(&master.ephemeral),
    })).unwrap());
    Ok(())
}

fn cmd_address(args: AddressArgs) -> Result<(), String> {
    let handle = resolve_seed_handle(&args.seed, args.identity, &args.passphrase_file)?;
    let addr = stealth::kdf::derive_stealth_from_seed(&handle, args.index)
        .map_err(|e| format!("address derivation failed: {e}"))?;

    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "index": args.index,
        "viewing_secret": hex::encode(&addr.viewing_secret),
        "spending_secret": hex::encode(&addr.spending_secret),
        "ephemeral_secret": hex::encode(&addr.ephemeral_secret),
    })).unwrap());
    Ok(())
}

fn cmd_solve(args: SolveArgs) -> Result<(), String> {
    let handle = resolve_seed_handle(&args.seed, args.identity, &args.passphrase_file)?;
    let seed_bytes = handle.as_bytes().ok_or("seed expired")?;

    // Derive identity public key from seed
    let pk = origin_crypto_sdk::sha3_256(seed_bytes);
    let dest_hint = args.index.to_le_bytes();

    let (proof, iterations) = stealth::pow::solve(&pk, &dest_hint, args.difficulty)
        .map_err(|e| format!("PoW solve failed: {e}"))?;

    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "index": args.index,
        "difficulty": args.difficulty,
        "iterations": iterations,
        "nonce": hex::encode(&proof.nonce),
        "counter": proof.counter,
    })).unwrap());
    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<(), String> {
    let content = std::fs::read_to_string(&args.proof)
        .map_err(|e| format!("cannot read '{}': {e}", args.proof))?;
    let proof_json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("cannot parse proof: {e}"))?;

    let nonce_hex = proof_json["nonce"].as_str().unwrap_or("");
    let nonce = hex::decode(nonce_hex).map_err(|e| format!("invalid nonce: {e}"))?;

    // Reconstruct the hash to verify
    let mut input = Vec::new();
    input.extend_from_slice(&nonce);
    input.extend_from_slice(&args.index.to_le_bytes());
    let hash = origin_crypto_sdk::sha3_256(&input);

    let mut zero_bits = 0u32;
    for &byte in &hash {
        if byte == 0 {
            zero_bits += 8;
        } else {
            zero_bits += byte.leading_zeros();
            break;
        }
    }

    if zero_bits >= args.difficulty {
        println!("VALID (difficulty={}, leading_zeros={})", args.difficulty, zero_bits);
        Ok(())
    } else {
        println!("INVALID (need {} zero bits, found {})", args.difficulty, zero_bits);
        std::process::exit(1);
    }
}
