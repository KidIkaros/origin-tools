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
        let bytes = hex::decode(hex_seed.trim())
            .map_err(|e| format!("invalid hex seed: {e}"))?;
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
    let bytes = hex::decode(args.seed.trim())
        .map_err(|e| format!("invalid hex seed: {e}"))?;
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
        "hex" => hex::decode(args.input.trim())
            .map_err(|e| format!("invalid hex: {e}"))?,
        _ => return Err(format!("unknown format: {} (use hex)", args.format)),
    };
    if bytes.len() != 32 {
        return Err(format!("decoded seed must be 32 bytes, got {}", bytes.len()));
    }
    println!("{}", hex::encode(&bytes));
    Ok(())
}

fn cmd_blob_create(args: BlobCreateArgs) -> Result<(), String> {
    let tier = tier_from_str(&args.tier)?;
    let seed_bytes = hex::decode(args.seed.trim())
        .map_err(|e| format!("invalid hex seed: {e}"))?;
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
    eprintln!("encrypted seed blob written to {} ({} bytes)", args.output, blob.len());
    Ok(())
}

fn cmd_blob_recover(args: BlobRecoverArgs) -> Result<(), String> {
    let tier = tier_from_str(&args.tier)?;
    let blob = std::fs::read(&args.input)
        .map_err(|e| format!("cannot read '{}': {e}", args.input))?;
    let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;

    let seed = recover_seed(&blob, passphrase.as_bytes(), tier)
        .map_err(|_| "blob decryption failed (wrong passphrase or corrupt)".to_string())?;

    println!("{}", hex::encode(&seed));
    Ok(())
}

fn output_seed(seed: &[u8], format: &str) -> Result<(), String> {
    match format {
        "hex" => println!("{}", hex::encode(seed)),
        "raw" => {
            use std::io::Write;
            std::io::stdout().write_all(seed).map_err(|e| format!("stdout: {e}"))?;
        }
        _ => return Err(format!("unknown format: {format} (use hex or raw)")),
    }
    Ok(())
}
