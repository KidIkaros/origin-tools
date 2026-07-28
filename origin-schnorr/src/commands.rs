// SPDX-License-Identifier: Apache-2.0

use origin_common::{read_input, resolve_passphrase};
use origin_crypto_sdk::ec_schnorr;

use crate::cli::{Commands, KeygenArgs, ProveArgs, VerifyArgs};

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Keygen(args) => cmd_keygen(args),
        Commands::Prove(args) => cmd_prove(args),
        Commands::Verify(args) => cmd_verify(args),
    }
}

fn resolve_seed(
    seed_hex: &Option<String>,
    identity: bool,
    passphrase_file: &Option<String>,
) -> Result<[u8; 32], String> {
    if identity {
        let home = origin_common::OriginHome::load()?;
        let passphrase = resolve_passphrase(passphrase_file.as_deref())?;
        let store = origin_common::IdentityStore::load(&home, &passphrase)?;
        Ok(*store.seed_bytes())
    } else {
        let hex_str = seed_hex.as_ref().ok_or("--seed or --identity required")?;
        let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("invalid hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("seed must be 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

fn cmd_keygen(args: KeygenArgs) -> Result<(), String> {
    let seed = resolve_seed(&args.seed, args.identity, &args.passphrase_file)?;
    let (secret, public) = ec_schnorr::generate_keypair(&seed);

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "secret_key": hex::encode(&secret),
            "public_key": hex::encode(&public),
        }))
        .unwrap()
    );
    Ok(())
}

fn cmd_prove(args: ProveArgs) -> Result<(), String> {
    let message = read_input(args.input.as_deref())?;

    let (secret, public) = if args.identity {
        let seed = resolve_seed(&None, true, &args.passphrase_file)?;
        ec_schnorr::generate_keypair(&seed)
    } else {
        let secret_hex = args
            .secret
            .as_ref()
            .ok_or("--secret or --identity required")?;
        let secret_bytes =
            hex::decode(secret_hex.trim()).map_err(|e| format!("invalid secret: {e}"))?;
        if secret_bytes.len() != 32 {
            return Err("secret must be 32 bytes".to_string());
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);
        let public_hex = args
            .public
            .as_ref()
            .ok_or("--public required with --secret")?;
        let public = hex::decode(public_hex.trim()).map_err(|e| format!("invalid public: {e}"))?;
        (secret, public)
    };

    let proof = ec_schnorr::prove(&secret, &public, &message)
        .map_err(|e| format!("proof generation failed: {e}"))?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "commitment": hex::encode(&proof.commitment),
            "response": hex::encode(&proof.response),
            "public_key": hex::encode(&public),
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

    let commitment = hex::decode(proof_json["commitment"].as_str().unwrap_or(""))
        .map_err(|e| format!("invalid commitment: {e}"))?;
    let response = hex::decode(proof_json["response"].as_str().unwrap_or(""))
        .map_err(|e| format!("invalid response: {e}"))?;
    let public = hex::decode(args.public.trim())
        .map_err(|e| format!("invalid public key: {e}"))?;
    let message = hex::decode(args.message.trim())
        .map_err(|e| format!("invalid message: {e}"))?;

    let proof = ec_schnorr::EcSchnorrProof {
        commitment,
        response,
    };

    match ec_schnorr::verify(&proof, &public, &message) {
        Ok(true) => {
            println!("VALID");
            Ok(())
        }
        Ok(false) => {
            println!("INVALID");
            std::process::exit(1);
        }
        Err(e) => Err(format!("verification error: {e}")),
    }
}
