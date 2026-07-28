// SPDX-License-Identifier: Apache-2.0

use origin_common::{read_input, resolve_passphrase};
use origin_crypto_sdk::ec_schnorr;

use crate::cli::{BatchVerifyArgs, Commands, KeygenArgs, ProveArgs, VerifyArgs};

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Keygen(args) => cmd_keygen(args),
        Commands::Prove(args) => cmd_prove(args),
        Commands::Verify(args) => cmd_verify(args),
        Commands::BatchVerify(args) => cmd_batch_verify(args),
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
            "secret_key": hex::encode(secret),
            "public_key": hex::encode(&public),
        }))
        .unwrap()
    );
    Ok(())
}

fn cmd_prove(args: ProveArgs) -> Result<(), String> {
    let message = read_input(args.input.as_deref())?;

    let (secret, public) = if args.identity {
        let home = origin_common::OriginHome::load()?;
        let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;
        let store = origin_common::IdentityStore::load(&home, &passphrase)?;
        let derived = store.derive_key("origin-schnorr-ed25519", 32)?;
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&derived);
        ec_schnorr::generate_keypair(&sk)
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
    // When `--identity` is set, derive the Ed25519 public key from the suite
    // identity so verification needs only the proof + challenge (no exposed key).
    let public_hex = if args.identity {
        let home = origin_common::OriginHome::load()?;
        let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;
        let store = origin_common::IdentityStore::load(&home, &passphrase)?;
        let secret = store.derive_key("origin-schnorr-ed25519", 32)?;
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&secret);
        let (_s, pk) = origin_crypto_sdk::ec_schnorr::generate_keypair(&sk);
        hex::encode(pk)
    } else {
        args.public
            .clone()
            .ok_or("either --public or --identity is required")?
    };

    let content = std::fs::read_to_string(&args.proof)
        .map_err(|e| format!("cannot read '{}': {e}", args.proof))?;
    let proof_json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("cannot parse proof: {e}"))?;

    let commitment = hex::decode(proof_json["commitment"].as_str().unwrap_or(""))
        .map_err(|e| format!("invalid commitment: {e}"))?;
    let response = hex::decode(proof_json["response"].as_str().unwrap_or(""))
        .map_err(|e| format!("invalid response: {e}"))?;
    let public = hex::decode(public_hex.trim()).map_err(|e| format!("invalid public key: {e}"))?;
    let message = hex::decode(args.message.trim()).map_err(|e| format!("invalid message: {e}"))?;

    let proof = ec_schnorr::EcSchnorrProof {
        commitment,
        response,
    };

    match ec_schnorr::verify(&proof, &public, &message) {
        Ok(true) => {
            println!("OK");
            Ok(())
        }
        Ok(false) => {
            println!("INVALID");
            std::process::exit(1);
        }
        Err(e) => Err(format!("verification error: {e}")),
    }
}

fn cmd_batch_verify(args: BatchVerifyArgs) -> Result<(), String> {
    let content = std::fs::read_to_string(&args.input)
        .map_err(|e| format!("cannot read '{}': {e}", args.input))?;
    let items: Vec<serde_json::Value> =
        serde_json::from_str(&content).map_err(|e| format!("cannot parse JSON array: {e}"))?;

    if items.is_empty() {
        return Err("input array is empty".to_string());
    }

    let mut proofs = Vec::with_capacity(items.len());
    let mut public_keys = Vec::with_capacity(items.len());
    let mut messages = Vec::with_capacity(items.len());

    for (i, item) in items.iter().enumerate() {
        let commitment = hex::decode(
            item["proof"]["commitment"]
                .as_str()
                .ok_or(format!("item {i}: missing proof.commitment"))?,
        )
        .map_err(|e| format!("item {i}: invalid commitment hex: {e}"))?;

        let response = hex::decode(
            item["proof"]["response"]
                .as_str()
                .ok_or(format!("item {i}: missing proof.response"))?,
        )
        .map_err(|e| format!("item {i}: invalid response hex: {e}"))?;

        let pk = hex::decode(
            item["public_key"]
                .as_str()
                .ok_or(format!("item {i}: missing public_key"))?,
        )
        .map_err(|e| format!("item {i}: invalid public_key hex: {e}"))?;

        let msg = hex::decode(
            item["message"]
                .as_str()
                .ok_or(format!("item {i}: missing message"))?,
        )
        .map_err(|e| format!("item {i}: invalid message hex: {e}"))?;

        proofs.push(ec_schnorr::EcSchnorrProof {
            commitment,
            response,
        });
        public_keys.push(pk);
        messages.push(msg);
    }

    match ec_schnorr::batch_verify(&proofs, &public_keys, &messages) {
        Ok(true) => {
            println!("ALL {} PROOFS VALID", proofs.len());
            Ok(())
        }
        Ok(false) => {
            println!("BATCH VERIFICATION FAILED");
            std::process::exit(1);
        }
        Err(e) => Err(format!("batch verification error: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed_byte: u8) -> ([u8; 32], Vec<u8>) {
        ec_schnorr::generate_keypair(&[seed_byte; 32])
    }

    // --- Keygen tests ---

    #[test]
    fn keygen_deterministic() {
        let (sk1, pk1) = keypair(42);
        let (sk2, pk2) = keypair(42);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn keygen_different_seeds() {
        let (sk1, pk1) = keypair(1);
        let (sk2, pk2) = keypair(2);
        assert_ne!(sk1, sk2);
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn keygen_public_key_is_33_bytes() {
        let (_, pk) = keypair(7);
        assert_eq!(pk.len(), 33); // compressed SEC1
    }

    // --- Prove/verify roundtrip ---

    #[test]
    fn prove_verify_roundtrip() {
        let (sk, pk) = keypair(42);
        let msg = b"hello world";
        let proof = ec_schnorr::prove(&sk, &pk, msg).unwrap();
        assert!(ec_schnorr::verify(&proof, &pk, msg).unwrap());
    }

    #[test]
    fn verify_wrong_message_fails() {
        let (sk, pk) = keypair(42);
        let proof = ec_schnorr::prove(&sk, &pk, b"original").unwrap();
        assert!(!ec_schnorr::verify(&proof, &pk, b"tampered").unwrap());
    }

    #[test]
    fn verify_wrong_key_fails() {
        let (sk1, pk1) = keypair(1);
        let (_, pk2) = keypair(2);
        let proof = ec_schnorr::prove(&sk1, &pk1, b"msg").unwrap();
        assert!(!ec_schnorr::verify(&proof, &pk2, b"msg").unwrap());
    }

    #[test]
    fn verify_empty_message() {
        let (sk, pk) = keypair(42);
        let proof = ec_schnorr::prove(&sk, &pk, b"").unwrap();
        assert!(ec_schnorr::verify(&proof, &pk, b"").unwrap());
    }

    #[test]
    fn verify_large_message() {
        let (sk, pk) = keypair(42);
        let msg = vec![0xCDu8; 100_000];
        let proof = ec_schnorr::prove(&sk, &pk, &msg).unwrap();
        assert!(ec_schnorr::verify(&proof, &pk, &msg).unwrap());
    }

    // --- Proof structure ---

    #[test]
    fn proof_commitment_is_33_bytes() {
        let (sk, pk) = keypair(42);
        let proof = ec_schnorr::prove(&sk, &pk, b"test").unwrap();
        assert_eq!(proof.commitment.len(), 33);
    }

    #[test]
    fn proof_response_is_32_bytes() {
        let (sk, pk) = keypair(42);
        let proof = ec_schnorr::prove(&sk, &pk, b"test").unwrap();
        assert_eq!(proof.response.len(), 32);
    }

    #[test]
    fn proofs_are_randomized() {
        let (sk, pk) = keypair(42);
        let p1 = ec_schnorr::prove(&sk, &pk, b"same").unwrap();
        let p2 = ec_schnorr::prove(&sk, &pk, b"same").unwrap();
        // Random nonce means different commitments
        assert_ne!(p1.commitment, p2.commitment);
        // But both verify
        assert!(ec_schnorr::verify(&p1, &pk, b"same").unwrap());
        assert!(ec_schnorr::verify(&p2, &pk, b"same").unwrap());
    }

    // --- Tampered proof ---

    #[test]
    fn tampered_commitment_fails() {
        let (sk, pk) = keypair(42);
        let mut proof = ec_schnorr::prove(&sk, &pk, b"msg").unwrap();
        proof.commitment[0] ^= 0xFF;
        // Should either fail verification or return an error
        let result = ec_schnorr::verify(&proof, &pk, b"msg");
        if let Ok(valid) = result {
            assert!(!valid);
        }
    }

    #[test]
    fn tampered_response_fails() {
        let (sk, pk) = keypair(42);
        let mut proof = ec_schnorr::prove(&sk, &pk, b"msg").unwrap();
        proof.response[15] ^= 0x01;
        let result = ec_schnorr::verify(&proof, &pk, b"msg");
        if let Ok(valid) = result {
            assert!(!valid);
        }
    }

    #[test]
    fn truncated_response_fails() {
        let (sk, pk) = keypair(42);
        let mut proof = ec_schnorr::prove(&sk, &pk, b"msg").unwrap();
        proof.response.truncate(16);
        assert!(ec_schnorr::verify(&proof, &pk, b"msg").is_err());
    }

    #[test]
    fn empty_commitment_fails() {
        let (_, pk) = keypair(42);
        let proof = ec_schnorr::EcSchnorrProof {
            commitment: vec![],
            response: vec![0u8; 32],
        };
        assert!(ec_schnorr::verify(&proof, &pk, b"msg").is_err());
    }

    // --- Batch verify ---

    #[test]
    fn batch_verify_all_valid() {
        let mut proofs = Vec::new();
        let mut pks = Vec::new();
        let mut msgs = Vec::new();
        for i in 0..5u8 {
            let (sk, pk) = keypair(i);
            let msg = format!("batch message {i}").into_bytes();
            proofs.push(ec_schnorr::prove(&sk, &pk, &msg).unwrap());
            pks.push(pk);
            msgs.push(msg);
        }
        assert!(ec_schnorr::batch_verify(&proofs, &pks, &msgs).unwrap());
    }

    #[test]
    fn batch_verify_one_bad_message() {
        let mut proofs = Vec::new();
        let mut pks = Vec::new();
        let mut msgs = Vec::new();
        for i in 0..3u8 {
            let (sk, pk) = keypair(i);
            let msg = format!("msg {i}").into_bytes();
            proofs.push(ec_schnorr::prove(&sk, &pk, &msg).unwrap());
            pks.push(pk);
            msgs.push(msg);
        }
        // Tamper with the last message
        msgs[2] = b"tampered".to_vec();
        assert!(!ec_schnorr::batch_verify(&proofs, &pks, &msgs).unwrap());
    }

    #[test]
    fn batch_verify_empty() {
        assert!(ec_schnorr::batch_verify(&[], &[], &[]).unwrap());
    }

    #[test]
    fn batch_verify_mismatched_lengths() {
        let (sk, pk) = keypair(1);
        let proof = ec_schnorr::prove(&sk, &pk, b"msg").unwrap();
        let result = ec_schnorr::batch_verify(&[proof], &[pk], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn batch_verify_single() {
        let (sk, pk) = keypair(99);
        let msg = b"single batch entry".to_vec();
        let proof = ec_schnorr::prove(&sk, &pk, &msg).unwrap();
        assert!(ec_schnorr::batch_verify(&[proof], &[pk], &[msg]).unwrap());
    }
}
