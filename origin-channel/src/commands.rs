// SPDX-License-Identifier: Apache-2.0

//! Command implementations for origin-channel.

use std::path::PathBuf;

use origin_crypto_sdk::sha3_256;

use crate::cli::{Commands, DemoArgs, FingerprintArgs, KeygenArgs};
use crate::codec;
use crate::dh::DhSecret;
use crate::handshake::Handshake;
use crate::message::{ChannelMessage, MSG_DATA};
use crate::ratchet;
use crate::session::RatchetedSession;
use crate::types::ChannelState;
use crate::usage_limit::AeadLimits;

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Keygen(args) => cmd_keygen(args),
        Commands::Fingerprint(args) => cmd_fingerprint(args),
        Commands::Demo(args) => cmd_demo(args),
    }
}

fn resolve_path(raw: &str) -> Result<PathBuf, String> {
    if let Some(rest) = raw.strip_prefix("~/") {
        let home =
            std::env::var("HOME").map_err(|_| "$HOME unset; pass an absolute path".to_string())?;
        Ok(PathBuf::from(home).join(rest))
    } else {
        Ok(PathBuf::from(raw))
    }
}

fn cmd_keygen(args: KeygenArgs) -> Result<(), String> {
    let path = resolve_path(&args.output)?;
    if path.exists() && !args.force {
        return Err(format!(
            "{} already exists (use --force to overwrite)",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }

    let secret = DhSecret::generate().map_err(|e| e.to_string())?;
    let public = secret.public();

    let out = serde_json::json!({
        "version": 1,
        "algorithm": "X25519",
        "private_key": hex::encode(secret.to_bytes()),
        "public_key": hex::encode(public.as_bytes()),
        "fingerprint": hex::encode(sha3_256(public.as_bytes())),
    });

    std::fs::write(&path, serde_json::to_string_pretty(&out).unwrap())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;

    eprintln!("Generated X25519 keypair at {}", path.display());
    eprintln!("  public key:  {}", hex::encode(public.as_bytes()));
    eprintln!(
        "  fingerprint: {}",
        hex::encode(sha3_256(public.as_bytes()))
    );
    Ok(())
}

fn cmd_fingerprint(args: FingerprintArgs) -> Result<(), String> {
    let path = resolve_path(&args.keyfile)?;
    let data = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let val: serde_json::Value =
        serde_json::from_str(&data).map_err(|e| format!("invalid JSON: {e}"))?;

    let fp = val["fingerprint"]
        .as_str()
        .ok_or("missing fingerprint field")?;
    let pk = val["public_key"]
        .as_str()
        .ok_or("missing public_key field")?;

    println!("fingerprint: {fp}");
    println!("public key:  {pk}");
    Ok(())
}

fn cmd_demo(args: DemoArgs) -> Result<(), String> {
    eprintln!("=== origin-channel handshake demo ===\n");

    // Generate two identity keypairs (via the crate's single X25519 seam)
    let alice_secret = DhSecret::generate().map_err(|e| e.to_string())?;
    let alice_pk = alice_secret.public();
    let bob_secret = DhSecret::generate().map_err(|e| e.to_string())?;
    let bob_pk = bob_secret.public();

    eprintln!("Alice X25519: {}", hex::encode(alice_pk.as_bytes()));
    eprintln!("Bob   X25519: {}", hex::encode(bob_pk.as_bytes()));
    eprintln!();

    // Run the 3-message IK handshake
    let mut alice_hs = Handshake::new(alice_secret, bob_pk, true);
    let mut bob_hs = Handshake::new(bob_secret, alice_pk, false);

    let msg1 = alice_hs.start().map_err(|e| format!("msg1: {e}"))?;
    eprintln!("msg1 (Alice → Bob): {} bytes", msg1.to_bytes().len());

    let msg2 = bob_hs
        .process_msg1(&msg1)
        .map_err(|e| format!("msg2: {e}"))?;
    eprintln!("msg2 (Bob → Alice): {} bytes", msg2.to_bytes().len());

    let msg3 = alice_hs
        .process_msg2(&msg2)
        .map_err(|e| format!("msg3: {e}"))?;
    eprintln!("msg3 (Alice → Bob): {} bytes", msg3.to_bytes().len());

    bob_hs
        .process_msg3(&msg3)
        .map_err(|e| format!("finalize bob: {e}"))?;

    let (alice_ss, alice_sid) = alice_hs
        .finalize()
        .map_err(|e| format!("alice finalize: {e}"))?;
    let (bob_ss, bob_sid) = bob_hs
        .finalize()
        .map_err(|e| format!("bob finalize: {e}"))?;

    assert_eq!(alice_ss, bob_ss);
    assert_eq!(alice_sid, bob_sid);

    eprintln!("\nHandshake complete!");
    eprintln!("  session ID:    {}", alice_sid);
    eprintln!("  shared secret: {}…", &hex::encode(alice_ss)[..16]);
    eprintln!();

    // Derive ratchet keys and create sessions with AEAD usage limits
    let alice_keys = ratchet::init_ratchet(&alice_ss, true).map_err(|e| format!("ratchet: {e}"))?;
    let bob_keys = ratchet::init_ratchet(&bob_ss, false).map_err(|e| format!("ratchet: {e}"))?;

    let limits = AeadLimits::default();
    let mut alice_session = RatchetedSession::new(alice_keys, limits);
    let mut bob_session = RatchetedSession::new(bob_keys, limits);

    eprintln!("Exchanging {} encrypted messages:\n", args.messages);

    for i in 0..args.messages {
        let plaintext = format!("Hello from Alice, message #{i}");

        // Alice encrypts (usage-limited)
        let msg = alice_session
            .encrypt(plaintext.as_bytes())
            .map_err(|e| format!("encrypt: {e}"))?;

        // Frame it
        let frame =
            codec::encode_typed(MSG_DATA, &msg.to_bytes()).map_err(|e| format!("encode: {e}"))?;

        // Bob receives, decodes, and decrypts (replay + usage limited)
        let (_tag, inner, _consumed) = codec::decode_typed(&frame)
            .map_err(|e| format!("decode: {e}"))?
            .ok_or("incomplete frame")?;
        let recv_msg = ChannelMessage::from_bytes(&inner).map_err(|e| format!("parse: {e}"))?;

        let decrypted = bob_session
            .decrypt(&recv_msg)
            .map_err(|e| format!("decrypt: {e}"))?;

        let text = String::from_utf8(decrypted).map_err(|e| format!("utf8: {e}"))?;
        eprintln!(
            "  [{i}] {} bytes → {} bytes → \"{}\"",
            plaintext.len(),
            frame.len(),
            text
        );
    }

    eprintln!(
        "\nAll {} messages encrypted, framed, replay-checked, and decrypted.",
        args.messages
    );
    eprintln!(
        "AEAD usage: {} msgs / {} bytes sent, {} msgs / {} bytes recv",
        alice_session.send_messages(),
        alice_session.send_bytes(),
        bob_session.recv_messages(),
        bob_session.recv_bytes()
    );
    eprintln!("Session state: {:?}", ChannelState::Established);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_runs_successfully() {
        let args = DemoArgs { messages: 3 };
        assert!(cmd_demo(args).is_ok());
    }

    #[test]
    fn keygen_and_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let keyfile = dir.path().join("test-keys.json");
        let kf_str = keyfile.to_str().unwrap();

        let kg = KeygenArgs {
            output: kf_str.to_string(),
            force: false,
        };
        assert!(cmd_keygen(kg).is_ok());
        assert!(keyfile.exists());

        let fp = FingerprintArgs {
            keyfile: kf_str.to_string(),
        };
        assert!(cmd_fingerprint(fp).is_ok());
    }

    #[test]
    fn keygen_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let keyfile = dir.path().join("test-keys.json");
        let kf_str = keyfile.to_str().unwrap();

        let kg = KeygenArgs {
            output: kf_str.to_string(),
            force: false,
        };
        assert!(cmd_keygen(kg).is_ok());

        let kg2 = KeygenArgs {
            output: kf_str.to_string(),
            force: false,
        };
        assert!(cmd_keygen(kg2).is_err());
    }

    #[test]
    fn keygen_force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let keyfile = dir.path().join("test-keys.json");
        let kf_str = keyfile.to_str().unwrap();

        let kg = KeygenArgs {
            output: kf_str.to_string(),
            force: false,
        };
        assert!(cmd_keygen(kg).is_ok());

        let kg2 = KeygenArgs {
            output: kf_str.to_string(),
            force: true,
        };
        assert!(cmd_keygen(kg2).is_ok());
    }

    #[test]
    fn resolve_path_tilde_expansion() {
        let resolved = resolve_path("~/some/file.json").unwrap();
        let home = std::env::var("HOME").unwrap();
        assert_eq!(resolved, PathBuf::from(home).join("some/file.json"));
    }

    #[test]
    fn resolve_path_absolute() {
        let resolved = resolve_path("/tmp/keys.json").unwrap();
        assert_eq!(resolved, PathBuf::from("/tmp/keys.json"));
    }

    #[test]
    fn fingerprint_missing_fields() {
        let dir = tempfile::tempdir().unwrap();
        let keyfile = dir.path().join("bad.json");
        std::fs::write(&keyfile, r#"{"version": 1}"#).unwrap();

        let fp = FingerprintArgs {
            keyfile: keyfile.to_str().unwrap().to_string(),
        };
        assert!(cmd_fingerprint(fp).is_err());
    }

    #[test]
    fn fingerprint_missing_file() {
        let fp = FingerprintArgs {
            keyfile: "/nonexistent/path/keys.json".to_string(),
        };
        assert!(cmd_fingerprint(fp).is_err());
    }

    #[test]
    fn dispatch_routes_commands() {
        use crate::cli::Cli;
        use clap::Parser;

        let cli = Cli::parse_from(["origin-channel", "demo", "--messages", "1"]);
        assert!(dispatch(cli).is_ok());
    }
}
