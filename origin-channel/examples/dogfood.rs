// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-channel` as a foundational dependency.
//!
//! Encrypted sessions through the typed library API: a Noise-style
//! ratchet handshake (`ratchet::init_ratchet`), forward-secret
//! messaging via `RatchetedSession`, replay protection, AEAD tamper
//! detection, usage-limit enforcement, and DH ratchet rotation — the
//! exact surface a transport layer or messaging app consumes.
//!
//! Run with: `cargo run -p origin-channel --example dogfood`

use origin_channel::error::ChannelError;
use origin_channel::ratchet;
use origin_channel::session::RatchetedSession;
use origin_channel::usage_limit::AeadLimits;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── handshake: both sides derive mirrored ratchet keys ───────────
    let shared_secret = [0x42u8; 32];
    let alice_keys = ratchet::init_ratchet(&shared_secret, true).map_err(|e| format!("{e}"))?;
    let bob_keys = ratchet::init_ratchet(&shared_secret, false).map_err(|e| format!("{e}"))?;
    println!("✓ Noise IK-style ratchet init (mirrored key schedules)");

    // ── messaging: 10-message round-trip ─────────────────────────────
    let mut alice = RatchetedSession::with_defaults(alice_keys);
    let mut bob = RatchetedSession::with_defaults(bob_keys);

    for i in 0..10u64 {
        let text = format!("secret message {i}");
        let msg = alice.encrypt(text.as_bytes()).map_err(|e| format!("{e}"))?;
        assert_eq!(msg.msg_type, origin_channel::message::MSG_DATA);
        let plaintext = bob.decrypt(&msg).map_err(|e| format!("{e}"))?;
        assert_eq!(plaintext, text.as_bytes());
    }
    assert_eq!(alice.send_messages(), 10);
    assert_eq!(bob.recv_messages(), 10);
    println!("✓ 10-message forward-secret round-trip");

    // ── replay protection ────────────────────────────────────────────
    let msg = alice.encrypt(b"once").map_err(|e| format!("{e}"))?;
    bob.decrypt(&msg).map_err(|e| format!("{e}"))?;
    let replay = bob.decrypt(&msg);
    assert!(
        matches!(replay, Err(ChannelError::Replay(_))),
        "replayed message must be rejected"
    );
    println!("✓ replay rejected");

    // ── tamper detection ─────────────────────────────────────────────
    let mut tampered = alice.encrypt(b"integrity").map_err(|e| format!("{e}"))?;
    tampered.ciphertext[0] ^= 0xff;
    let bad = bob.decrypt(&tampered);
    assert!(
        matches!(bad, Err(ChannelError::Decryption(_))),
        "tampered ciphertext must fail AEAD"
    );
    println!("✓ tampered ciphertext rejected (AEAD)");

    // ── usage limits + ratchet rotation ──────────────────────────────
    let limits = AeadLimits::new(2, u64::MAX);
    let mut carol = RatchetedSession::new(alice.keys().clone(), limits);
    carol.encrypt(b"a").map_err(|e| format!("{e}"))?;
    carol.encrypt(b"b").map_err(|e| format!("{e}"))?;
    assert!(carol.send_exhausted());
    let refused = carol.encrypt(b"c");
    assert!(
        matches!(refused, Err(ChannelError::UsageLimitExceeded(_))),
        "third message must be refused by the usage limit"
    );

    // A DH ratchet step refreshes the epoch: counters reset, budget back.
    let fresh_dh = [0x99u8; 32];
    let new_keys =
        ratchet::dh_ratchet(&carol.keys().root, &fresh_dh).map_err(|e| format!("{e}"))?;
    let new_keys = origin_channel::types::RatchetKeys {
        root: new_keys.root,
        send_chain: new_keys.send_chain,
        recv_chain: new_keys.recv_chain,
    };
    carol.rotate(new_keys);
    assert!(!carol.send_exhausted());
    assert_eq!(carol.send_messages(), 0);
    carol.encrypt(b"c").map_err(|e| format!("{e}"))?;
    println!("✓ usage limits enforced + DH ratchet rotation resets epoch");

    println!("\norigin-channel dogfood OK — usable as a foundational dependency");
    Ok(())
}
