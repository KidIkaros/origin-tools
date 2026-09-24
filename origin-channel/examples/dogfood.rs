// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-channel` as a foundational dependency.
//!
//! Encrypted sessions through the typed library API (`origin_channel`):
//! a full Noise-IK 3-message handshake between two parties (X25519 via the
//! crate's `dh` seam, HKDF via the SDK), ratchet initialization, and a
//! forward-secure message exchange through `RatchetedSession` — including
//! tamper rejection and replay protection. No CLI, no files.
//!
//! Run with: `cargo run -p origin-channel --example dogfood`

use origin_channel::dh::DhSecret;
use origin_channel::handshake::Handshake;
use origin_channel::message::ChannelMessage;
use origin_channel::ratchet;
use origin_channel::replay::ReplayWindow;
use origin_channel::session::RatchetedSession;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── static identity keypairs (via the crate's single X25519 seam) ──
    let alice_static = DhSecret::generate()?;
    let bob_static = DhSecret::generate()?;
    let alice_pk = alice_static.public();
    let bob_pk = bob_static.public();
    println!("✓ X25519 identity keypairs (DhSecret/DhPublic seam)");

    // ── Noise-IK 3-message handshake ──────────────────────────────────
    let mut alice = Handshake::new(alice_static, bob_pk, true);
    let mut bob = Handshake::new(bob_static, alice_pk, false);

    let msg1 = alice.start()?;
    let msg2 = bob.process_msg1(&msg1)?;
    let msg3 = alice.process_msg2(&msg2)?;
    bob.process_msg3(&msg3)?;

    let (alice_ss, alice_sid) = alice.finalize()?;
    let (bob_ss, bob_sid) = bob.finalize()?;
    assert_eq!(alice_ss, bob_ss, "shared secrets must match");
    assert_eq!(alice_sid, bob_sid, "session IDs must match");
    println!("✓ Noise-IK handshake: same shared secret + session ID on both sides");

    // ── ratchet sessions and forward-secure exchange ──────────────────
    let alice_keys = ratchet::init_ratchet(&alice_ss, true)?;
    let bob_keys = ratchet::init_ratchet(&bob_ss, false)?;
    let mut alice_sess = RatchetedSession::with_defaults(alice_keys);
    let mut bob_sess = RatchetedSession::with_defaults(bob_keys);

    let plaintext = b"forward-secret hello from origin-channel";
    let wire = alice_sess.encrypt(plaintext)?;
    let decrypted = bob_sess.decrypt(&wire)?;
    assert_eq!(decrypted, plaintext);
    println!(
        "✓ ratchet encrypt → decrypt round-trip ({} bytes on wire)",
        wire.wire_size()
    );

    // ── tamper rejection: flip one ciphertext byte ────────────────────
    let mut tampered_bytes = wire.to_bytes();
    let last = tampered_bytes.len() - 1;
    tampered_bytes[last] ^= 0xff;
    let tampered = ChannelMessage::from_bytes(&tampered_bytes)?;
    assert!(
        bob_sess.decrypt(&tampered).is_err(),
        "tampered ciphertext must fail AEAD auth"
    );
    println!("✓ tampered ciphertext rejected (AEAD auth failure)");

    // ── replay protection: same sequence number must be refused ───────
    let mut window = ReplayWindow::new(64);
    let seq = 7u64;
    window
        .accept(seq)
        .expect("first sight of seq must be accepted");
    assert!(
        window.accept(seq).is_err(),
        "duplicate sequence number must be refused by the replay window"
    );
    println!("✓ replay window refuses duplicate sequence numbers");

    println!("\norigin-channel dogfood OK — usable as a foundational dependency");
    Ok(())
}
