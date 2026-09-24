// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-wallet` as a foundational dependency.
//!
//! The post-quantum wallet as a library: create (fresh seed + entropy
//! gate + mlock'd SeedHandle), derive accounts with stealth support,
//! sign/verify hybrid transactions with encrypted memos, MMR history
//! with membership proofs, encrypted save/open, K-of-N shard backup +
//! recovery, phrase export/import, spend-policy gating, and the
//! contacts table.
//!
//! Run with: `cargo run -p origin-wallet --example dogfood`

use origin_wallet::{Address, Transaction, Wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "origin-dogfood-wallet-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir)?;
    let wallet_path = dir.join("wallet.dat");

    // ── create: fresh seed, entropy-validated, mlock'd handle ────────
    let mut wallet = Wallet::create("dogfood-passphrase").map_err(|e| e.to_string())?;
    assert_eq!(wallet.name(), "Origin Wallet");
    assert_eq!(wallet.accounts().len(), 0);
    println!("✓ Wallet::create (seed generated + entropy-gated)");

    // ── derive accounts (unique addresses + stealth support) ─────────
    let alice = wallet.derive_account(0).map_err(|e| e.to_string())?;
    let bob = wallet.derive_account(1).map_err(|e| e.to_string())?;
    assert_ne!(alice.address(), bob.address());
    assert!(alice
        .address()
        .to_bech32()
        .map_err(|e| e.to_string())?
        .starts_with("origin1"));
    assert!(
        alice.has_stealth_support(),
        "accounts carry stealth masters"
    );
    let stealth = alice
        .generate_stealth_address(3)
        .map_err(|e| e.to_string())?;
    assert_eq!(stealth.index, 3);
    assert_ne!(&stealth.address, alice.address());
    println!("✓ derive_account ×2 + stealth address derivation");

    // ── hybrid transaction: sign + verify + encrypted memo ───────────
    let mut tx = Transaction::new(alice.address(), bob.address(), 1000, 10, 0);
    tx.sign(&alice).map_err(|e| e.to_string())?;
    assert!(tx.signature.len() > 68, "hybrid signature present");
    let ed_pk = alice.ed25519_pk().map_err(|e| e.to_string())?;
    // The Account stores the hybrid signature in wire form (64-byte Ed25519
    // leg first). Verify the Ed25519 leg against the account's public key;
    // the Falcon-1024 leg requires the wallet to store its public key, which
    // the crate does not persist today (same limitation its own tests note).
    let ed_sig: [u8; 64] = tx.signature[..64].try_into().map_err(|_| "ed leg")?;
    assert!(
        origin_crypto_sdk::signing::classical::Ed25519Signer::verify_with_pubkey(
            &ed_pk,
            &tx.to_sign_bytes(),
            &ed_sig,
        ),
        "ed25519 leg of the hybrid signature must verify"
    );
    let mut tampered = tx.clone();
    tampered.amount = 9999;
    assert!(
        !origin_crypto_sdk::signing::classical::Ed25519Signer::verify_with_pubkey(
            &ed_pk,
            &tampered.to_sign_bytes(),
            &ed_sig,
        ),
        "tampered tx must fail signature verification"
    );
    println!("✓ hybrid sign → ed25519-leg verify (tamper rejected)");

    // Encrypted memo round-trip (AAD = tx id).
    let memo_key = origin_crypto_sdk::aead::try_generate_key().map_err(|e| e.to_string())?;
    tx.encrypt_memo(&memo_key, b"invoice #42")
        .map_err(|e| e.to_string())?;
    assert_eq!(
        tx.decrypt_memo(&memo_key).map_err(|e| e.to_string())?,
        b"invoice #42"
    );
    println!("✓ encrypted memo (AAD-bound to tx id)");

    // ── MMR history + membership proofs ──────────────────────────────
    for i in 0..10u64 {
        let t = Transaction::new(alice.address(), bob.address(), 100 + i, 10, i);
        wallet.add_transaction(&t).map_err(|e| e.to_string())?;
    }
    assert_eq!(wallet.transaction_count(), 10);
    let proof = wallet.prove_transaction(5).map_err(|e| e.to_string())?;
    assert!(
        wallet
            .verify_transaction_proof(&proof)
            .map_err(|e| e.to_string())?,
        "MMR membership proof must verify"
    );
    println!("✓ MMR transaction history (10 leaves) + proof");

    // ── spend policy gating ──────────────────────────────────────────
    wallet.set_spend_policy(origin_wallet::wallet::SpendPolicy {
        per_tx: Some(500),
        ..Default::default()
    });
    assert!(wallet.check_spend(499).is_ok());
    assert!(wallet.check_spend(501).is_err(), "per-tx cap enforced");
    println!("✓ spend policy gate (per-tx cap)");

    // ── encrypted save / open round-trip ─────────────────────────────
    wallet.update_balance(0, 2500).map_err(|e| e.to_string())?;
    wallet
        .save(&wallet_path, "dogfood-passphrase")
        .map_err(|e| e.to_string())?;
    let opened = Wallet::open(&wallet_path, "dogfood-passphrase").map_err(|e| e.to_string())?;
    assert_eq!(opened.total_balance(), 2500, "balance persisted");
    assert_eq!(opened.transaction_count(), 10, "history persisted");
    assert!(
        Wallet::open(&wallet_path, "wrong-passphrase").is_err(),
        "wrong passphrase must fail AEAD"
    );
    println!("✓ save → open (encrypted at rest, wrong passphrase rejected)");

    // ── shard backup (3-of-5) + recovery ─────────────────────────────
    let shards = wallet.backup(5, 3).map_err(|e| e.to_string())?;
    assert_eq!(shards.len(), 5);
    let recovered = Wallet::recover_from_shards(&shards[1..4]).map_err(|e| e.to_string())?;
    let mut restored = Wallet::from_seed(&recovered).map_err(|e| e.to_string())?;
    let restored_account = restored.derive_account(0).map_err(|e| e.to_string())?;
    assert_eq!(
        restored_account.address(),
        alice.address(),
        "keys reproduce"
    );
    println!("✓ 3-of-5 shard backup → recovery reproduces account keys");

    // ── phrase export / import ───────────────────────────────────────
    let phrase = wallet.export_phrase().map_err(|e| e.to_string())?;
    // The phrase is a unicode-cipher encoding (one contiguous char string,
    // not whitespace-separated words), so assert on char length.
    assert!(phrase.chars().count() > 0, "phrase is non-empty");
    let mut from_phrase = Wallet::from_phrase(&phrase, "x").map_err(|e| e.to_string())?;
    let re = from_phrase.derive_account(0).map_err(|e| e.to_string())?;
    assert_eq!(re.address(), alice.address());
    println!("✓ phrase export → import reproduces identity");

    // ── contacts table (sidecar, non-secret) ─────────────────────────
    let mut contacts =
        origin_wallet::contacts::Contacts::load(&wallet_path).map_err(|e| e.to_string())?;
    let mesh_hex = hex::encode([0xAB; 32]);
    contacts
        .add("payee-alice", &mesh_hex)
        .map_err(|e| e.to_string())?;
    let reloaded =
        origin_wallet::contacts::Contacts::load(&wallet_path).map_err(|e| e.to_string())?;
    assert_eq!(reloaded.get("payee-alice"), Some(mesh_hex.as_str()));
    println!("✓ contacts table (label → MeshId, persisted)");

    // ── address encoding round-trips ─────────────────────────────────
    // NB: the bech32/Base58Check *encoding* differs, so round-trip compare
    // on the pubkey hash, not the whole typed Address.
    let b58 = alice.address().to_base58check();
    let decoded = Address::from_base58check(&b58).map_err(|e| e.to_string())?;
    assert_eq!(decoded.hash(), alice.address().hash());
    let b32 = alice.address().to_bech32().map_err(|e| e.to_string())?;
    let decoded32 = Address::from_bech32(&b32).map_err(|e| e.to_string())?;
    assert_eq!(decoded32.hash(), alice.address().hash());
    println!("✓ address encodings (Bech32m + Base58Check round-trips)");

    std::fs::remove_dir_all(&dir).ok();
    println!("\norigin-wallet dogfood OK — usable as a foundational dependency");
    Ok(())
}
