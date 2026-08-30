// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-common` as a foundational dependency.
//!
//! This example builds a tiny downstream app entirely on `origin-common`'s
//! public library API — the same surface any project would consume as a
//! dependency:
//!
//!   1. `OriginHome` — resolve/load a shared home directory
//!   2. `IdentityStore` — create + reload a passphrase-protected identity
//!   3. `derive_key` / `hybrid_signing_keys` — domain-separated derivation
//!   4. `Envelope` — authenticated encrypted container (round-trip + tamper)
//!   5. Tier helpers, IO helpers, randomness
//!
//! Run with: `cargo run -p origin-common --example dogfood`

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use origin_common::{
    read_input, resolve_passphrase, tier_from_str, tier_to_byte, write_output, Envelope,
    IdentityStore, MemoryTier, OriginHome, PayloadType,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique scratch directory per run (std-only, no extra dev-deps).
fn scratch(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join("origin-dogfood-common");
    let dir = base.join(format!(
        "{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = scratch("home");

    // ── 1. OriginHome: one shared home, config on disk ────────────────
    let home = OriginHome::with_root(dir.clone())?;
    assert_eq!(home.root(), &dir);
    assert!(home.config_path().exists(), "config.toml should be created");
    assert_eq!(home.config().tier, "standard");
    assert_eq!(home.config().tier(), MemoryTier::Standard);
    println!("✓ OriginHome at {}", home.root().display());

    // ── 2. IdentityStore: create → reload → derive ────────────────────
    let passphrase = "dogfood-passphrase";
    let store = IdentityStore::create(&home, passphrase, MemoryTier::Nano)?;
    let seed = *store.seed_bytes();
    assert_ne!(seed, [0u8; 32], "fresh identity must not be all zeros");

    let loaded = IdentityStore::load(&home, passphrase)?;
    assert_eq!(loaded.seed_bytes(), &seed, "reload must reproduce the seed");
    assert_eq!(loaded.tier(), MemoryTier::Nano);

    // Wrong passphrase must be rejected loudly.
    assert!(
        IdentityStore::load(&home, "wrong").is_err(),
        "wrong passphrase must fail"
    );
    println!("✓ IdentityStore create/load (tier {:?})", loaded.tier());

    // Domain-separated key derivation: same domain → same key, different
    // domain → different key. This is how a downstream app gets per-use keys.
    let k1 = store.derive_key("app:domain:a", 32)?;
    let k2 = store.derive_key("app:domain:a", 32)?;
    let k3 = store.derive_key("app:domain:b", 32)?;
    assert_eq!(k1, k2);
    assert_ne!(k1, k3);
    assert_eq!(k1.len(), 32);
    let _keys = store.hybrid_signing_keys("app:signing")?;
    println!("✓ derive_key + hybrid_signing_keys");

    // ── 3. Envelope: encrypted-at-rest container with AAD ─────────────
    let mut key = [0u8; 32];
    key.copy_from_slice(&k1);
    let plaintext = b"secret application payload";
    let env = Envelope::encrypt(plaintext, &key, MemoryTier::Nano, PayloadType::File, true)?;
    assert!(env.header.flags & 0x01 != 0, "compressed flag set");

    // Serialize → parse → decrypt (the on-disk wire format).
    let bytes = env.to_bytes();
    let parsed = Envelope::from_bytes(&bytes)?;
    assert_eq!(parsed.header.payload_type, PayloadType::File);
    assert_eq!(parsed.decrypt(&key)?, plaintext);

    // Tampering with a header byte must fail decryption (AAD).
    let mut tampered = bytes;
    tampered[6] ^= 0x01; // flip the flags byte
    let tampered_env = Envelope::from_bytes(&tampered)?;
    assert!(
        tampered_env.decrypt(&key).is_err(),
        "tampered header must fail"
    );
    println!("✓ Envelope encrypt/decrypt + AAD tamper detection");

    // ── 4. IO helpers: read_input / write_output / atomic_write ───────
    let in_path = dir.join("input.bin");
    std::fs::write(&in_path, b"io payload")?;
    assert_eq!(read_input(Some(in_path.to_str().unwrap()))?, b"io payload");

    let out_path = dir.join("nested").join("out.bin");
    write_output(Some(out_path.to_str().unwrap()), b"io payload")?;
    assert_eq!(std::fs::read(&out_path)?, b"io payload");

    origin_common::atomic_write(&dir.join("atomic.bin"), b"atomic")?;
    println!("✓ read_input / write_output / atomic_write");

    // ── 5. Passphrase resolution + tier helpers + randomness ──────────
    let pw_path = dir.join("pw.txt");
    std::fs::write(&pw_path, "file-passphrase\n")?;
    assert_eq!(
        resolve_passphrase(Some(pw_path.to_str().unwrap()))?,
        "file-passphrase"
    );

    assert_eq!(tier_from_str("NANO").unwrap(), MemoryTier::Nano);
    assert!(tier_from_str("bogus").is_err());
    assert!(tier_to_byte(MemoryTier::Sovereign) == 2);

    let rand: [u8; 16] = origin_common::random_array()?;
    assert_ne!(rand, [0u8; 16]);
    println!("✓ passphrase file, tier helpers, CSPRNG randomness");

    println!("\norigin-common dogfood OK — usable as a foundational dependency");
    Ok(())
}
