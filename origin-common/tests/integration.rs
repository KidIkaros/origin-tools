// SPDX-License-Identifier: Apache-2.0

//! Integration tests for origin-common.

use origin_common::{
    read_input, resolve_passphrase, tier_from_byte, tier_from_str, tier_to_byte, write_output,
    Envelope, IdentityStore, MemoryTier, OriginHome, PayloadType,
};

/// Create an isolated temp home for testing.
fn temp_home() -> (tempfile::TempDir, OriginHome) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let home = OriginHome::with_root(dir.path().to_path_buf()).expect("load home");
    (dir, home)
}

// ─── OriginHome tests ───

#[test]
fn home_creates_directory_and_config() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("subdir").join("origin");
    let home = OriginHome::with_root(root.clone()).expect("load");

    assert!(root.exists());
    assert!(root.join("config.toml").exists());
    assert_eq!(home.root(), root);
}

#[test]
fn home_respects_origin_home_env() {
    let dir = tempfile::tempdir().expect("temp dir");
    let custom = dir.path().join("custom-origin");
    std::env::set_var("ORIGIN_HOME", &custom);

    let home = OriginHome::load().expect("load");
    assert_eq!(home.root(), custom);
    assert!(custom.exists());

    std::env::remove_var("ORIGIN_HOME");
}

#[test]
fn home_config_defaults() {
    let (_dir, home) = temp_home();
    let config = home.config();
    assert_eq!(config.tier, "standard");
    assert_eq!(config.format, "hex");
    assert_eq!(config.tier(), MemoryTier::Standard);
}

#[test]
fn home_config_custom_tier() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().to_path_buf();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("config.toml"),
        "tier = \"nano\"\nformat = \"base64\"\n",
    )
    .unwrap();

    let home = OriginHome::with_root(root).expect("load");
    assert_eq!(home.config().tier, "nano");
    assert_eq!(home.config().format, "base64");
    assert_eq!(home.config().tier(), MemoryTier::Nano);
}

#[test]
fn home_config_invalid_tier_falls_back() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().to_path_buf();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("config.toml"), "tier = \"bogus\"\n").unwrap();

    let home = OriginHome::with_root(root).expect("load");
    // Invalid tier falls back to Standard
    assert_eq!(home.config().tier(), MemoryTier::Standard);
}

#[test]
fn home_paths() {
    let (_dir, home) = temp_home();
    assert_eq!(home.identity_seed_path(), home.root().join("identity.seed"));
    assert_eq!(home.vault_path(), home.root().join("vault.opass"));
    assert_eq!(home.config_path(), home.root().join("config.toml"));
    assert_eq!(home.keys_dir(), home.root().join("keys"));
    assert_eq!(home.backups_dir(), home.root().join("backups"));
}

#[cfg(unix)]
#[test]
fn home_directory_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().join("perm-test");
    let _home = OriginHome::with_root(root.clone()).expect("load");

    let perms = std::fs::metadata(&root).unwrap().permissions();
    assert_eq!(perms.mode() & 0o777, 0o700);
}

// ─── IdentityStore tests ───

#[test]
fn identity_create_and_load_roundtrip() {
    let (_dir, home) = temp_home();
    let passphrase = "test-passphrase-123";

    let store = IdentityStore::create(&home, passphrase, MemoryTier::Nano).expect("create");
    let seed = *store.seed_bytes();
    assert_ne!(seed, [0u8; 32]);

    // Load it back
    let loaded = IdentityStore::load(&home, passphrase).expect("load");
    assert_eq!(loaded.seed_bytes(), &seed);
    assert_eq!(loaded.tier(), MemoryTier::Nano);
}

#[test]
fn identity_wrong_passphrase_fails() {
    let (_dir, home) = temp_home();
    IdentityStore::create(&home, "correct", MemoryTier::Nano).expect("create");

    let result = IdentityStore::load(&home, "wrong");
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.contains("decryption failed"));
}

#[test]
fn identity_missing_file_fails() {
    let (_dir, home) = temp_home();
    let result = IdentityStore::load(&home, "any");
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.contains("identity not found"));
}

#[test]
fn identity_corrupt_blob_fails() {
    let (_dir, home) = temp_home();
    IdentityStore::create(&home, "pass", MemoryTier::Nano).expect("create");

    // Corrupt the blob
    let path = home.identity_seed_path();
    let mut blob = std::fs::read(&path).unwrap();
    blob[50] ^= 0xFF; // flip a ciphertext byte
    std::fs::write(&path, &blob).unwrap();

    let result = IdentityStore::load(&home, "pass");
    assert!(result.is_err());
}

#[test]
fn identity_truncated_blob_fails() {
    let (_dir, home) = temp_home();
    IdentityStore::create(&home, "pass", MemoryTier::Nano).expect("create");

    // Truncate to less than minimum
    let path = home.identity_seed_path();
    std::fs::write(&path, [0u8; 30]).unwrap();

    let result = IdentityStore::load(&home, "pass");
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.contains("too short"));
}

#[test]
fn identity_derive_key_deterministic() {
    let (_dir, home) = temp_home();
    let store = IdentityStore::create(&home, "pass", MemoryTier::Nano).expect("create");

    let key1 = store.derive_key("domain-a", 32).expect("derive");
    let key2 = store.derive_key("domain-a", 32).expect("derive");
    assert_eq!(key1, key2);

    // Different domain → different key
    let key3 = store.derive_key("domain-b", 32).expect("derive");
    assert_ne!(key1, key3);

    // Different length
    let key4 = store.derive_key("domain-a", 64).expect("derive");
    assert_eq!(key4.len(), 64);
}

#[test]
fn identity_hybrid_signing_keys() {
    let (_dir, home) = temp_home();
    let store = IdentityStore::create(&home, "pass", MemoryTier::Nano).expect("create");

    let keys = store.hybrid_signing_keys("test-domain").expect("keys");
    // Just verify it doesn't panic and returns something
    let _ = keys;
}

#[cfg(unix)]
#[test]
fn identity_file_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, home) = temp_home();
    IdentityStore::create(&home, "pass", MemoryTier::Nano).expect("create");

    let path = home.identity_seed_path();
    let perms = std::fs::metadata(&path).unwrap().permissions();
    assert_eq!(perms.mode() & 0o777, 0o600);
}

// ─── Envelope tests ───

#[test]
fn envelope_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let plaintext = b"secret data for envelope test";

    let env = Envelope::encrypt(plaintext, &key, MemoryTier::Nano, PayloadType::File, false)
        .expect("encrypt");
    let decrypted = env.decrypt(&key).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn envelope_wrong_key_fails() {
    let key = [0x42u8; 32];
    let wrong_key = [0x43u8; 32];
    let plaintext = b"secret";

    let env = Envelope::encrypt(plaintext, &key, MemoryTier::Nano, PayloadType::File, false)
        .expect("encrypt");
    let result = env.decrypt(&wrong_key);
    assert!(result.is_err());
}

#[test]
fn envelope_serialization_roundtrip() {
    let key = [0xABu8; 32];
    let plaintext = b"serialize me";

    let env = Envelope::encrypt(
        plaintext,
        &key,
        MemoryTier::Standard,
        PayloadType::Seed,
        false,
    )
    .expect("encrypt");
    let bytes = env.to_bytes();

    let parsed = Envelope::from_bytes(&bytes).expect("parse");
    assert_eq!(parsed.header.version, 1);
    assert_eq!(parsed.header.payload_type, PayloadType::Seed);
    assert_eq!(parsed.header.tier, MemoryTier::Standard);

    let decrypted = parsed.decrypt(&key).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn envelope_aad_tamper_detection() {
    let key = [0xCDu8; 32];
    let plaintext = b"authenticated data";

    let env = Envelope::encrypt(plaintext, &key, MemoryTier::Nano, PayloadType::File, false)
        .expect("encrypt");
    let mut bytes = env.to_bytes();

    // Tamper with payload_type byte (offset 5)
    bytes[5] = 0xFF;
    let tampered = Envelope::from_bytes(&bytes);
    // Should either fail to parse or fail to decrypt
    if let Ok(env2) = tampered {
        assert!(
            env2.decrypt(&key).is_err(),
            "tampered header must fail decryption"
        );
    }
}

#[test]
fn envelope_aad_flags_tamper_detection() {
    let key = [0xEFu8; 32];
    let plaintext = b"flag tamper test";

    let env = Envelope::encrypt(plaintext, &key, MemoryTier::Nano, PayloadType::File, false)
        .expect("encrypt");
    let mut bytes = env.to_bytes();

    // Tamper with flags byte (offset 6) — set compressed flag
    bytes[6] |= 0x01;
    let tampered = Envelope::from_bytes(&bytes).expect("parse");
    // Decryption must fail because AAD doesn't match
    assert!(tampered.decrypt(&key).is_err(), "tampered flags must fail");
}

#[test]
fn envelope_compression_roundtrip() {
    let key = [0x11u8; 32];
    // Highly compressible data
    let plaintext = vec![0xAAu8; 10000];

    let env = Envelope::encrypt(&plaintext, &key, MemoryTier::Nano, PayloadType::File, true)
        .expect("encrypt");
    assert!(env.header.flags & 0x01 != 0, "compressed flag must be set");

    let decrypted = env.decrypt(&key).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn envelope_empty_plaintext() {
    let key = [0x22u8; 32];
    let env =
        Envelope::encrypt(b"", &key, MemoryTier::Nano, PayloadType::Vault, false).expect("encrypt");
    let decrypted = env.decrypt(&key).expect("decrypt");
    assert!(decrypted.is_empty());
}

#[test]
fn envelope_too_short_fails() {
    let result = Envelope::from_bytes(&[0u8; 10]);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("too short"));
}

#[test]
fn envelope_wrong_magic_fails() {
    let mut bytes = vec![0u8; 48];
    bytes[0..4].copy_from_slice(b"XXXX");
    let result = Envelope::from_bytes(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("wrong magic"));
}

#[test]
fn envelope_wrong_version_fails() {
    let key = [0x33u8; 32];
    let env = Envelope::encrypt(b"data", &key, MemoryTier::Nano, PayloadType::File, false)
        .expect("encrypt");
    let mut bytes = env.to_bytes();
    bytes[4] = 99; // bad version
    let result = Envelope::from_bytes(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("version"));
}

#[test]
fn envelope_all_payload_types() {
    let types = [
        PayloadType::Vault,
        PayloadType::File,
        PayloadType::Signed,
        PayloadType::Seed,
        PayloadType::Shard,
        PayloadType::Proof,
    ];
    for pt in types {
        let byte = pt.to_byte();
        let parsed = PayloadType::from_byte(byte).expect("parse");
        assert_eq!(parsed, pt);
    }
    assert!(PayloadType::from_byte(0xFF).is_err());
}

// ─── Tier extension tests ───

#[test]
fn tier_byte_roundtrip() {
    for tier in [
        MemoryTier::Nano,
        MemoryTier::Standard,
        MemoryTier::Sovereign,
    ] {
        let byte = tier_to_byte(tier);
        let parsed = tier_from_byte(byte).expect("parse");
        assert_eq!(parsed, tier);
    }
    assert!(tier_from_byte(99).is_err());
}

#[test]
fn tier_str_parsing() {
    assert_eq!(tier_from_str("nano").unwrap(), MemoryTier::Nano);
    assert_eq!(tier_from_str("NANO").unwrap(), MemoryTier::Nano);
    assert_eq!(tier_from_str("standard").unwrap(), MemoryTier::Standard);
    assert_eq!(tier_from_str("std").unwrap(), MemoryTier::Standard);
    assert_eq!(tier_from_str("sovereign").unwrap(), MemoryTier::Sovereign);
    assert_eq!(tier_from_str("sov").unwrap(), MemoryTier::Sovereign);
    assert!(tier_from_str("bogus").is_err());
}

// ─── IO tests ───

#[test]
fn io_read_from_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"file content").unwrap();

    let data = read_input(Some(path.to_str().unwrap())).expect("read");
    assert_eq!(data, b"file content");
}

#[test]
fn io_read_missing_file_fails() {
    let result = read_input(Some("/nonexistent/path/file.bin"));
    assert!(result.is_err());
}

#[test]
fn io_write_to_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("subdir").join("output.bin");

    write_output(Some(path.to_str().unwrap()), b"output data").expect("write");
    assert_eq!(std::fs::read(&path).unwrap(), b"output data");
}

// ─── Passphrase tests ───

#[test]
fn passphrase_from_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("pass.txt");
    std::fs::write(&path, "my-secret-pass\n").unwrap();

    let pass = resolve_passphrase(Some(path.to_str().unwrap())).expect("resolve");
    assert_eq!(pass, "my-secret-pass");
}

#[test]
fn passphrase_from_file_trims_crlf() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("pass.txt");
    std::fs::write(&path, "pass\r\n").unwrap();

    let pass = resolve_passphrase(Some(path.to_str().unwrap())).expect("resolve");
    assert_eq!(pass, "pass");
}

#[test]
fn passphrase_missing_file_fails() {
    let result = resolve_passphrase(Some("/nonexistent/pass.txt"));
    assert!(result.is_err());
}
