//! Unit tests for vault operations

use crate::vault::{MemoryTier, Vault};
use tempfile::NamedTempFile;

#[test]
fn test_vault_serialization_roundtrip() {
    let vault = Vault {
        version: 1,
        created_at: "2026-07-30T21:27:45Z".to_string(),
        tier: MemoryTier::Standard,
        fingerprint: "3af4c01e".to_string(),
        salt: [1u8; 16],
        nonce: [2u8; 24],
        ciphertext: vec![3, 4, 5],
        mac: [6u8; 32],
    };

    let serialized = serde_json::to_string(&vault).unwrap();
    let deserialized: Vault = serde_json::from_str(&serialized).unwrap();

    assert_eq!(vault.version, deserialized.version);
    assert_eq!(vault.tier, deserialized.tier);
    assert_eq!(vault.fingerprint, deserialized.fingerprint);
}

#[test]
fn test_vault_write_and_read() {
    let vault = Vault {
        version: 1,
        created_at: "2026-07-30T21:27:45Z".to_string(),
        tier: MemoryTier::Standard,
        fingerprint: "3af4c01e".to_string(),
        salt: [1u8; 16],
        nonce: [2u8; 24],
        ciphertext: vec![3, 4, 5],
        mac: [6u8; 32],
    };

    let temp_file = NamedTempFile::new().unwrap();
    let vault_path = temp_file.path();

    // Write vault to file
    let serialized = serde_json::to_string(&vault).unwrap();
    std::fs::write(vault_path, serialized).unwrap();

    // Read vault from file
    let read_data = std::fs::read_to_string(vault_path).unwrap();
    let read_vault: Vault = serde_json::from_str(&read_data).unwrap();

    assert_eq!(vault.version, read_vault.version);
    assert_eq!(vault.tier, read_vault.tier);
    assert_eq!(vault.fingerprint, read_vault.fingerprint);
}

#[test]
fn test_vault_file_not_found() {
    let vault_path = "/tmp/nonexistent_vault_file_12345.json";

    let result = std::fs::read_to_string(vault_path);
    assert!(result.is_err());
}