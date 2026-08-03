//! SDK-backed randomness adapters for origin-tools.
//!
//! The SDK is the sole entropy provider. This module is intentionally a thin
//! suite adapter until the SDK exposes an equivalent stable public API.

/// Fill a byte slice with randomness from the SDK provider.
pub fn random_bytes(dest: &mut [u8]) -> Result<(), String> {
    origin_crypto_sdk::fill_random(dest).map_err(|error| format!("SDK randomness failure: {error}"))
}

/// Generate a fixed-size random byte array using the SDK provider.
pub fn random_array<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    random_bytes(&mut bytes)?;
    Ok(bytes)
}
