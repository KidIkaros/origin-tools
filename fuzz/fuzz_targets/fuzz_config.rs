// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: Config TOML deserialization + tier resolution.
//!
//! Feeds arbitrary strings to `toml::from_str::<Config>` and then calls
//! `Config::tier()`, which resolves a free-form tier string to a MemoryTier.
//! `tier()` uses `unwrap_or(Standard)` so it must never panic even on
//! garbage tier values — this target proves that.
//!
//! Properties verified:
//!   - TOML parsing never panics (serde returns Result)
//!   - `Config::tier()` never panics regardless of the tier string
//!   - `Config::tier()` always yields a valid MemoryTier
//!
//! Run with: cargo +nightly fuzz run fuzz_config

#![no_main]

use libfuzzer_sys::fuzz_target;
use origin_common::Config;
use origin_crypto_sdk::tier::MemoryTier;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Parsing arbitrary TOML must never panic.
    if let Ok(config) = toml::from_str::<Config>(s) {
        // Tier resolution must never panic and must return a valid tier,
        // no matter what string was in the config.
        let tier = config.tier();
        assert!(matches!(
            tier,
            MemoryTier::Nano | MemoryTier::Standard | MemoryTier::Sovereign
        ));
    }
});
