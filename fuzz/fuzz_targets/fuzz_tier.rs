// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: MemoryTier byte/string conversions.
//!
//! Exercises `tier_from_byte`, `tier_from_str`, and `tier_to_byte` — the
//! converters that map the envelope's tier byte and the config's tier string
//! to the SDK's MemoryTier enum.
//!
//! Properties verified:
//!   - `tier_from_byte` accepts exactly {0,1,2}, rejects everything else,
//!     and never panics
//!   - `tier_from_str` never panics on arbitrary UTF-8
//!   - byte round-trip is identity: from_byte(to_byte(t)) == Ok(t)
//!
//! Run with: cargo +nightly fuzz run fuzz_tier

#![no_main]

use libfuzzer_sys::fuzz_target;
use origin_common::{tier_from_byte, tier_from_str, tier_to_byte};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Byte conversion: exactly 0,1,2 are valid; nothing may panic.
    let b = data[0];
    match tier_from_byte(b) {
        Ok(t) => {
            assert!(b <= 2, "only bytes 0..=2 may decode to a tier");
            // Round-trip must be the identity.
            assert_eq!(tier_from_byte(tier_to_byte(t)), Ok(t));
        }
        Err(_) => assert!(b > 2, "bytes 0..=2 must always decode"),
    }

    // String conversion: arbitrary UTF-8 must never panic.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = tier_from_str(s);
    }
});
