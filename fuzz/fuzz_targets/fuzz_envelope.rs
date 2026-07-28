// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: ORGN envelope binary parser.
//!
//! Feeds arbitrary bytes to `Envelope::from_bytes`, the parser for the
//! suite's unified binary format (magic + version + payload_type + flags +
//! tier + salt + nonce + payload). This is the highest-value target: every
//! tool reads untrusted envelope bytes from files/stdin.
//!
//! Properties verified:
//!   - `from_bytes` never panics on arbitrary input
//!   - if parsing succeeds, `to_bytes` never panics
//!   - round-trip is stable: from_bytes(to_bytes(x)) parses and is equal
//!
//! Run with: cargo +nightly fuzz run fuzz_envelope

#![no_main]

use libfuzzer_sys::fuzz_target;
use origin_common::Envelope;

fuzz_target!(|data: &[u8]| {
    // Parsing arbitrary bytes must never panic.
    if let Ok(env) = Envelope::from_bytes(data) {
        // A successfully parsed envelope must serialize without panic.
        let reser = env.to_bytes();

        // Round-trip stability: re-parsing our own output must succeed
        // and produce an identical envelope.
        let reparsed = Envelope::from_bytes(&reser).expect("self-produced bytes must re-parse");
        assert_eq!(
            reparsed.to_bytes(),
            reser,
            "envelope round-trip must be stable"
        );
    }
});
