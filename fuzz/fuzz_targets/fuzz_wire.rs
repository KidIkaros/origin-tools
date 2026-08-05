// SPDX-License-Identifier: Apache-2.0

//! Fuzz origin-network wire decoding.
//!
//! Targets:
//! 1. `decode_wire` on arbitrary bytes — must never panic, and any
//!    "complete frame" it claims must round-trip through `encode_wire`
//!    losslessly (type byte + payload preserved).
//! 2. Structured re-encode: every successfully decoded frame with a known
//!    wire type is re-encoded and decoded again; the two decodes must agree.
//! 3. `decode_payload` of every control payload type on fuzzed frame
//!    bodies — serde must reject garbage, never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use origin_network::relay_server::ProbeResponse;
use origin_network::wire::{
    decode_payload, decode_wire, encode_wire, AdvertFetch, AdvertPublish, AuthClaim, AuthOk,
    AuthReject, InboxPull, InboxPush, Probe, SessionClose, SessionOpen, WireError, WireType,
};

fuzz_target!(|data: &[u8]| {
    // 1. Raw frame decoding must be total: Ok(None) (incomplete),
    //    Ok(Some(..)) (complete), or Err (malformed) — never panic.
    let decoded = match decode_wire(data) {
        Ok(d) => d,
        Err(_) => return, // malformed: fine, decoder rejected it
    };
    let Some((tag, payload, consumed)) = decoded else {
        return; // incomplete frame: fine
    };

    // Consumed bytes must not exceed the buffer.
    assert!(consumed <= data.len());

    // 2. Re-encode round-trip for known wire types: the decoder's claim
    //    must be stable. Unknown tags can't be re-encoded (encode_wire takes
    //    WireType), which is itself the correct behaviour.
    if let Some(wt) = WireType::from_u8(tag) {
        let reencoded = encode_wire(wt, &payload).expect("re-encode of decoded frame");
        match decode_wire(&reencoded) {
            Ok(Some((tag2, payload2, consumed2))) => {
                assert_eq!(tag, tag2, "tag changed across round-trip");
                assert_eq!(payload, payload2, "payload changed across round-trip");
                assert_eq!(consumed2, reencoded.len());
            }
            other => panic!("re-encoded frame failed to decode: {other:?}"),
        }
    }

    // 3. Payload-level decoding on fuzzed bodies: every known control
    //    type must either parse or cleanly reject.
    let _ = decode_payload::<WireError>(&payload);
    let _ = decode_payload::<SessionOpen>(&payload);
    let _ = decode_payload::<SessionClose>(&payload);
    let _ = decode_payload::<InboxPush>(&payload);
    let _ = decode_payload::<InboxPull>(&payload);
    let _ = decode_payload::<Probe>(&payload);
    let _ = decode_payload::<ProbeResponse>(&payload);
    let _ = decode_payload::<AdvertPublish>(&payload);
    let _ = decode_payload::<AdvertFetch>(&payload);
    let _ = decode_payload::<AuthClaim>(&payload);
    let _ = decode_payload::<AuthOk>(&payload);
    let _ = decode_payload::<AuthReject>(&payload);
});
