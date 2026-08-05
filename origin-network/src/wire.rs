// SPDX-License-Identifier: Apache-2.0

//! Wire framing — reuses origin-channel's codec, owns CONTROL/ERROR ranges.
//!
//! Spec REV 3 §4: channel frames (`0x01..0x3F`) pass through verbatim;
//! origin-network owns `0x40..0x5F` (CONTROL) and `0xF0..0xFF` (ERROR).
//!
//! Frame format (origin-channel codec):
//! ```text
//! [4B length BE][1B type][payload ≤ 16MB]
//! ```

use serde::{Deserialize, Serialize};

pub use origin_channel::codec::{decode_frame, encode_frame, MAX_FRAME_SIZE};

use crate::error::{NetworkError, Result};

// ── Network-owned wire types ────────────────────────────────────────────

/// CONTROL range start (relay-terminated operations).
pub const TYPE_CONTROL_BASE: u8 = 0x40;
/// ERROR range start.
pub const TYPE_ERROR_BASE: u8 = 0xF0;

/// Network-layer wire message types owned by origin-network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireType {
    // Pass-through channel ranges (documented, not constructed here):
    // 0x01..=0x03 HANDSHAKE_*, 0x10 DATA, 0x20 CLOSE, 0x30/0x31 PING/PONG
    /// AUTH claim after Noise IK (agent → relay/peer).
    AuthClaim = 0x40,
    /// AUTH response: accepted, carries session token (relay only).
    AuthOk = 0x41,
    /// AUTH response: rejected with reason.
    AuthReject = 0x42,
    /// Request forwarding to a target fingerprint.
    SessionOpen = 0x43,
    /// Tear down a forwarding pair.
    SessionClose = 0x44,
    /// Store-and-forward for an offline target.
    InboxPush = 0x45,
    /// Retrieve buffered frames (read-once).
    InboxPull = 0x46,
    /// Online/offline status probe (boolean answer only).
    Probe = 0x47,
    /// Publish an endpoint advertisement (replaceable, latest wins).
    AdvertPublish = 0x48,
    /// Fetch a peer's current advertisement.
    AdvertFetch = 0x49,
    /// Multiplexed stream frame: `[4B stream id][inner channel frame]`.
    MuxFrame = 0x4A,
    /// Subscribe to presence changes for a target fingerprint (client → relay).
    PresenceSubscribe = 0x4B,
    /// Presence change notification (relay → client, push).
    PresenceEvent = 0x4C,
    /// Generic error frame.
    Error = 0xF0,
}

impl WireType {
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x40 => Self::AuthClaim,
            0x41 => Self::AuthOk,
            0x42 => Self::AuthReject,
            0x43 => Self::SessionOpen,
            0x44 => Self::SessionClose,
            0x45 => Self::InboxPush,
            0x46 => Self::InboxPull,
            0x47 => Self::Probe,
            0x48 => Self::AdvertPublish,
            0x49 => Self::AdvertFetch,
            0x4A => Self::MuxFrame,
            0x4B => Self::PresenceSubscribe,
            0x4C => Self::PresenceEvent,
            0xF0 => Self::Error,
            _ => return None,
        })
    }

    /// True if this type is in the channel pass-through range.
    pub fn is_channel_passthrough(v: u8) -> bool {
        (0x01..=0x3F).contains(&v)
    }

    /// True if this type is network-owned (CONTROL or ERROR range).
    pub fn is_network_owned(v: u8) -> bool {
        (0x40..=0x5F).contains(&v) || (0xF0..=0xFF).contains(&v)
    }
}

/// Encode a network-owned frame: `[4B len][1B type][payload]`.
pub fn encode_wire(t: WireType, payload: &[u8]) -> Result<Vec<u8>> {
    encode_frame(&{
        let mut v = Vec::with_capacity(1 + payload.len());
        v.push(t.to_u8());
        v.extend_from_slice(payload);
        v
    })
    .map_err(|e| NetworkError::Codec(e.to_string()))
}

/// Decode a complete frame from a buffer.
/// Returns `Ok(None)` if the buffer holds no complete frame yet.
/// Rejects frames whose payload exceeds the 16MB codec cap.
pub fn decode_wire(buf: &[u8]) -> Result<Option<(u8, Vec<u8>, usize)>> {
    origin_channel::codec::decode_typed(buf).map_err(|e| NetworkError::Codec(e.to_string()))
}

// ── CONTROL payloads (serde JSON, bounded) ──────────────────────────────

/// AUTH claim sent encrypted after Noise IK completes (spec §3.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthClaim {
    /// Claimed identity fingerprint.
    pub fingerprint: [u8; 32],
    /// Transport key authenticated by the Noise handshake.
    pub x25519_pk: [u8; 32],
    /// Hybrid Ed25519+Falcon signature over
    /// `(transcript ‖ relay_fp ‖ nonce)` — proves fingerprint↔key ownership.
    pub hybrid_signature: Vec<u8>,
    /// Protocol version for coexistence (mandatory, spec §6.6).
    pub protocol_version: u16,
    /// Fresh nonce binding the claim to this handshake.
    pub nonce: [u8; 16],
}

/// AUTH OK response with session token (relay → agent).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthOk {
    pub session_token: String,
}

/// AUTH rejection reason (relay → agent).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthReject {
    pub reason: String,
}

/// Request forwarding to a target fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionOpen {
    pub target_fp: [u8; 32],
}

/// Tear down a forwarding pair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionClose {
    pub pair_id: u64,
}

/// Store-and-forward push for an offline target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboxPush {
    pub target_fp: [u8; 32],
    /// The opaque (encrypted) frame to buffer.
    pub frame: Vec<u8>,
}

/// Retrieve buffered frames for this session's fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboxPull;

/// Online/offline probe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Probe {
    pub target_fp: [u8; 32],
}

/// Endpoint advertisement (spec §8.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Advert {
    /// Protocol version the responder speaks.
    pub protocol_version: u16,
    /// Reachable endpoint candidates (host:port strings), best first.
    pub endpoints: Vec<String>,
    /// Seconds from publication until the advert expires.
    pub ttl_secs: u64,
    /// Presence hint (opaque to the relay).
    pub presence: u8,
}

/// Publish an advert for the session's own fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvertPublish {
    pub advert: Advert,
}

/// Fetch a fingerprint's current advert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvertFetch {
    pub target_fp: [u8; 32],
}

/// Generic error payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireError {
    pub code: String,
    pub detail: String,
}

/// Subscribe to presence changes for a target fingerprint (spec §8.2).
/// Subscription-based, not polling: the relay pushes `PresenceEvent`
/// frames whenever the target registers or deregisters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceSubscribe {
    pub target_fp: [u8; 32],
}

/// Presence change notification pushed by the relay to subscribers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceEvent {
    /// The peer whose presence changed.
    pub target_fp: [u8; 32],
    /// True = registered (came online), false = deregistered.
    pub online: bool,
}

/// Serialize a CONTROL/ERROR payload to JSON bytes (bounded by frame cap).
pub fn encode_payload<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|e| NetworkError::Codec(e.to_string()))
}

/// Deserialize a CONTROL/ERROR payload from JSON bytes.
pub fn decode_payload<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T> {
    serde_json::from_slice(b).map_err(|e| NetworkError::Codec(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_type_roundtrip_all() {
        for t in [
            WireType::AuthClaim,
            WireType::AuthOk,
            WireType::AuthReject,
            WireType::SessionOpen,
            WireType::SessionClose,
            WireType::InboxPush,
            WireType::InboxPull,
            WireType::Probe,
            WireType::AdvertPublish,
            WireType::AdvertFetch,
            WireType::MuxFrame,
            WireType::PresenceSubscribe,
            WireType::PresenceEvent,
            WireType::Error,
        ] {
            assert_eq!(WireType::from_u8(t.to_u8()), Some(t), "{t:?}");
        }
    }

    #[test]
    fn wire_type_ranges_disjoint() {
        // Network-owned types never collide with channel pass-through.
        for v in 0x01..=0x3F {
            assert!(WireType::is_channel_passthrough(v));
            assert!(!WireType::is_network_owned(v));
        }
        assert!(WireType::is_network_owned(0x40));
        assert!(WireType::is_network_owned(0x5F));
        assert!(WireType::is_network_owned(0xF0));
        assert!(!WireType::is_network_owned(0x60));
        assert!(!WireType::is_network_owned(0xEF));
    }

    #[test]
    fn unknown_wire_type_is_none() {
        assert_eq!(WireType::from_u8(0x00), None);
        assert_eq!(WireType::from_u8(0x60), None);
        assert_eq!(WireType::from_u8(0xEF), None);
        assert_eq!(WireType::from_u8(0xFF), None);
    }

    #[test]
    fn encode_decode_wire_roundtrip() {
        let payload = b"hello substrate";
        let frame = encode_wire(WireType::Probe, payload).unwrap();
        let (tag, body, consumed) = decode_wire(&frame).unwrap().unwrap();
        assert_eq!(tag, WireType::Probe.to_u8());
        assert_eq!(body, payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn decode_wire_incomplete_returns_none() {
        let frame = encode_wire(WireType::InboxPull, b"x").unwrap();
        assert!(decode_wire(&frame[..3]).unwrap().is_none());
        assert!(decode_wire(&frame[..frame.len() - 1]).unwrap().is_none());
        assert!(decode_wire(b"").unwrap().is_none());
    }

    #[test]
    fn decode_wire_partial_buffer_then_complete() {
        let f1 = encode_wire(WireType::Probe, b"one").unwrap();
        let f2 = encode_wire(WireType::Probe, b"two").unwrap();
        let mut buf = f1.clone();
        buf.extend_from_slice(&f2);
        let (_, b1, c1) = decode_wire(&buf).unwrap().unwrap();
        assert_eq!(b1, b"one");
        let (_, b2, _) = decode_wire(&buf[c1..]).unwrap().unwrap();
        assert_eq!(b2, b"two");
    }

    #[test]
    fn frame_oversize_rejected() {
        // 16MB cap from the channel codec — encoding above it must fail.
        let big = vec![0u8; MAX_FRAME_SIZE + 1];
        assert!(encode_wire(WireType::Error, &big).is_err());
        // Decode side: forge a header claiming beyond the cap.
        let forged = [(MAX_FRAME_SIZE + 1) as u8; 4];
        assert!(decode_wire(&forged).is_err());
    }

    #[test]
    fn auth_claim_payload_roundtrip() {
        let claim = AuthClaim {
            fingerprint: [1; 32],
            x25519_pk: [2; 32],
            hybrid_signature: vec![9; 128],
            protocol_version: 1,
            nonce: [7; 16],
        };
        let bytes = encode_payload(&claim).unwrap();
        assert_eq!(decode_payload::<AuthClaim>(&bytes).unwrap(), claim);
    }

    #[test]
    fn control_payloads_roundtrip() {
        let open = SessionOpen { target_fp: [3; 32] };
        assert_eq!(
            decode_payload::<SessionOpen>(&encode_payload(&open).unwrap()).unwrap(),
            open
        );
        let close = SessionClose { pair_id: 42 };
        assert_eq!(
            decode_payload::<SessionClose>(&encode_payload(&close).unwrap()).unwrap(),
            close
        );
        let push = InboxPush {
            target_fp: [4; 32],
            frame: vec![1, 2, 3],
        };
        assert_eq!(
            decode_payload::<InboxPush>(&encode_payload(&push).unwrap()).unwrap(),
            push
        );
        let probe = Probe { target_fp: [5; 32] };
        assert_eq!(
            decode_payload::<Probe>(&encode_payload(&probe).unwrap()).unwrap(),
            probe
        );
        let ok = AuthOk {
            session_token: "tok".into(),
        };
        assert_eq!(
            decode_payload::<AuthOk>(&encode_payload(&ok).unwrap()).unwrap(),
            ok
        );
        let rej = AuthReject {
            reason: "evicted".into(),
        };
        assert_eq!(
            decode_payload::<AuthReject>(&encode_payload(&rej).unwrap()).unwrap(),
            rej
        );
    }

    #[test]
    fn advert_roundtrip() {
        let pub_msg = AdvertPublish {
            advert: Advert {
                protocol_version: 1,
                endpoints: vec!["192.168.1.5:7331".into(), "[fd00::1]:7331".into()],
                ttl_secs: 300,
                presence: 1,
            },
        };
        let bytes = encode_payload(&pub_msg).unwrap();
        assert_eq!(decode_payload::<AdvertPublish>(&bytes).unwrap(), pub_msg);

        let fetch = AdvertFetch { target_fp: [6; 32] };
        assert_eq!(
            decode_payload::<AdvertFetch>(&encode_payload(&fetch).unwrap()).unwrap(),
            fetch
        );
    }

    #[test]
    fn wire_error_roundtrip() {
        let e = WireError {
            code: "relay_full".into(),
            detail: "at capacity 1000".into(),
        };
        let bytes = encode_payload(&e).unwrap();
        assert_eq!(decode_payload::<WireError>(&bytes).unwrap(), e);
    }

    #[test]
    fn decode_payload_rejects_garbage() {
        assert!(decode_payload::<AuthClaim>(b"{not json").is_err());
        assert!(decode_payload::<SessionOpen>(b"[]").is_err());
    }

    #[test]
    fn channel_frames_pass_through_verbatim() {
        // A channel DATA frame (0x10) wrapped as-is must decode with its
        // type intact — the network never rewrites channel bytes.
        let inner = vec![0x10, 0, 0, 0, 0, 1, 0xAA];
        let frame = encode_frame(&inner).unwrap();
        let (tag, body, _) = decode_wire(&frame).unwrap().unwrap();
        assert_eq!(tag, 0x10);
        assert_eq!(body, &inner[1..]);
    }
}
