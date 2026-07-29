// SPDX-License-Identifier: Apache-2.0

//! Wire codec — length-prefixed framing for channel messages.
//!
//! Frame format:
//! ```text
//! ┌──────────────────┬─────────────────────────┐
//! │ length (4B BE)   │ payload (length bytes)   │
//! └──────────────────┴─────────────────────────┘
//! ```
//!
//! Maximum frame size is 16 MiB to prevent memory exhaustion attacks.

use crate::error::{ChannelError, Result};

/// Maximum frame payload size (16 MiB).
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Length prefix size in bytes.
pub const LENGTH_PREFIX_SIZE: usize = 4;

/// Encode a payload into a length-prefixed frame.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_FRAME_SIZE {
        return Err(ChannelError::Codec(format!(
            "payload too large: {} bytes (max {})",
            payload.len(),
            MAX_FRAME_SIZE
        )));
    }
    let mut frame = Vec::with_capacity(LENGTH_PREFIX_SIZE + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Decode a length-prefixed frame, returning the payload and bytes consumed.
/// Returns None if the buffer doesn't contain a complete frame yet.
pub fn decode_frame(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>> {
    if buf.len() < LENGTH_PREFIX_SIZE {
        return Ok(None); // incomplete header
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(ChannelError::Codec(format!(
            "frame size {len} exceeds maximum {MAX_FRAME_SIZE}"
        )));
    }
    let total = LENGTH_PREFIX_SIZE + len;
    if buf.len() < total {
        return Ok(None); // incomplete payload
    }
    Ok(Some((buf[LENGTH_PREFIX_SIZE..total].to_vec(), total)))
}

/// Encode a message with a 1-byte type tag prepended before framing.
pub fn encode_typed(msg_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let mut inner = Vec::with_capacity(1 + payload.len());
    inner.push(msg_type);
    inner.extend_from_slice(payload);
    encode_frame(&inner)
}

/// Decode a typed message, returning (type_tag, payload, bytes_consumed).
pub fn decode_typed(buf: &[u8]) -> Result<Option<(u8, Vec<u8>, usize)>> {
    match decode_frame(buf)? {
        None => Ok(None),
        Some((inner, consumed)) => {
            if inner.is_empty() {
                return Err(ChannelError::Codec("empty frame body".into()));
            }
            let tag = inner[0];
            let payload = inner[1..].to_vec();
            Ok(Some((tag, payload, consumed)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_frame() {
        let payload = b"hello channel";
        let frame = encode_frame(payload).unwrap();
        assert_eq!(frame.len(), LENGTH_PREFIX_SIZE + payload.len());
        let (decoded, consumed) = decode_frame(&frame).unwrap().unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn incomplete_frame_returns_none() {
        let frame = encode_frame(b"test data").unwrap();
        // Truncate
        let partial = &frame[..frame.len() - 3];
        assert!(decode_frame(partial).unwrap().is_none());
    }

    #[test]
    fn empty_payload() {
        let frame = encode_frame(b"").unwrap();
        let (decoded, _) = decode_frame(&frame).unwrap().unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn oversized_rejected() {
        let result = encode_frame(&vec![0u8; MAX_FRAME_SIZE + 1]);
        assert!(result.is_err());
    }

    #[test]
    fn typed_roundtrip() {
        let frame = encode_typed(0x42, b"typed payload").unwrap();
        let (tag, payload, consumed) = decode_typed(&frame).unwrap().unwrap();
        assert_eq!(tag, 0x42);
        assert_eq!(payload, b"typed payload");
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn multiple_frames_in_buffer() {
        let f1 = encode_frame(b"first").unwrap();
        let f2 = encode_frame(b"second").unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&f1);
        buf.extend_from_slice(&f2);

        let (p1, consumed1) = decode_frame(&buf).unwrap().unwrap();
        assert_eq!(p1, b"first");
        let (p2, consumed2) = decode_frame(&buf[consumed1..]).unwrap().unwrap();
        assert_eq!(p2, b"second");
        assert_eq!(consumed1 + consumed2, buf.len());
    }
}
