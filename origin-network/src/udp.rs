// SPDX-License-Identifier: Apache-2.0

//! UDP frame transport — datagram-pure core (spec §6.1, §8.3).
//!
//! `UdpFrameConn` implements `FrameConn` over a CONNECTED UDP socket.
//! Each frame is exactly one datagram; UDP delivers whole datagrams or
//! nothing, so there is no partial-frame buffering (contrast with TCP's
//! stream reassembly). The codec's 16MB cap is unreachable on UDP —
//! datagrams are bounded by the network MTU; we enforce a conservative
//! frame ceiling so oversized frames fail loudly instead of fragmenting
//! silently (fragmented UDP is dropped wholesale by most NATs).
//!
//! This is the transport NAT-traversed pipes ride: `nat::hole_punch`
//! returns a connected `UdpSocket`; wrapping it here yields a `FrameConn`
//! the session layer (`Endpoint::drive`) can run Noise IK over.
//! Reliability/stream/file semantics live ABOVE this (spec §4), not here.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::error::{NetworkError, Result};
use crate::transport::TransportAddr;
use crate::wire::{encode_wire, WireType};

/// Largest frame we will send/accept as a single datagram. Well below
/// the 64KB UDP ceiling — realistic handshake/control frames are a few
/// KB, and anything larger should ride the stream layer.
pub const MAX_DATAGRAM_FRAME: usize = 48 * 1024;

/// Default per-recv deadline for a UDP frame connection. A peer that
/// punches but never sends a real frame would otherwise loop forever in
/// `recv_frame().await`; this bounds it.
pub const UDP_RECV_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `FrameConn` over a connected UDP socket.
#[derive(Debug)]
pub struct UdpFrameConn {
    socket: UdpSocket,
    peer: SocketAddr,
    recv_timeout: std::time::Duration,
}

impl UdpFrameConn {
    /// Wrap an already-connected socket (e.g. from `nat::hole_punch` or
    /// `nat::dial_direct`). The punch-socket law is enforced by callers:
    /// the socket must be fresh per attempt, never a shared listener.
    pub fn from_connected(socket: UdpSocket) -> Result<Self> {
        let peer = socket
            .peer_addr()
            .map_err(|e| NetworkError::Transport(format!("socket not connected: {e}")))?;
        Ok(Self {
            socket,
            peer,
            recv_timeout: UDP_RECV_TIMEOUT,
        })
    }

    /// Fresh connect: bind anywhere + connect to `peer` (direct dial).
    pub async fn connect(peer: SocketAddr) -> Result<Self> {
        let socket = crate::nat::fresh_punch_socket(peer.is_ipv6()).await?;
        socket
            .connect(peer)
            .await
            .map_err(|e| NetworkError::Transport(e.to_string()))?;
        Self::from_connected(socket)
    }

    /// The connected peer address.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Consume and return the inner socket (for the stream layer to
    /// adopt once traversal completes).
    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }
}

#[async_trait::async_trait]
impl crate::transport::FrameConn for UdpFrameConn {
    async fn send_frame(&mut self, typ: u8, payload: &[u8]) -> Result<()> {
        let frame = if WireType::is_network_owned(typ) || WireType::from_u8(typ).is_some() {
            encode_wire(
                WireType::from_u8(typ)
                    .ok_or_else(|| NetworkError::Codec(format!("unknown wire type {typ:#04x}")))?,
                payload,
            )?
        } else {
            origin_channel::codec::encode_typed(typ, payload)
                .map_err(|e| NetworkError::Codec(e.to_string()))?
        };
        if frame.len() > MAX_DATAGRAM_FRAME {
            return Err(NetworkError::Codec(format!(
                "frame {} exceeds UDP datagram ceiling {}",
                frame.len(),
                MAX_DATAGRAM_FRAME
            )));
        }
        self.socket
            .send(&frame)
            .await
            .map_err(|e| NetworkError::Transport(e.to_string()))?;
        Ok(())
    }

    async fn recv_frame(&mut self) -> Result<(u8, Vec<u8>)> {
        // One datagram = one frame. Oversized datagrams are rejected by
        // the decoder's frame cap anyway; truncation is impossible on a
        // connected socket with a generously-sized buffer.
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = tokio::time::timeout(self.recv_timeout, self.socket.recv(&mut buf))
                .await
                .map_err(|_| NetworkError::Timeout("udp recv timed out".into()))?
                .map_err(|e| NetworkError::Transport(e.to_string()))?;
            let frame = &buf[..n];
            // Skip punch probes: a peer may still be punching our mapping
            // while we wait; non-frame datagrams are noise, not errors.
            if frame.starts_with(crate::nat::PUNCH_PROBE) || frame.is_empty() {
                continue;
            }
            return crate::wire::decode_wire(frame)?
                .map(|(tag, payload, _consumed)| (tag, payload))
                .ok_or_else(|| NetworkError::Codec("incomplete UDP frame".into()));
        }
    }

    fn peer_addr(&self) -> TransportAddr {
        TransportAddr::Udp(self.peer)
    }

    async fn close(&mut self) -> Result<()> {
        // UDP has no teardown; closing the socket drops the mapping.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::FrameConn;

    #[tokio::test]
    async fn udp_frame_roundtrip_network_owned() {
        let a_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a_sock.local_addr().unwrap();
        let b_addr = b_sock.local_addr().unwrap();
        a_sock.connect(b_addr).await.unwrap();
        b_sock.connect(a_addr).await.unwrap();

        let mut a = UdpFrameConn::from_connected(a_sock).unwrap();
        let mut b = UdpFrameConn::from_connected(b_sock).unwrap();

        a.send_frame(WireType::Probe.to_u8(), b"{\"target_fp\":[1,2,3]}")
            .await
            .unwrap();
        let (tag, payload) = b.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::Probe.to_u8());
        assert_eq!(payload, b"{\"target_fp\":[1,2,3]}");
    }

    #[tokio::test]
    async fn udp_frame_roundtrip_channel_passthrough() {
        let a_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a_sock.local_addr().unwrap();
        let b_addr = b_sock.local_addr().unwrap();
        a_sock.connect(b_addr).await.unwrap();
        b_sock.connect(a_addr).await.unwrap();

        let mut a = UdpFrameConn::from_connected(a_sock).unwrap();
        let mut b = UdpFrameConn::from_connected(b_sock).unwrap();

        // Channel DATA frame (0x10) — pass-through range.
        a.send_frame(0x10, b"ciphertext-bytes").await.unwrap();
        let (tag, payload) = b.recv_frame().await.unwrap();
        assert_eq!(tag, 0x10);
        assert_eq!(payload, b"ciphertext-bytes");
    }

    #[tokio::test]
    async fn udp_connect_helper() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let mut conn = UdpFrameConn::connect(target_addr).await.unwrap();
        assert_eq!(conn.peer(), target_addr);
        conn.send_frame(WireType::Probe.to_u8(), b"{}")
            .await
            .unwrap();
        let mut buf = vec![0u8; 512];
        let n = target.recv(&mut buf).await.unwrap();
        assert!(n > 0);
    }

    #[tokio::test]
    async fn udp_oversize_frame_rejected() {
        let a_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_addr = b_sock.local_addr().unwrap();
        a_sock.connect(b_addr).await.unwrap();
        let mut a = UdpFrameConn::from_connected(a_sock).unwrap();

        let big = vec![0u8; MAX_DATAGRAM_FRAME + 1];
        let err = a
            .send_frame(WireType::InboxPush.to_u8(), &big)
            .await
            .unwrap_err();
        assert!(matches!(err, NetworkError::Codec(_)));
    }

    #[tokio::test]
    async fn udp_from_unconnected_socket_errors() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let err = UdpFrameConn::from_connected(sock).unwrap_err();
        assert!(matches!(err, NetworkError::Transport(_)));
    }

    #[tokio::test]
    async fn udp_punch_probe_skipped_on_recv() {
        let a_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a_sock.local_addr().unwrap();
        let b_addr = b_sock.local_addr().unwrap();
        a_sock.connect(b_addr).await.unwrap();
        b_sock.connect(a_addr).await.unwrap();

        let mut b = UdpFrameConn::from_connected(b_sock).unwrap();

        // Send a punch probe, then a real frame.
        a_sock.send(crate::nat::PUNCH_PROBE).await.unwrap();
        let mut a = UdpFrameConn::from_connected(a_sock).unwrap();
        a.send_frame(WireType::Probe.to_u8(), b"{}").await.unwrap();

        // The probe is skipped; recv yields the real frame.
        let (tag, _payload) = b.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::Probe.to_u8());
    }

    #[tokio::test]
    async fn udp_peer_addr_is_udp_variant() {
        let a_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_addr = b_sock.local_addr().unwrap();
        a_sock.connect(b_addr).await.unwrap();
        let conn = UdpFrameConn::from_connected(a_sock).unwrap();
        assert!(matches!(conn.peer_addr(), TransportAddr::Udp(sa) if sa == b_addr));
    }

    #[tokio::test]
    async fn udp_close_is_clean_noop() {
        let a_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_addr = b_sock.local_addr().unwrap();
        a_sock.connect(b_addr).await.unwrap();
        let mut conn = UdpFrameConn::from_connected(a_sock).unwrap();
        conn.close().await.unwrap();
    }
}
