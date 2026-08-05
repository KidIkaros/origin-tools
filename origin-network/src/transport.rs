// SPDX-License-Identifier: Apache-2.0

//! Transport layer — datagram/frame delivery over a medium (spec §6.1).
//!
//! FIPS discipline adopted: a transport delivers frames to **opaque
//! transport addresses** and reports MTU. It knows nothing about Origin
//! identities, routing, or encryption; identity binding happens at the
//! handshake layer above.
//!
//! One transport serves many endpoints simultaneously and keeps no
//! per-endpoint state.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use crate::error::{NetworkError, Result};
use crate::wire::{decode_wire, encode_wire, WireType};

/// Default MTU reported by stream transports (TCP has no inherent MTU;
/// we use a practical working size for framing decisions — fits u16).
pub const DEFAULT_STREAM_MTU: u16 = 32 * 1024;

/// Opaque transport address — everything above the transport sees only
/// identities; this type never escapes the transport layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportAddr {
    /// TCP socket address.
    Tcp(SocketAddr),
    /// UDP socket address (NAT-traversed / punched connections).
    Udp(SocketAddr),
    /// QUIC socket address (feature-gated transport, spec phase 2).
    Quic(SocketAddr),
    /// Loopback in-memory pipe (tests, local IPC).
    Memory(String),
}

impl fmt::Display for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(a) => write!(f, "tcp://{a}"),
            Self::Udp(a) => write!(f, "udp://{a}"),
            Self::Quic(a) => write!(f, "quic://{a}"),
            Self::Memory(id) => write!(f, "mem://{id}"),
        }
    }
}

/// A transport delivers frames to transport addresses.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Connect to a remote transport address.
    async fn connect(&self, addr: &TransportAddr) -> Result<Box<dyn FrameConn>>;
    /// Accept the next inbound connection (listener transports).
    async fn accept(&self) -> Result<Box<dyn FrameConn>>;
    /// Transport-wide default MTU.
    fn mtu(&self) -> u16;
    /// Per-link MTU for a specific remote address. Uniform transports
    /// (TCP) fall back to `mtu()` — per-link negotiation matters for
    /// e.g. BLE later.
    fn link_mtu(&self, _addr: &TransportAddr) -> u16 {
        self.mtu()
    }
    /// Local address the transport listens on, if applicable.
    fn local_addr(&self) -> Option<TransportAddr>;
}

/// A single frame-oriented connection to one transport endpoint.
#[async_trait]
pub trait FrameConn: Send + Sync {
    /// Send one typed frame.
    async fn send_frame(&mut self, typ: u8, payload: &[u8]) -> Result<()>;
    /// Receive the next typed frame.
    async fn recv_frame(&mut self) -> Result<(u8, Vec<u8>)>;
    /// Remote transport address.
    fn peer_addr(&self) -> TransportAddr;
    /// Close the connection.
    async fn close(&mut self) -> Result<()>;
}

// ── TCP transport ───────────────────────────────────────────────────────

/// TCP transport: connects and accepts framed connections.
pub struct TcpTransport {
    listener: Option<TcpListener>,
    local: Option<SocketAddr>,
}

impl TcpTransport {
    /// Bind a listener on `addr` (use port 0 for OS-assigned).
    pub async fn listen(addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| NetworkError::Transport(format!("bind {addr}: {e}")))?;
        let local = listener
            .local_addr()
            .map_err(|e| NetworkError::Transport(e.to_string()))?;
        Ok(Self {
            listener: Some(listener),
            local: Some(local),
        })
    }

    /// Connector-only transport (no listener).
    pub fn connector() -> Self {
        Self {
            listener: None,
            local: None,
        }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&self, addr: &TransportAddr) -> Result<Box<dyn FrameConn>> {
        let TransportAddr::Tcp(target) = addr else {
            return Err(NetworkError::Transport(format!(
                "tcp transport cannot dial {addr}"
            )));
        };
        let stream = TcpStream::connect(*target)
            .await
            .map_err(|e| NetworkError::Transport(format!("connect {target}: {e}")))?;
        stream
            .set_nodelay(true)
            .map_err(|e| NetworkError::Transport(e.to_string()))?;
        Ok(Box::new(TcpFrameConn::new(stream, *target)))
    }

    async fn accept(&self) -> Result<Box<dyn FrameConn>> {
        let Some(listener) = &self.listener else {
            return Err(NetworkError::Transport(
                "connector transport cannot accept".into(),
            ));
        };
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|e| NetworkError::Transport(e.to_string()))?;
        stream
            .set_nodelay(true)
            .map_err(|e| NetworkError::Transport(e.to_string()))?;
        Ok(Box::new(TcpFrameConn::new(stream, peer)))
    }

    fn mtu(&self) -> u16 {
        DEFAULT_STREAM_MTU
    }

    fn local_addr(&self) -> Option<TransportAddr> {
        self.local.map(TransportAddr::Tcp)
    }
}

/// TCP frame connection with an internal read buffer.
pub struct TcpFrameConn {
    stream: TcpStream,
    peer: SocketAddr,
    buf: Vec<u8>,
}

impl TcpFrameConn {
    fn new(stream: TcpStream, peer: SocketAddr) -> Self {
        Self {
            stream,
            peer,
            buf: Vec::with_capacity(64 * 1024),
        }
    }

    async fn read_more(&mut self) -> Result<()> {
        let mut chunk = vec![0u8; 64 * 1024];
        let n = self
            .stream
            .read(&mut chunk)
            .await
            .map_err(|e| NetworkError::Transport(e.to_string()))?;
        if n == 0 {
            return Err(NetworkError::Transport("peer closed connection".into()));
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }
}

#[async_trait]
impl FrameConn for TcpFrameConn {
    async fn send_frame(&mut self, typ: u8, payload: &[u8]) -> Result<()> {
        // Network-owned types go through encode_wire; channel pass-through
        // frames are re-wrapped preserving their type byte.
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
        self.stream
            .write_all(&frame)
            .await
            .map_err(|e| NetworkError::Transport(e.to_string()))?;
        Ok(())
    }

    async fn recv_frame(&mut self) -> Result<(u8, Vec<u8>)> {
        loop {
            if let Some((tag, payload, consumed)) = decode_wire(&self.buf)? {
                self.buf.drain(..consumed);
                return Ok((tag, payload));
            }
            self.read_more().await?;
        }
    }

    fn peer_addr(&self) -> TransportAddr {
        TransportAddr::Tcp(self.peer)
    }

    async fn close(&mut self) -> Result<()> {
        self.stream
            .shutdown()
            .await
            .map_err(|e| NetworkError::Transport(e.to_string()))
    }
}

// ── Stream multiplexing over one connection ─────────────────────────────
//
// TCP phase: N logical streams share one FrameConn. Each stream is
// identified by a u32 id — odd = initiator-opened, even = responder-opened
// (HTTP/2 discipline, prevents id collisions). Frames ride as
// `WireType::MuxFrame` with a `[4B stream id]` prefix; CONTROL frames
// (handshake, auth, relay ops) are not multiplexed.

/// Handle for one logical stream over a multiplexed connection.
pub struct StreamHandle {
    pub id: u32,
    tx: mpsc::UnboundedSender<(u32, Vec<u8>)>,
    rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    closed: Arc<AtomicBool>,
}

impl StreamHandle {
    /// Send payload on this stream (wrapped as MuxFrame by the demuxer).
    pub fn send(&self, payload: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(NetworkError::Transport("stream closed".into()));
        }
        self.tx
            .send((self.id, payload.to_vec()))
            .map_err(|_| NetworkError::Transport("connection closed".into()))
    }

    /// Receive the next payload from this stream.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| NetworkError::Transport("stream closed".into()))
    }

    /// Whether this stream has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// One mux stream's slot: payload channel plus closed flag.
type StreamSlot = (mpsc::UnboundedSender<Vec<u8>>, Arc<AtomicBool>);

/// Demultiplexer: routes inbound frames to per-stream channels and hands
/// non-mux frames to a control channel.
pub struct Demux {
    streams: Mutex<HashMap<u32, StreamSlot>>,
    next_id: Mutex<u32>,
    outbound_tx: mpsc::UnboundedSender<(u32, Vec<u8>)>,
}

impl Demux {
    /// Create a demuxer. `is_initiator` selects odd/even stream id parity.
    /// The outbound receiver yields `(stream_id, payload)` pairs for the
    /// connection writer to wrap as MuxFrames.
    pub fn new(is_initiator: bool) -> (Self, mpsc::UnboundedReceiver<(u32, Vec<u8>)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let start = if is_initiator { 1 } else { 2 };
        (
            Self {
                streams: Mutex::new(HashMap::new()),
                next_id: Mutex::new(start),
                outbound_tx: tx,
            },
            rx,
        )
    }

    /// Open a new local stream; returns a handle wired through this demuxer.
    pub async fn open_stream(&self) -> StreamHandle {
        let mut next = self.next_id.lock().await;
        let id = *next;
        *next += 2;
        drop(next);
        self.register_stream(id).await
    }

    async fn register_stream(&self, id: u32) -> StreamHandle {
        let (stx, srx) = mpsc::unbounded_channel();
        let closed = Arc::new(AtomicBool::new(false));
        self.streams
            .lock()
            .await
            .insert(id, (stx, Arc::clone(&closed)));
        StreamHandle {
            id,
            tx: self.outbound_tx.clone(),
            rx: Mutex::new(srx),
            closed,
        }
    }

    /// Route one inbound frame. MuxFrames go to their stream channel;
    /// everything else is returned to the caller for control handling.
    pub async fn route_inbound(&self, tag: u8, payload: Vec<u8>) -> Option<(u8, Vec<u8>)> {
        if tag == WireType::MuxFrame.to_u8() {
            // A MuxFrame MUST carry a [4B stream id][inner frame]. A shorter
            // payload is malformed: surface it as a control ERROR rather than
            // forwarding an unparsable frame to the control path.
            if payload.len() < 4 {
                return Some((
                    WireType::Error.to_u8(),
                    format!("malformed MuxFrame: {} bytes < 4", payload.len()).into_bytes(),
                ));
            }
            let id = u32::from_be_bytes(payload[..4].try_into().unwrap());
            let body = payload[4..].to_vec();
            let streams = self.streams.lock().await;
            if let Some((ch, _)) = streams.get(&id) {
                let _ = ch.send(body); // closed streams drop silently
                None
            } else {
                // Unknown stream id → surface to control for error handling.
                Some((tag, payload))
            }
        } else {
            Some((tag, payload))
        }
    }

    /// Encode a (stream_id, payload) pair into MuxFrame wire bytes.
    pub fn encode_mux(stream_id: u32, payload: &[u8]) -> Result<Vec<u8>> {
        let mut inner = Vec::with_capacity(4 + payload.len());
        inner.extend_from_slice(&stream_id.to_be_bytes());
        inner.extend_from_slice(payload);
        encode_wire(WireType::MuxFrame, &inner)
    }

    /// Number of registered streams (for tests/diagnostics).
    pub async fn stream_count(&self) -> usize {
        self.streams.lock().await.len()
    }

    /// Drop a stream (graceful close). Marks the handle's closed flag so
    /// subsequent sends fail.
    pub async fn close_stream(&self, id: u32) {
        if let Some((_, closed)) = self.streams.lock().await.remove(&id) {
            closed.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        ([127, 0, 0, 1], port).into()
    }

    #[tokio::test]
    async fn tcp_transport_bind_and_report() {
        let t = TcpTransport::listen(addr(0)).await.unwrap();
        let local = t.local_addr().unwrap();
        assert!(matches!(local, TransportAddr::Tcp(_)));
        assert_eq!(t.mtu(), DEFAULT_STREAM_MTU);
        assert_eq!(t.link_mtu(&local), DEFAULT_STREAM_MTU);
    }

    #[tokio::test]
    async fn tcp_frame_roundtrip() {
        let t = TcpTransport::listen(addr(0)).await.unwrap();
        let local = t.local_addr().unwrap();
        let tc = TcpTransport::connector();

        let (server, client) = tokio::join!(t.accept(), tc.connect(&local));
        let mut server = server.unwrap();
        let mut client = client.unwrap();

        client
            .send_frame(WireType::Probe.to_u8(), b"ping-body")
            .await
            .unwrap();
        let (tag, body) = server.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::Probe.to_u8());
        assert_eq!(body, b"ping-body");
    }

    #[tokio::test]
    async fn tcp_frame_channel_passthrough() {
        let t = TcpTransport::listen(addr(0)).await.unwrap();
        let local = t.local_addr().unwrap();
        let tc = TcpTransport::connector();

        let (server, client) = tokio::join!(t.accept(), tc.connect(&local));
        let mut server = server.unwrap();
        let mut client = client.unwrap();

        // Channel DATA frame (0x10) passes through with type intact.
        client.send_frame(0x10, b"ciphertext").await.unwrap();
        let (tag, body) = server.recv_frame().await.unwrap();
        assert_eq!(tag, 0x10);
        assert_eq!(body, b"ciphertext");
    }

    #[tokio::test]
    async fn tcp_multiple_frames_in_order() {
        let t = TcpTransport::listen(addr(0)).await.unwrap();
        let local = t.local_addr().unwrap();
        let tc = TcpTransport::connector();

        let (server, client) = tokio::join!(t.accept(), tc.connect(&local));
        let mut server = server.unwrap();
        let mut client = client.unwrap();

        for i in 0..50u8 {
            client
                .send_frame(WireType::Probe.to_u8(), &[i; 8])
                .await
                .unwrap();
        }
        for i in 0..50u8 {
            let (tag, body) = server.recv_frame().await.unwrap();
            assert_eq!(tag, WireType::Probe.to_u8());
            assert_eq!(body, vec![i; 8]);
        }
    }

    #[tokio::test]
    async fn tcp_connect_wrong_transport_rejected() {
        let tc = TcpTransport::connector();
        let err = tc.connect(&TransportAddr::Memory("x".into())).await;
        match err {
            Err(NetworkError::Transport(_)) => {}
            Err(other) => panic!("expected Transport error, got {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn connector_cannot_accept() {
        let tc = TcpTransport::connector();
        assert!(tc.accept().await.is_err());
        assert!(tc.local_addr().is_none());
    }

    #[tokio::test]
    async fn conn_close_then_recv_errors() {
        let t = TcpTransport::listen(addr(0)).await.unwrap();
        let local = t.local_addr().unwrap();
        let tc = TcpTransport::connector();

        let (server, client) = tokio::join!(t.accept(), tc.connect(&local));
        let mut server = server.unwrap();
        let mut client = client.unwrap();

        client.close().await.unwrap();
        assert!(server.recv_frame().await.is_err());
    }

    #[tokio::test]
    async fn demux_odd_even_ids() {
        let (initiator, _rx) = Demux::new(true);
        let (responder, _rx2) = Demux::new(false);

        let s1 = initiator.open_stream().await;
        let s2 = initiator.open_stream().await;
        assert_eq!(s1.id % 2, 1);
        assert_eq!(s2.id, s1.id + 2);

        let r1 = responder.open_stream().await;
        assert_eq!(r1.id % 2, 0);
        assert_eq!(initiator.stream_count().await, 2);
    }

    #[tokio::test]
    async fn demux_routes_mux_frames() {
        let (demux, mut outbound) = Demux::new(true);
        let handle = demux.open_stream().await;
        let id = handle.id;

        // Inbound: mux frame for our stream arrives at the handle.
        let mut payload = id.to_be_bytes().to_vec();
        payload.extend_from_slice(b"stream-data");
        let routed = demux
            .route_inbound(WireType::MuxFrame.to_u8(), payload)
            .await;
        assert!(routed.is_none()); // consumed by demux
        let got = handle.recv().await.unwrap();
        assert_eq!(got, b"stream-data");

        // Outbound: handle.send produces (stream_id, payload) on outbound.
        handle.send(b"out").unwrap();
        let (sid, enc) = outbound.recv().await.unwrap();
        assert_eq!(sid, id);
        assert_eq!(enc, b"out");
    }

    #[tokio::test]
    async fn demux_unknown_stream_surfaces_to_control() {
        let (demux, _rx) = Demux::new(true);
        let mut payload = 99u32.to_be_bytes().to_vec();
        payload.extend_from_slice(b"orphan");
        let out = demux
            .route_inbound(WireType::MuxFrame.to_u8(), payload.clone())
            .await;
        assert_eq!(out, Some((WireType::MuxFrame.to_u8(), payload)));
    }

    #[tokio::test]
    async fn demux_malformed_mux_surfaces() {
        let (demux, _rx) = Demux::new(true);
        let out = demux
            .route_inbound(WireType::MuxFrame.to_u8(), vec![1, 2])
            .await;
        // Malformed MuxFrame surfaces as a control ERROR (not the raw mux tag).
        assert_eq!(
            out,
            Some((
                WireType::Error.to_u8(),
                b"malformed MuxFrame: 2 bytes < 4".to_vec()
            ))
        );
    }

    #[tokio::test]
    async fn demux_non_mux_frames_go_to_control() {
        let (demux, _rx) = Demux::new(true);
        let out = demux
            .route_inbound(WireType::Probe.to_u8(), b"x".to_vec())
            .await;
        assert_eq!(out, Some((WireType::Probe.to_u8(), b"x".to_vec())));
    }

    #[tokio::test]
    async fn demux_encode_mux_layout() {
        let frame = Demux::encode_mux(7, b"abc").unwrap();
        let (tag, body, _) = decode_wire(&frame).unwrap().unwrap();
        assert_eq!(tag, WireType::MuxFrame.to_u8());
        assert_eq!(&body[..4], &7u32.to_be_bytes());
        assert_eq!(&body[4..], b"abc");
    }

    #[tokio::test]
    async fn demux_close_stream() {
        let (demux, _rx) = Demux::new(true);
        let h = demux.open_stream().await;
        assert_eq!(demux.stream_count().await, 1);
        demux.close_stream(h.id).await;
        assert_eq!(demux.stream_count().await, 0);
        assert!(h.send(b"after-close").is_err());
    }

    #[tokio::test]
    async fn stream_handle_recv_after_close_errors() {
        let (demux, _rx) = Demux::new(true);
        let h = demux.open_stream().await;
        demux.close_stream(h.id).await;
        assert!(h.recv().await.is_err());
    }

    #[test]
    fn transport_addr_display() {
        let a = TransportAddr::Tcp(([127, 0, 0, 1], 443).into());
        assert_eq!(a.to_string(), "tcp://127.0.0.1:443");
        let m = TransportAddr::Memory("tgui".into());
        assert_eq!(m.to_string(), "mem://tgui");
    }
}
