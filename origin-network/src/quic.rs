// SPDX-License-Identifier: Apache-2.0

//! QUIC transport (spec REV 3 §7, phase 2) — behind the `quic` feature.
//!
//! ## Position in the trust model
//!
//! QUIC requires TLS 1.3, but TLS here is NOT the trust anchor. It
//! provides stream multiplexing, 0-RTT-capable migration support, and
//! opportunistic obfuscation. Identity authentication still happens at
//! the Noise IK layer ABOVE this transport — the same AUTH flow the TCP
//! transport uses. Consequences:
//! * The server uses a SELF-SIGNED certificate (generated at startup).
//! * The client does NOT verify the server certificate — verification
//!   is the Noise handshake's job. This is the same posture as raw TCP
//!   (which has no TLS at all): QUIC adds no false sense of identity.
//! * The relay's fingerprint binding is unaffected: AUTH claims bind to
//!   the Noise transcript, not the TLS session.
//!
//! ## Framing
//!
//! One bidirectional stream per connection carries length-prefixed
//! frames exactly as the TCP transport does (`origin-channel` codec
//! layout: `[u32 len][type][payload]`). QUIC's native stream
//! multiplexing is reserved for the substrate's stream layer (MuxFrame
//! rides inside the control stream), keeping frame ordering identical
//! to the TCP path.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::error::{NetworkError, Result};
use crate::transport::{FrameConn, Transport, TransportAddr};
use crate::wire::{decode_wire, encode_wire, WireType};

/// Server name for the self-signed cert. The client never verifies it;
/// it exists because TLS 1.3 requires *some* name.
const SERVER_NAME: &str = "origin-relay";

// ── TLS plumbing (obfuscation only — see module docs) ───────────────────

fn server_tls_config() -> Result<quinn::ServerConfig> {
    let ck = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
        .map_err(|e| NetworkError::Transport(format!("rcgen: {e}")))?;
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
    let config = quinn::ServerConfig::with_single_cert(vec![cert], key.into())
        .map_err(|e| NetworkError::Transport(format!("quic server config: {e}")))?;
    Ok(config)
}

/// Client TLS config that skips certificate verification BY DESIGN:
/// identity is authenticated by the Noise IK handshake above QUIC.
fn client_tls_config() -> Result<quinn::ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| NetworkError::Transport(format!("tls versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let quic_cfg: quinn::crypto::rustls::QuicClientConfig = tls
        .try_into()
        .map_err(|e| NetworkError::Transport(format!("quic client config: {e}")))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_cfg)))
}

/// Certificate verifier that accepts anything (Noise above authenticates).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── Transport ───────────────────────────────────────────────────────────

/// QUIC transport: listener or connector over `quinn::Endpoint`.
pub struct QuicTransport {
    endpoint: quinn::Endpoint,
    listener: bool,
    local: SocketAddr,
}

impl QuicTransport {
    /// Bind a QUIC listener with a fresh self-signed certificate.
    pub async fn listen(addr: SocketAddr) -> Result<Self> {
        let config = server_tls_config()?;
        let endpoint = quinn::Endpoint::server(config, addr)
            .map_err(|e| NetworkError::Transport(format!("quic bind: {e}")))?;
        let local = endpoint
            .local_addr()
            .map_err(|e| NetworkError::Transport(format!("quic local_addr: {e}")))?;
        Ok(Self {
            endpoint,
            listener: true,
            local,
        })
    }

    /// Build a QUIC connector (client endpoint bound to any port).
    pub fn connector() -> Result<Self> {
        let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut endpoint = quinn::Endpoint::client(bind)
            .map_err(|e| NetworkError::Transport(format!("quic client bind: {e}")))?;
        endpoint.set_default_client_config(client_tls_config()?);
        let local = endpoint
            .local_addr()
            .map_err(|e| NetworkError::Transport(format!("quic local_addr: {e}")))?;
        Ok(Self {
            endpoint,
            listener: false,
            local,
        })
    }
}

#[async_trait::async_trait]
impl Transport for QuicTransport {
    async fn connect(&self, addr: &TransportAddr) -> Result<Box<dyn FrameConn>> {
        let TransportAddr::Quic(sa) = addr else {
            return Err(NetworkError::Transport(format!(
                "quic transport cannot dial {addr}"
            )));
        };
        let conn = self
            .endpoint
            .connect(*sa, SERVER_NAME)
            .map_err(|e| NetworkError::Transport(format!("quic connect: {e}")))?
            .await
            .map_err(|e| NetworkError::Transport(format!("quic handshake: {e}")))?;
        QuicFrameConn::initiator(conn)
            .await
            .map(|c| Box::new(c) as Box<dyn FrameConn>)
    }

    async fn accept(&self) -> Result<Box<dyn FrameConn>> {
        if !self.listener {
            return Err(NetworkError::Transport(
                "cannot accept on a quic connector".into(),
            ));
        }
        let conn = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| NetworkError::Transport("quic listener closed".into()))?
            .await
            .map_err(|e| NetworkError::Transport(format!("quic accept: {e}")))?;
        Ok(Box::new(QuicFrameConn::responder(conn)) as Box<dyn FrameConn>)
    }

    /// QUIC's effective per-stream limit; we cap frames below it so a
    /// single frame never fragments across flow-control boundaries.
    fn mtu(&self) -> u16 {
        crate::udp::MAX_DATAGRAM_FRAME.min(u16::MAX as usize) as u16
    }

    fn local_addr(&self) -> Option<TransportAddr> {
        Some(TransportAddr::Quic(self.local))
    }
}

// ── FrameConn over one QUIC stream ──────────────────────────────────────

/// `FrameConn` over a single bidirectional QUIC stream.
///
/// The responder's stream is established LAZILY on first frame I/O:
/// quinn makes an opened stream visible to `accept_bi` only once the
/// initiator writes on it, so blocking in `accept_bi` at accept time
/// would deadlock (client hasn't sent msg1 yet). This matches TCP
/// semantics — `accept()` returns after the handshake, reads wait.
pub struct QuicFrameConn {
    /// Held by the responder until the first frame operation.
    conn: Option<quinn::Connection>,
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
    peer: SocketAddr,
    buf: Vec<u8>,
}

impl QuicFrameConn {
    /// Initiator side: open the control stream now.
    async fn initiator(conn: quinn::Connection) -> Result<Self> {
        let peer = conn.remote_address();
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| NetworkError::Transport(format!("quic open_bi: {e}")))?;
        Ok(Self {
            conn: None,
            send: Some(send),
            recv: Some(recv),
            peer,
            buf: Vec::with_capacity(64 * 1024),
        })
    }

    /// Responder side: defer the stream until data arrives.
    fn responder(conn: quinn::Connection) -> Self {
        let peer = conn.remote_address();
        Self {
            conn: Some(conn),
            send: None,
            recv: None,
            peer,
            buf: Vec::with_capacity(64 * 1024),
        }
    }

    /// Establish the stream on first use (responder path).
    async fn ensure_stream(&mut self) -> Result<()> {
        if self.recv.is_none() {
            let conn = self.conn.take().ok_or_else(|| {
                NetworkError::Transport("quic stream lost before establishment".into())
            })?;
            let (send, recv) = conn
                .accept_bi()
                .await
                .map_err(|e| NetworkError::Transport(format!("quic accept_bi: {e}")))?;
            self.send = Some(send);
            self.recv = Some(recv);
        }
        Ok(())
    }

    async fn read_more(&mut self) -> Result<()> {
        self.ensure_stream().await?;
        let recv = self
            .recv
            .as_mut()
            .ok_or_else(|| NetworkError::Transport("quic stream gone".into()))?;
        let chunk = recv
            .read_chunk(64 * 1024, false)
            .await
            .map_err(|e| NetworkError::Transport(format!("quic read: {e}")))?
            .ok_or_else(|| NetworkError::Transport("quic stream finished".into()))?;
        self.buf.extend_from_slice(&chunk.bytes);
        Ok(())
    }
}

#[async_trait::async_trait]
impl FrameConn for QuicFrameConn {
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
        self.ensure_stream().await?;
        let send = self
            .send
            .as_mut()
            .ok_or_else(|| NetworkError::Transport("quic stream gone".into()))?;
        send.write_all(&frame)
            .await
            .map_err(|e| NetworkError::Transport(format!("quic write: {e}")))?;
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
        TransportAddr::Quic(self.peer)
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(send) = self.send.as_mut() {
            let _ = send.finish();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn quic_pair() -> (Box<dyn FrameConn>, Box<dyn FrameConn>) {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = QuicTransport::listen(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await });
        let connector = QuicTransport::connector().unwrap();
        let client = connector.connect(&addr).await.unwrap();
        let server = accept.await.unwrap().unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn quic_frame_roundtrip_network_owned() {
        let (mut client, mut server) = quic_pair().await;
        client
            .send_frame(WireType::Probe.to_u8(), b"{\"target_fp\":[]}")
            .await
            .unwrap();
        let (tag, payload) = server.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::Probe.to_u8());
        assert_eq!(payload, b"{\"target_fp\":[]}");
    }

    #[tokio::test]
    async fn quic_frame_roundtrip_passthrough() {
        let (mut client, mut server) = quic_pair().await;
        client.send_frame(0x10, b"ciphertext").await.unwrap();
        let (tag, payload) = server.recv_frame().await.unwrap();
        assert_eq!(tag, 0x10);
        assert_eq!(payload, b"ciphertext");
    }

    #[tokio::test]
    async fn quic_multiple_frames_in_order() {
        let (mut client, mut server) = quic_pair().await;
        for i in 0u8..8 {
            client
                .send_frame(WireType::Probe.to_u8(), &[i; 16])
                .await
                .unwrap();
        }
        for i in 0u8..8 {
            let (_tag, payload) = server.recv_frame().await.unwrap();
            assert_eq!(payload, vec![i; 16]);
        }
    }

    #[tokio::test]
    async fn quic_both_directions() {
        let (mut client, mut server) = quic_pair().await;
        client
            .send_frame(WireType::Probe.to_u8(), b"ping")
            .await
            .unwrap();
        let (_t, p) = server.recv_frame().await.unwrap();
        assert_eq!(p, b"ping");
        server
            .send_frame(WireType::Probe.to_u8(), b"pong")
            .await
            .unwrap();
        let (_t, p) = client.recv_frame().await.unwrap();
        assert_eq!(p, b"pong");
    }

    #[tokio::test]
    async fn quic_transport_addr_variant() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = QuicTransport::listen(bind).await.unwrap();
        match listener.local_addr().unwrap() {
            TransportAddr::Quic(sa) => assert_eq!(sa.ip().to_string(), "127.0.0.1"),
            other => panic!("expected Quic addr, got {other}"),
        }
    }

    #[tokio::test]
    async fn quic_connector_cannot_accept() {
        let connector = QuicTransport::connector().unwrap();
        assert!(connector.accept().await.is_err());
    }

    #[tokio::test]
    async fn quic_connect_wrong_addr_variant_rejected() {
        let connector = QuicTransport::connector().unwrap();
        let tcp_addr = TransportAddr::Tcp("127.0.0.1:1".parse().unwrap());
        assert!(connector.connect(&tcp_addr).await.is_err());
    }

    #[tokio::test]
    async fn quic_mtu_is_bounded() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = QuicTransport::listen(bind).await.unwrap();
        assert!(listener.mtu() > 0);
        assert!(listener.mtu() <= crate::udp::MAX_DATAGRAM_FRAME as u16);
    }
}
