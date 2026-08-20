// SPDX-License-Identifier: Apache-2.0

//! Endpoint + Noise IK wiring + SecurePipe — the origin-channel seam.
//!
//! Spec REV 3 §6.2/§6.4:
//! * `Endpoint` = identity + transport + listener/dialer.
//! * Dial drives channel's Noise IK handshake over the transport:
//!   msg1 (carries initiator static key in payload) → msg2 (carries
//!   responder static key) → msg3, then AUTH claim exchange, then
//!   `init_ratchet` → `RatchetedSession`.
//! * `SecurePipe` wraps the session: plaintext in → ratchet encrypt →
//!   channel frame → transport, and the reverse.
//! * Sessions bind to identity, not path — the pipe survives any
//!   transport change beneath it.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

use origin_channel::handshake::Handshake;
use origin_channel::message::HandshakeMessage;
use origin_channel::ratchet::init_ratchet;
use origin_channel::session::RatchetedSession;

use crate::address::Fingerprint;
use crate::error::{NetworkError, Result};
use crate::identity::{
    derive_transport_secret, sign_auth_claim, transport_public_key, verify_auth_claim, PeerKeys,
};
use crate::replay::HandshakeReplayTracker;
use crate::transport::{FrameConn, Transport, TransportAddr};
use crate::wire::{decode_payload, encode_payload, AuthClaim, AuthOk, AuthReject, WireType};

/// Resolve a fingerprint to known peer keys (allowlist / TOFU directory).
/// Returns `None` for unknown peers → dial/accept is refused.
pub trait PeerResolver: Send + Sync {
    fn resolve(&self, fp: &Fingerprint) -> Option<PeerKeys>;
}

/// In-memory resolver for tests and small allowlists.
#[derive(Default, Clone)]
pub struct StaticResolver {
    peers: std::collections::HashMap<[u8; 32], PeerKeys>,
}

impl StaticResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, keys: PeerKeys) {
        self.peers.insert(keys.fingerprint, keys);
    }
}

impl PeerResolver for StaticResolver {
    fn resolve(&self, fp: &Fingerprint) -> Option<PeerKeys> {
        self.peers.get(&fp.0).cloned()
    }
}

/// Extract the initiator's static transport key from a msg1 payload
/// (network-layer convention: first 32 bytes of the payload).
fn initiator_static_from_msg1(msg: &HandshakeMessage) -> Result<[u8; 32]> {
    if msg.payload.len() < 32 {
        return Err(NetworkError::Handshake(
            "msg1 payload missing initiator static key".into(),
        ));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&msg.payload[..32]);
    Ok(pk)
}

/// Network transcript: SHA3-256 over the three handshake wire messages.
/// Both sides compute it from the bytes actually exchanged, so the AUTH
/// claim signature binds to the exact handshake that ran.
fn handshake_transcript(msg1: &[u8], msg2: &[u8], msg3: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(msg1.len() + msg2.len() + msg3.len() + 24);
    buf.extend_from_slice(b"origin-network:transcript:v1");
    buf.extend_from_slice(msg1);
    buf.extend_from_slice(msg2);
    buf.extend_from_slice(msg3);
    origin_crypto_sdk::sha3_256(&buf).to_vec()
}

/// The authenticated, ratcheted pipe between two identities.
pub struct SecurePipe {
    session: RatchetedSession,
    conn: Box<dyn FrameConn>,
    peer: Fingerprint,
    is_initiator: bool,
}

impl SecurePipe {
    /// Encrypt + frame + send one plaintext message.
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let msg = self
            .session
            .encrypt(plaintext)
            .map_err(|e| NetworkError::Channel(e.to_string()))?;
        self.conn
            .send_frame(msg.msg_type, &msg.to_bytes()[1..])
            .await
    }

    /// Receive + parse + decrypt one message.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let (tag, body) = self.conn.recv_frame().await?;
        let mut wire = Vec::with_capacity(1 + body.len());
        wire.push(tag);
        wire.extend_from_slice(&body);
        let msg = origin_channel::message::ChannelMessage::from_bytes(&wire)
            .map_err(|e| NetworkError::Channel(e.to_string()))?;
        self.session
            .decrypt(&msg)
            .map_err(|e| NetworkError::Channel(e.to_string()))
    }

    /// Peer identity fingerprint.
    pub fn peer(&self) -> Fingerprint {
        self.peer
    }

    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Whether the session needs a rotation (usage limits reached).
    pub fn needs_rotation(&self) -> bool {
        self.session.needs_rotation()
    }

    /// Direct access to the channel session (rotation, counters).
    pub fn session_mut(&mut self) -> &mut RatchetedSession {
        &mut self.session
    }
}

/// Endpoint = identity + transport + dial/accept.
pub struct Endpoint {
    seed: [u8; 32],
    device_index: u32,
    fingerprint: Fingerprint,
    static_secret: StaticSecret,
    transport: Arc<dyn Transport>,
    resolver: Arc<dyn PeerResolver>,
    replay: Arc<Mutex<HandshakeReplayTracker>>,
}

impl Endpoint {
    /// Build an endpoint from an identity seed.
    pub fn new(
        seed: [u8; 32],
        device_index: u32,
        transport: Arc<dyn Transport>,
        resolver: Arc<dyn PeerResolver>,
    ) -> Result<Self> {
        let static_secret = derive_transport_secret(&seed, device_index)?;
        Ok(Self {
            fingerprint: Fingerprint::from_seed_bytes(&seed),
            seed,
            device_index,
            static_secret,
            transport,
            resolver,
            replay: Arc::new(Mutex::new(HandshakeReplayTracker::new())),
        })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Dial a known peer at an explicit transport address.
    ///
    /// Uses bounded retry with exponential backoff + full jitter so a
    /// transiently-unreachable or flaky peer doesn't fail the call
    /// outright, and — critically — doesn't hammer a saturated dependency
    /// (retry storm). The connection attempt itself is also deadline-
    /// bounded.
    pub async fn connect_at(&self, peer: &PeerKeys, addr: &TransportAddr) -> Result<SecurePipe> {
        // Validate the record's transport key before dialing.
        let _peer_static_pk = peer.transport_pk_bytes()?;
        const MAX_ATTEMPTS: u32 = 5;
        const BASE_DELAY_MS: u64 = 100;
        const MAX_DELAY_MS: u64 = 5_000;
        const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
        // Cheap, dependency-free jitter seed so concurrent dialers don't
        // synchronize their backoffs (retry-storm avoidance). Not crypto.
        let seed = jitter_seed(addr, peer.fingerprint());
        let mut attempt: u32 = 0;
        loop {
            match tokio::time::timeout(CONNECT_TIMEOUT, self.transport.connect(addr)).await {
                Ok(Ok(conn)) => return self.drive(conn, peer, true).await,
                Ok(Err(e)) => {
                    // Retry only transient transport/timeout errors, not
                    // permanent ones (e.g. wrong transport type).
                    if !matches!(e, NetworkError::Transport(_) | NetworkError::Timeout(_)) {
                        return Err(e);
                    }
                    attempt += 1;
                    if attempt >= MAX_ATTEMPTS {
                        return Err(NetworkError::Transport(format!(
                            "dial {addr} failed after {MAX_ATTEMPTS} attempts: {e}"
                        )));
                    }
                    tokio::time::sleep(backoff(attempt, BASE_DELAY_MS, MAX_DELAY_MS, seed)).await;
                }
                Err(_) => {
                    attempt += 1;
                    if attempt >= MAX_ATTEMPTS {
                        return Err(NetworkError::Timeout(format!(
                            "dial {addr} timed out after {MAX_ATTEMPTS} attempts"
                        )));
                    }
                    tokio::time::sleep(backoff(attempt, BASE_DELAY_MS, MAX_DELAY_MS, seed)).await;
                }
            }
        }
    }

    /// Accept one inbound connection and establish an authenticated pipe.
    pub async fn accept_one(&self) -> Result<SecurePipe> {
        let conn = self.transport.accept().await?;
        // Responder learns the initiator from msg1's static key + AUTH claim.
        self.drive(conn, &PeerKeys::default_unknown(), false).await
    }

    /// Drive the full handshake + AUTH exchange over one connection.
    /// For responders, `peer_hint` is replaced by the looked-up record
    /// once the initiator's identity is known.
    async fn drive(
        &self,
        mut conn: Box<dyn FrameConn>,
        peer_hint: &PeerKeys,
        is_initiator: bool,
    ) -> Result<SecurePipe> {
        let (hs, msg1_bytes, msg2_bytes, msg3_bytes) = if is_initiator {
            let peer_pk = PublicKey::from(peer_hint.transport_pk_bytes()?);
            let mut hs = Handshake::new(self.static_secret.clone(), peer_pk, true);

            // msg1: start, then embed our static key for the responder.
            let mut msg1 = hs
                .start()
                .map_err(|e| NetworkError::Handshake(e.to_string()))?;
            msg1.payload
                .extend_from_slice(transport_public_key(&self.static_secret).as_slice());
            let m1 = msg1.to_bytes();
            conn.send_frame(msg1.msg_type, &m1[1..]).await?;

            // msg2
            let (_, body2) = conn.recv_frame().await?;
            let msg2 = HandshakeMessage::from_bytes(&reassemble(body2, 0x02))
                .map_err(|e| NetworkError::Handshake(e.to_string()))?;
            let m2 = msg2.to_bytes();
            let msg3 = hs
                .process_msg2(&msg2)
                .map_err(|e| NetworkError::Handshake(e.to_string()))?;
            let m3 = msg3.to_bytes();
            conn.send_frame(msg3.msg_type, &m3[1..]).await?;

            hs.process_msg3_dummy()?; // initiator already done at msg3 send
            (hs, m1, m2, m3)
        } else {
            // Responder: receive msg1, learn initiator static key.
            let (_, body1) = conn.recv_frame().await?;
            let msg1 = HandshakeMessage::from_bytes(&reassemble(body1.clone(), 0x01))
                .map_err(|e| NetworkError::Handshake(e.to_string()))?;

            // Replay gate before any ECDH work (signet-daemon pattern).
            {
                let mut tracker = self.replay.lock().await;
                if !tracker.check_and_track(&body1) {
                    return Err(NetworkError::Handshake("handshake replay detected".into()));
                }
            }

            let initiator_static = initiator_static_from_msg1(&msg1)?;
            let mut hs = Handshake::new(
                self.static_secret.clone(),
                PublicKey::from(initiator_static),
                false,
            );
            let msg2 = hs
                .process_msg1(&msg1)
                .map_err(|e| NetworkError::Handshake(e.to_string()))?;
            let mut msg2 = msg2;
            msg2.payload
                .extend_from_slice(transport_public_key(&self.static_secret).as_slice());
            let m1 = msg1.to_bytes();
            let m2 = msg2.to_bytes();
            conn.send_frame(msg2.msg_type, &m2[1..]).await?;

            // msg3
            let (_, body3) = conn.recv_frame().await?;
            let msg3 = HandshakeMessage::from_bytes(&reassemble(body3, 0x03))
                .map_err(|e| NetworkError::Handshake(e.to_string()))?;
            hs.process_msg3(&msg3)
                .map_err(|e| NetworkError::Handshake(e.to_string()))?;
            let m3 = msg3.to_bytes();
            (hs, m1, m2, m3)
        };

        hs.finalize_check()?;
        let (shared_secret, _session_id) = hs
            .finalize()
            .map_err(|e| NetworkError::Handshake(e.to_string()))?;

        // AUTH claim exchange (initiator first).
        let transcript = handshake_transcript(&msg1_bytes, &msg2_bytes, &msg3_bytes);
        let (peer_fp, _peer_keys_verified) = if is_initiator {
            let claim = sign_auth_claim(
                &self.seed,
                self.device_index,
                &peer_hint.fingerprint(),
                &transcript,
            )?;
            conn.send_frame(WireType::AuthClaim.to_u8(), &encode_payload(&claim)?)
                .await?;
            let ok: AuthOk = expect_auth_ok(&mut *conn).await?;
            let _ = ok; // session_token used by relay path (P6+)
            (peer_hint.fingerprint(), peer_hint.clone())
        } else {
            let (tag, body) = conn.recv_frame().await?;
            if tag != WireType::AuthClaim.to_u8() {
                let _ = conn
                    .send_frame(
                        WireType::AuthReject.to_u8(),
                        &encode_payload(&AuthReject {
                            reason: "expected AUTH claim".into(),
                        })?,
                    )
                    .await;
                return Err(NetworkError::Auth("expected AUTH claim".into()));
            }
            let claim: AuthClaim = decode_payload(&body)?;
            let claimed_fp = Fingerprint(claim.fingerprint);
            let keys = match self.resolver.resolve(&claimed_fp) {
                Some(k) => k,
                None => {
                    let _ = conn
                        .send_frame(
                            WireType::AuthReject.to_u8(),
                            &encode_payload(&AuthReject {
                                reason: "unknown peer".into(),
                            })?,
                        )
                        .await;
                    return Err(NetworkError::Auth("unknown peer".into()));
                }
            };
            // Claimed transport key must equal the handshake static key.
            if claim.x25519_pk != keys.transport_pk_bytes()? {
                let _ = conn
                    .send_frame(
                        WireType::AuthReject.to_u8(),
                        &encode_payload(&AuthReject {
                            reason: "claimed key does not match handshake key".into(),
                        })?,
                    )
                    .await;
                return Err(NetworkError::Auth(
                    "claimed key does not match handshake key".into(),
                ));
            }
            if let Err(e) = verify_auth_claim(&keys, &claim, &self.fingerprint, &transcript) {
                let _ = conn
                    .send_frame(
                        WireType::AuthReject.to_u8(),
                        &encode_payload(&AuthReject {
                            reason: "signature verification failed".into(),
                        })?,
                    )
                    .await;
                return Err(e);
            }
            conn.send_frame(
                WireType::AuthOk.to_u8(),
                &encode_payload(&AuthOk {
                    session_token: String::new(),
                })?,
            )
            .await?;
            (claimed_fp, keys)
        };

        // Ratchet + pipe.
        let keys = init_ratchet(&shared_secret, is_initiator)
            .map_err(|e| NetworkError::Channel(e.to_string()))?;
        let session = RatchetedSession::with_defaults(keys);
        Ok(SecurePipe {
            session,
            conn,
            peer: peer_fp,
            is_initiator,
        })
    }
}

/// Re-prepend the type byte stripped by the transport framing.
fn reassemble(body: Vec<u8>, tag: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(tag);
    v.extend_from_slice(&body);
    v
}

/// Public reassembly helper (relay server drives the same handshake).
pub fn reassemble_pub(body: Vec<u8>, tag: u8) -> Vec<u8> {
    reassemble(body, tag)
}

/// Public handshake transcript (relay server binds AUTH claims the same way).
pub fn transcript_pub(msg1: &[u8], msg2: &[u8], msg3: &[u8]) -> Vec<u8> {
    handshake_transcript(msg1, msg2, msg3)
}

/// Read the peer's AUTH response; convert REJECT into an error.
async fn expect_auth_ok(conn: &mut dyn FrameConn) -> Result<AuthOk> {
    let (tag, body) = conn.recv_frame().await?;
    match tag {
        t if t == WireType::AuthOk.to_u8() => decode_payload(&body),
        t if t == WireType::AuthReject.to_u8() => {
            let rej: AuthReject = decode_payload(&body)?;
            Err(NetworkError::Auth(rej.reason))
        }
        other => Err(NetworkError::Auth(format!(
            "unexpected auth response frame {other:#04x}"
        ))),
    }
}

// ── Small extension shims so the drive() flow reads linearly ────────────

trait HandshakeExt {
    /// Initiator completes at msg3 send; this is a no-op state check.
    fn process_msg3_dummy(&mut self) -> Result<()>;
    /// Guard: finalize requires step 3.
    fn finalize_check(&self) -> Result<()>;
}

impl HandshakeExt for Handshake {
    fn process_msg3_dummy(&mut self) -> Result<()> {
        if self.step() < 3 {
            return Err(NetworkError::Handshake("handshake incomplete".into()));
        }
        Ok(())
    }
    fn finalize_check(&self) -> Result<()> {
        if self.step() < 3 {
            return Err(NetworkError::Handshake("handshake incomplete".into()));
        }
        Ok(())
    }
}

// PeerKeys needs a neutral "unknown" value for the responder path where
// the identity is learned from the wire. Keep it private to this module.
impl PeerKeys {
    fn default_unknown() -> Self {
        Self {
            fingerprint: [0; 32],
            device_index: 0,
            ed25519_pk: Vec::new(),
            falcon_pk: Vec::new(),
            transport_pk: Vec::new(),
        }
    }
}

/// Exponential backoff with full jitter, capped at `max_ms`.
///
/// delay = min(max_ms, base_ms * 2^(attempt-1)) + uniform(0, that ceiling)
/// Full jitter spreads concurrent retries so they don't re-synchronize
/// into a retry storm against a recovering dependency.
fn backoff(attempt: u32, base_ms: u64, max_ms: u64, seed: u64) -> Duration {
    let exp = attempt.saturating_sub(1).min(31); // guard against 2^pow overflow
    let ceil = (base_ms << exp).min(max_ms);
    // Deterministic-in-this-process jitter from seed + attempt; spreads
    // retries without a new RNG dependency. Not cryptographically random.
    let jitter = ((seed ^ (seed >> 17) ^ u64::from(attempt).wrapping_mul(0x9e3779b97f4a7c15))
        % ceil.max(1)) as u64;
    Duration::from_millis(ceil.saturating_add(jitter))
}

/// Stable, non-crypto jitter seed from the dial target so different
/// peers back off on different schedules.
fn jitter_seed(addr: &TransportAddr, fp: Fingerprint) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mut feed = |b: u8| {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    };
    match addr {
        TransportAddr::Tcp(s) | TransportAddr::Udp(s) | TransportAddr::Quic(s) => {
            match s.ip() {
                std::net::IpAddr::V4(v4) => {
                    for b in v4.octets() {
                        feed(b);
                    }
                }
                std::net::IpAddr::V6(v6) => {
                    for b in v6.octets() {
                        feed(b);
                    }
                }
            }
            feed((s.port() & 0xff) as u8);
            feed((s.port() >> 8) as u8);
        }
        TransportAddr::Memory(name) => {
            for b in name.as_bytes() {
                feed(*b);
            }
        }
    }
    for b in fp.0 {
        feed(b);
    }
    h
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    #[test]
    fn backoff_grows_exponentially_and_caps() {
        // base=100ms, max=5000ms. Seed irrelevant for the ceiling math.
        let ceil_1 = backoff(1, 100, 5000, 1);
        let ceil_2 = backoff(2, 100, 5000, 1);
        let ceil_3 = backoff(3, 100, 5000, 1);
        // Exponential growth in the ceiling (100 -> 200 -> 400), plus jitter.
        assert!(ceil_1 >= Duration::from_millis(100));
        assert!(ceil_2 >= Duration::from_millis(200));
        assert!(ceil_3 >= Duration::from_millis(400));
        // Never exceeds max + jitter window (jitter < 5000).
        assert!(ceil_3 < Duration::from_millis(9000));
    }

    #[test]
    fn backoff_respects_max_cap() {
        // Attempt 10 would be 100*2^9 = 51.2s but must cap at 5000ms.
        let d = backoff(10, 100, 5000, 7);
        assert!(d <= Duration::from_millis(5000 + 5000));
        assert!(d >= Duration::from_millis(5000));
    }

    #[test]
    fn backoff_does_not_panic_on_overflow_attempt() {
        // attempt saturating_sub(1).min(31) guards 2^pow overflow.
        let _ = backoff(u32::MAX, 100, 5000, 3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TcpTransport;

    fn seed_a() -> [u8; 32] {
        [0xA1; 32]
    }
    fn seed_b() -> [u8; 32] {
        [0xB2; 32]
    }

    /// Build two endpoints wired to each other over loopback TCP.
    /// Returns (initiator_endpoint, responder_endpoint, dial_addr).
    async fn pair() -> (Endpoint, Endpoint, TransportAddr) {
        let listener = TcpTransport::listen(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let mut res_a = StaticResolver::new();
        res_a.add(PeerKeys::from_seed(&seed_b(), 0).unwrap());
        let mut res_b = StaticResolver::new();
        res_b.add(PeerKeys::from_seed(&seed_a(), 0).unwrap());

        let ep_a = Endpoint::new(
            seed_a(),
            0,
            Arc::new(TcpTransport::connector()),
            Arc::new(res_a),
        )
        .unwrap();
        let ep_b = Endpoint::new(seed_b(), 0, Arc::new(listener), Arc::new(res_b)).unwrap();
        (ep_a, ep_b, listen_addr)
    }

    async fn connected_pair() -> (SecurePipe, SecurePipe) {
        let (ep_a, ep_b, addr) = pair().await;
        let peer_b = PeerKeys::from_seed(&seed_b(), 0).unwrap();
        let (ia, ib) = tokio::join!(ep_a.connect_at(&peer_b, &addr), ep_b.accept_one());
        (ia.unwrap(), ib.unwrap())
    }

    #[tokio::test]
    async fn endpoint_identity_stable() {
        let (ep_a, _ep_b, _addr) = pair().await;
        assert_eq!(ep_a.fingerprint(), Fingerprint::from_seed_bytes(&seed_a()));
    }

    #[tokio::test]
    async fn loopback_handshake_establishes_pipe() {
        let (mut pipe_a, mut pipe_b) = connected_pair().await;
        assert_eq!(pipe_a.peer(), Fingerprint::from_seed_bytes(&seed_b()));
        assert_eq!(pipe_b.peer(), Fingerprint::from_seed_bytes(&seed_a()));
        assert!(pipe_a.is_initiator());
        assert!(!pipe_b.is_initiator());

        pipe_a.send(b"hello from A").await.unwrap();
        assert_eq!(pipe_b.recv().await.unwrap(), b"hello from A");
        pipe_b.send(b"hello from B").await.unwrap();
        assert_eq!(pipe_a.recv().await.unwrap(), b"hello from B");
    }

    #[tokio::test]
    async fn thousand_messages_both_directions() {
        let (mut pipe_a, mut pipe_b) = connected_pair().await;
        for i in 0..1000u32 {
            let payload = i.to_be_bytes();
            pipe_a.send(&payload).await.unwrap();
            assert_eq!(pipe_b.recv().await.unwrap(), payload.to_vec());
        }
        for i in 0..100u32 {
            let payload = i.to_be_bytes();
            pipe_b.send(&payload).await.unwrap();
            assert_eq!(pipe_a.recv().await.unwrap(), payload.to_vec());
        }
    }

    #[tokio::test]
    async fn unknown_peer_rejected() {
        let (ep_a, ep_b, addr) = pair().await;
        // ep_b's resolver only knows seed_a — dialing with a stranger key
        // must fail at AUTH on the responder side.
        let stranger = PeerKeys::from_seed(&[0x99; 32], 0).unwrap();
        let accept = tokio::spawn(async move { ep_b.accept_one().await });
        let dial = ep_a.connect_at(&stranger, &addr).await;
        assert!(dial.is_err()); // AuthReject surfaces as Auth error
        let accepted = accept.await.unwrap();
        assert!(accepted.is_err());
    }

    /// Manually drive the initiator side of the handshake over a raw TCP
    /// connection, capturing the exact msg1 body bytes. Returns the conn
    /// after receiving AuthOk (fully authenticated).
    async fn manual_initiator(
        addr: &crate::transport::TransportAddr,
    ) -> (Box<dyn crate::transport::FrameConn>, Vec<u8>) {
        let tc = TcpTransport::connector();
        let mut conn = tc.connect(addr).await.unwrap();
        let secret = derive_transport_secret(&seed_a(), 0).unwrap();
        let peer_pk = PublicKey::from(
            PeerKeys::from_seed(&seed_b(), 0)
                .unwrap()
                .transport_pk_bytes()
                .unwrap(),
        );
        let mut hs = Handshake::new(secret.clone(), peer_pk, true);
        let mut msg1 = hs.start().unwrap();
        msg1.payload
            .extend_from_slice(transport_public_key(&secret).as_slice());
        let m1 = msg1.to_bytes();
        let captured_msg1_body = m1[1..].to_vec();
        conn.send_frame(msg1.msg_type, &m1[1..]).await.unwrap();

        let (_, body2) = conn.recv_frame().await.unwrap();
        let msg2 = origin_channel::message::HandshakeMessage::from_bytes(
            &crate::session::reassemble_pub(body2, 0x02),
        )
        .unwrap();
        let m2 = msg2.to_bytes();
        let msg3 = hs.process_msg2(&msg2).unwrap();
        let m3 = msg3.to_bytes();
        conn.send_frame(msg3.msg_type, &m3[1..]).await.unwrap();

        let transcript = crate::session::transcript_pub(&m1, &m2, &m3);
        let relay_fp = PeerKeys::from_seed(&seed_b(), 0).unwrap().fingerprint();
        let claim = crate::identity::sign_auth_claim(&seed_a(), 0, &relay_fp, &transcript).unwrap();
        conn.send_frame(
            crate::wire::WireType::AuthClaim.to_u8(),
            &crate::wire::encode_payload(&claim).unwrap(),
        )
        .await
        .unwrap();
        let (tag, _body) = conn.recv_frame().await.unwrap();
        assert_eq!(tag, crate::wire::WireType::AuthOk.to_u8());
        (conn, captured_msg1_body)
    }

    #[tokio::test]
    async fn replayed_handshake_rejected() {
        let (ep_a, ep_b, addr) = pair().await;
        let _ = ep_a;

        // First connection: manual handshake, capture the exact msg1 bytes.
        let (init_res, accept_res) = tokio::join!(manual_initiator(&addr), ep_b.accept_one());
        let (_conn, captured_msg1) = init_res;
        assert!(accept_res.is_ok());

        // Replay: resend the IDENTICAL captured msg1 on a fresh connection.
        // The responder's tracker rejects it before sending msg2 and drops
        // the connection, so the client's recv errors (not hangs).
        let tc = TcpTransport::connector();
        let mut conn = tc.connect(&addr).await.unwrap();
        conn.send_frame(0x01, &captured_msg1).await.unwrap();

        let (recv_res, accept2_res) = tokio::join!(
            tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv_frame()),
            ep_b.accept_one(),
        );
        match recv_res {
            Err(_) => panic!("replayed msg1 was not rejected (timed out waiting)"),
            Ok(Ok(_)) => panic!("replayed msg1 was accepted (got msg2)"),
            Ok(Err(_)) => {} // expected: responder closed the connection
        }
        match accept2_res {
            Err(NetworkError::Handshake(msg)) => {
                assert!(msg.contains("replay"), "got: {msg}");
            }
            Err(other) => panic!("expected replay rejection, got {other:?}"),
            Ok(_) => panic!("expected replay rejection, got Ok"),
        }
    }

    #[tokio::test]
    async fn rotation_seam() {
        let (mut pipe_a, mut pipe_b) = connected_pair().await;
        pipe_a.send(b"pre-rotation").await.unwrap();
        assert_eq!(pipe_b.recv().await.unwrap(), b"pre-rotation");

        // Simulate a DH-ratchet rotation: both sides mix a fresh shared
        // secret into the root key (mirrored send/recv chains).
        let fresh_dh = [0x77u8; 32];
        let keys_a =
            origin_channel::ratchet::dh_ratchet(&pipe_a.session_mut().keys().root, &fresh_dh)
                .unwrap();
        let keys_b =
            origin_channel::ratchet::dh_ratchet(&pipe_b.session_mut().keys().root, &fresh_dh)
                .unwrap();
        // Initiator's send chain must equal responder's recv chain.
        let keys_b = origin_channel::types::RatchetKeys {
            root: keys_b.root,
            send_chain: keys_b.recv_chain,
            recv_chain: keys_b.send_chain,
        };
        pipe_a.session_mut().rotate(keys_a);
        pipe_b.session_mut().rotate(keys_b);

        pipe_a.send(b"post-rotation").await.unwrap();
        assert_eq!(pipe_b.recv().await.unwrap(), b"post-rotation");
    }

    #[tokio::test]
    async fn tampered_auth_claim_rejected() {
        // Verify the claim verifier catches a flipped key bit — the drive
        // path relies on verify_auth_claim for this.
        let peer = PeerKeys::from_seed(&seed_a(), 0).unwrap();
        let relay_fp = Fingerprint::from_seed_bytes(&seed_b());
        let mut claim = crate::identity::sign_auth_claim(&seed_a(), 0, &relay_fp, b"t").unwrap();
        claim.hybrid_signature[10] ^= 0xFF;
        assert!(crate::identity::verify_auth_claim(&peer, &claim, &relay_fp, b"t").is_err());
    }

    #[tokio::test]
    async fn connect_without_listen_addr_errors() {
        // Connector-only endpoint: connect() without explicit addr fails.
        let ep = Endpoint::new(
            seed_a(),
            0,
            Arc::new(TcpTransport::connector()),
            Arc::new(StaticResolver::new()),
        )
        .unwrap();
        let peer_b = PeerKeys::from_seed(&seed_b(), 0).unwrap();
        // connect_at to a non-listening address must fail to dial.
        let bad = TransportAddr::Tcp(([127, 0, 0, 1], 1).into());
        assert!(ep.connect_at(&peer_b, &bad).await.is_err());
    }

    #[test]
    fn handshake_transcript_bound_to_messages() {
        let t1 = handshake_transcript(b"m1", b"m2", b"m3");
        let t2 = handshake_transcript(b"m1", b"m2", b"m3");
        let t3 = handshake_transcript(b"m1", b"m2X", b"m3");
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
        assert_eq!(t1.len(), 32);
    }

    #[test]
    fn reassemble_prepends_tag() {
        assert_eq!(reassemble(vec![1, 2], 0x10), vec![0x10, 1, 2]);
    }

    #[tokio::test]
    async fn needs_rotation_accessor() {
        let (mut pipe_a, _pipe_b) = connected_pair().await;
        assert!(!pipe_a.needs_rotation());
        // Swap in a tiny budget and exhaust it → rotation needed. The
        // accessor delegates to the channel session.
        let tiny = origin_channel::usage_limit::AeadLimits::new(2, 1 << 30);
        let keys = pipe_a.session_mut().keys().clone();
        *pipe_a.session_mut() = origin_channel::session::RatchetedSession::new(keys, tiny);
        pipe_a.send(b"a").await.unwrap();
        pipe_a.send(b"b").await.unwrap();
        assert!(pipe_a.needs_rotation());
    }

    #[tokio::test]
    async fn mismatched_transport_key_rejected() {
        let (_ep_a, ep_b, addr) = pair().await;
        // Drive the misbehaving client concurrently with the accept side.
        let client = async {
            let tc = TcpTransport::connector();
            let mut conn = tc.connect(&addr).await.unwrap();
            let secret = derive_transport_secret(&seed_a(), 0).unwrap();
            let peer_pk = PublicKey::from(
                PeerKeys::from_seed(&seed_b(), 0)
                    .unwrap()
                    .transport_pk_bytes()
                    .unwrap(),
            );
            let mut hs = Handshake::new(secret.clone(), peer_pk, true);
            let mut msg1 = hs.start().unwrap();
            msg1.payload
                .extend_from_slice(transport_public_key(&secret).as_slice());
            let m1 = msg1.to_bytes();
            conn.send_frame(msg1.msg_type, &m1[1..]).await.unwrap();
            let (_, body2) = conn.recv_frame().await.unwrap();
            let msg2 = origin_channel::message::HandshakeMessage::from_bytes(
                &crate::session::reassemble_pub(body2, 0x02),
            )
            .unwrap();
            let m2 = msg2.to_bytes();
            let msg3 = hs.process_msg2(&msg2).unwrap();
            let m3 = msg3.to_bytes();
            conn.send_frame(msg3.msg_type, &m3[1..]).await.unwrap();

            // Claim signed for a DIFFERENT device's key than the handshake
            // used: device 1, but the handshake used device 0. The resolver
            // knows device 0's record → claimed key mismatch → AuthReject.
            let transcript = crate::session::transcript_pub(&m1, &m2, &m3);
            let relay_fp = PeerKeys::from_seed(&seed_b(), 0).unwrap().fingerprint();
            let claim =
                crate::identity::sign_auth_claim(&seed_a(), 1, &relay_fp, &transcript).unwrap();
            conn.send_frame(
                crate::wire::WireType::AuthClaim.to_u8(),
                &crate::wire::encode_payload(&claim).unwrap(),
            )
            .await
            .unwrap();
            let (tag, _body) = conn.recv_frame().await.unwrap();
            assert_eq!(tag, crate::wire::WireType::AuthReject.to_u8());
        };
        // client asserts AuthReject tag internally and returns ().
        let (_, accept_res) = tokio::join!(client, ep_b.accept_one());
        match accept_res {
            Err(NetworkError::Auth(msg)) => {
                assert!(msg.contains("does not match"), "got: {msg}");
            }
            Err(other) => panic!("expected Auth mismatch, got {other:?}"),
            Ok(_) => panic!("expected rejection, got Ok"),
        }
    }

    #[tokio::test]
    async fn unknown_initiator_rejected_with_auth_reject() {
        // Endpoint whose fingerprint the responder doesn't know: the
        // claim fails resolution → AuthReject → client sees Auth error.
        let stranger_seed = [0x55u8; 32];
        let mut resolver = StaticResolver::new();
        resolver.add(PeerKeys::from_seed(&stranger_seed, 0).unwrap());
        let ep_a = Endpoint::new(
            stranger_seed,
            0,
            Arc::new(TcpTransport::connector()),
            Arc::new(resolver),
        )
        .unwrap();

        let (_ep_a2, ep_b, addr) = pair().await;
        let stranger = PeerKeys::from_seed(&stranger_seed, 0).unwrap();
        let (dial_res, accept_res) =
            tokio::join!(ep_a.connect_at(&stranger, &addr), ep_b.accept_one());
        // The rejection can surface as the relay's AuthReject reason OR as
        // a connection-close Transport error (responder closes right after
        // rejecting — both outcomes mean the unknown initiator was denied).
        match dial_res {
            Err(NetworkError::Auth(reason)) => {
                assert!(reason.contains("unknown"), "got: {reason}");
            }
            Err(NetworkError::Transport(reason)) => {
                assert!(reason.contains("closed"), "got: {reason}");
            }
            Err(other) => panic!("expected rejection, got {other:?}"),
            Ok(_) => panic!("expected rejection, got Ok"),
        }
        assert!(accept_res.is_err());
    }
}
