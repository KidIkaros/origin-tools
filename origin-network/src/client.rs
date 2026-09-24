// SPDX-License-Identifier: Apache-2.0

//! RelayClient — the authenticated client-side surface for origin-relay
//! (spec REV 3 §5.2, §8.1, §8.2).
//!
//! One `RelayClient` owns one authenticated connection. Operations are
//! typed wrappers over the control frames the relay server speaks:
//! probe, inbox push/pull, advert publish/fetch, presence subscribe.
//!
//! ## Interleaving model (one connection, one ordering)
//!
//! The relay pushes `PresenceEvent` frames on the same connection that
//! carries request/response traffic. Every reader (request/response and
//! presence stream) locks the same connection state, and frames that
//! arrive for the "other side" are buffered:
//! * request/response readers stash presence events for the stream;
//! * the presence stream stashes response frames for the reader.
//!
//! No second control channel — the substrate contract keeps one closed
//! loop per relay connection.
//!
//! Handshake shape: identical to `RelayServer`'s expected flow —
//! Noise IK initiator + AUTH claim bound to the handshake transcript.

use std::collections::VecDeque;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::address::Fingerprint;
use crate::error::{NetworkError, Result};
use crate::identity::PeerKeys;
use crate::relay_server::{AdvertFetchResponse, InboxPullResponse, ProbeResponse};
use crate::transport::{FrameConn, Transport, TransportAddr};
use crate::wire::{
    decode_payload, encode_payload, Advert, AdvertFetch, AdvertPublish, AuthOk, AuthReject,
    InboxPull, InboxPush, PresenceEvent, PresenceSubscribe, Probe, RelayData, SessionClose,
    SessionOpen, SessionOpenAck, WireError, WireType,
};

/// Shared connection state behind the client's mutex.
struct ConnState {
    conn: Box<dyn FrameConn>,
    /// Presence events read by a request/response call, waiting for a
    /// `PresenceStream` to consume them.
    buffered_events: VecDeque<PresenceEvent>,
    /// Non-presence frames read by a `PresenceStream`, waiting for a
    /// request/response call to match them.
    pending_frames: VecDeque<(u8, Vec<u8>)>,
}

impl ConnState {
    /// Read one frame, routing it to the right side. Returns
    /// `Ok(Some(event))` for presence events, `Ok(Some_other)` never —
    /// non-presence frames land in `pending_frames` and the loop reads
    /// again. Callers wanting a response use `read_response`.
    async fn read_event(&mut self) -> Result<PresenceEvent> {
        loop {
            let (tag, body) = self.conn.recv_frame().await?;
            match WireType::from_u8(tag) {
                Some(WireType::PresenceEvent) => {
                    return decode_payload(&body);
                }
                other => {
                    // Not ours (presence): stash for request/response.
                    self.pending_frames
                        .push_back((other.map(|w| w.to_u8()).unwrap_or(tag), body));
                }
            }
        }
    }

    /// Read until the response frame for `tag` arrives, buffering any
    /// presence events that interleave.
    async fn read_response<T: serde::de::DeserializeOwned>(&mut self, tag: WireType) -> Result<T> {
        // Check frames the presence stream already stashed.
        if let Some(pos) = self
            .pending_frames
            .iter()
            .position(|(t, _)| *t == tag.to_u8())
        {
            let (_, body) = self.pending_frames.remove(pos).unwrap();
            return decode_payload(&body);
        }
        loop {
            let (rtag, body) = self.conn.recv_frame().await?;
            match WireType::from_u8(rtag) {
                Some(WireType::PresenceEvent) => {
                    let evt: PresenceEvent = decode_payload(&body)?;
                    self.buffered_events.push_back(evt);
                }
                Some(WireType::Error) => {
                    let err: WireError = decode_payload(&body)?;
                    return Err(NetworkError::RelayFull(format!(
                        "{}: {}",
                        err.code, err.detail
                    )));
                }
                Some(w) if w == tag => return decode_payload(&body),
                other => {
                    return Err(NetworkError::Handshake(format!(
                        "unexpected frame {other:?} answering {tag:?}"
                    )))
                }
            }
        }
    }
}

/// A presence event stream over one relay connection (spec §8.2).
///
/// Events are pushed by the relay; `recv` reads them off the shared
/// connection (buffering any interleaved response frames for their
/// callers). The first event after subscribe is the target's current
/// state.
pub struct PresenceStream {
    state: Arc<Mutex<ConnState>>,
}

impl PresenceStream {
    /// Wait for the next presence event. Returns `None` only when the
    /// connection is closed (recv error).
    pub async fn recv(&self) -> Option<PresenceEvent> {
        let mut state = self.state.lock().await;
        // Consume events buffered by request/response calls first.
        if let Some(evt) = state.buffered_events.pop_front() {
            return Some(evt);
        }
        state.read_event().await.ok()
    }

    /// Non-blocking peek at a buffered event.
    pub async fn try_recv(&self) -> Option<PresenceEvent> {
        let mut state = self.state.lock().await;
        state.buffered_events.pop_front()
    }
}

/// Authenticated connection to an origin-relay.
pub struct RelayClient {
    state: Arc<Mutex<ConnState>>,
    /// The relay's authenticated session token (diagnostic; the relay
    /// resolves identity from the handshake, not the token).
    session_token: String,
    relay_fp: Fingerprint,
}

impl std::fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayClient")
            .field("relay_fp", &self.relay_fp.to_hex())
            .field(
                "session_token",
                &format!("<{} bytes>", self.session_token.len()),
            )
            .finish()
    }
}

impl RelayClient {
    /// Connect and authenticate to a relay.
    ///
    /// `seed`/`device_index` identify THIS endpoint; `relay_keys` is the
    /// relay's identity record — its transport key is what Noise IK
    /// targets, and its fingerprint binds the AUTH claim.
    pub async fn connect(
        seed: [u8; 32],
        device_index: u32,
        transport: &Arc<dyn Transport>,
        addr: &TransportAddr,
        relay_keys: &PeerKeys,
    ) -> Result<Self> {
        let mut conn = transport.connect(addr).await?;

        // Noise IK initiator against the relay's transport key.
        let secret = crate::identity::derive_transport_secret(&seed, device_index)?;
        let relay_pk = relay_keys.transport_pk_bytes()?;
        let mut hs = origin_channel::handshake::Handshake::new(
            origin_channel::dh::DhSecret::from_bytes(secret.secret_key_bytes()),
            origin_channel::dh::DhPublic::from_bytes(relay_pk),
            true,
        );
        let mut msg1 = hs
            .start()
            .map_err(|e| NetworkError::Handshake(e.to_string()))?;
        msg1.payload
            .extend_from_slice(crate::identity::transport_public_key(&secret).as_slice());
        let m1 = msg1.to_bytes();
        conn.send_frame(msg1.msg_type, &m1[1..]).await?;

        let (_, body2) = conn.recv_frame().await?;
        let msg2 = origin_channel::message::HandshakeMessage::from_bytes(
            &crate::session::reassemble_pub(body2, 0x02),
        )
        .map_err(|e| NetworkError::Handshake(e.to_string()))?;
        let m2 = msg2.to_bytes();
        let msg3 = hs
            .process_msg2(&msg2)
            .map_err(|e| NetworkError::Handshake(e.to_string()))?;
        let m3 = msg3.to_bytes();
        conn.send_frame(msg3.msg_type, &m3[1..]).await?;

        // AUTH claim bound to the transcript + relay fingerprint.
        let relay_fp = relay_keys.fingerprint();
        let transcript = crate::session::transcript_pub(&m1, &m2, &m3);
        let claim = crate::identity::sign_auth_claim(&seed, device_index, &relay_fp, &transcript)?;
        conn.send_frame(WireType::AuthClaim.to_u8(), &encode_payload(&claim)?)
            .await?;

        // Expect AuthOk (or a reject).
        let (tag, body) = conn.recv_frame().await?;
        match WireType::from_u8(tag) {
            Some(WireType::AuthOk) => {
                let ok: AuthOk = decode_payload(&body)?;
                Ok(Self {
                    state: Arc::new(Mutex::new(ConnState {
                        conn,
                        buffered_events: VecDeque::new(),
                        pending_frames: VecDeque::new(),
                    })),
                    session_token: ok.session_token,
                    relay_fp,
                })
            }
            Some(WireType::AuthReject) => {
                let rej: AuthReject = decode_payload(&body)?;
                Err(NetworkError::Auth(format!(
                    "relay rejected: {}",
                    rej.reason
                )))
            }
            other => Err(NetworkError::Handshake(format!(
                "unexpected frame {other:?} in AUTH"
            ))),
        }
    }

    /// The relay's fingerprint this client authenticated against.
    pub fn relay_fingerprint(&self) -> Fingerprint {
        self.relay_fp
    }

    /// The session token issued by the relay (diagnostic).
    pub fn session_token(&self) -> &str {
        &self.session_token
    }

    // ── Control operations ──────────────────────────────────────────────

    /// Probe a peer's online status (imperative primitive, spec §8.2).
    pub async fn probe(&self, target: &Fingerprint) -> Result<bool> {
        let mut state = self.state.lock().await;
        state
            .conn
            .send_frame(
                WireType::Probe.to_u8(),
                &encode_payload(&Probe {
                    target_fp: target.0,
                })?,
            )
            .await?;
        let resp: ProbeResponse = state.read_response(WireType::Probe).await?;
        Ok(resp.online)
    }

    /// Publish an endpoint advertisement for ourselves (spec §8.1).
    /// Replaceable, latest-wins, best-effort by spec — the relay does
    /// not answer a success frame; failures surface on later exchanges.
    pub async fn advert_publish(&self, advert: Advert) -> Result<()> {
        let mut state = self.state.lock().await;
        state
            .conn
            .send_frame(
                WireType::AdvertPublish.to_u8(),
                &encode_payload(&AdvertPublish { advert })?,
            )
            .await?;
        Ok(())
    }

    /// Fetch a peer's current advertisement (spec §8.1). `None` = the
    /// peer published nothing (or it expired).
    pub async fn advert_fetch(&self, target: &Fingerprint) -> Result<Option<Advert>> {
        let mut state = self.state.lock().await;
        state
            .conn
            .send_frame(
                WireType::AdvertFetch.to_u8(),
                &encode_payload(&AdvertFetch {
                    target_fp: target.0,
                })?,
            )
            .await?;
        let resp: AdvertFetchResponse = state.read_response(WireType::AdvertFetch).await?;
        Ok(resp.advert)
    }

    /// Push a frame into a peer's inbox (store-and-forward, §5.2). The
    /// relay buffers only for registered (online) targets; an offline
    /// target produces a `target_offline` error frame on the NEXT read
    /// of this connection (surfaced then as `RelayFull`/error).
    pub async fn inbox_push(&self, target: &Fingerprint, frame: Vec<u8>) -> Result<()> {
        let mut state = self.state.lock().await;
        state
            .conn
            .send_frame(
                WireType::InboxPush.to_u8(),
                &encode_payload(&InboxPush {
                    target_fp: target.0,
                    frame,
                })?,
            )
            .await?;
        Ok(())
    }

    /// Drain our own inbox (read-once, §5.2).
    pub async fn inbox_pull(&self) -> Result<Vec<Vec<u8>>> {
        let mut state = self.state.lock().await;
        state
            .conn
            .send_frame(WireType::InboxPull.to_u8(), &encode_payload(&InboxPull)?)
            .await?;
        let resp: InboxPullResponse = state.read_response(WireType::InboxPull).await?;
        Ok(resp.frames)
    }

    /// Subscribe to presence changes for a target (spec §8.2).
    ///
    /// Returns a `PresenceStream`; the relay's first pushed event is the
    /// target's current state. One stream per client — the connection is
    /// the ordering point.
    pub async fn presence_subscribe(&self, target: &Fingerprint) -> Result<PresenceStream> {
        let mut state = self.state.lock().await;
        state
            .conn
            .send_frame(
                WireType::PresenceSubscribe.to_u8(),
                &encode_payload(&PresenceSubscribe {
                    target_fp: target.0,
                })?,
            )
            .await?;
        Ok(PresenceStream {
            state: Arc::clone(&self.state),
        })
    }

    // ── Live session + data forwarding (spec §5.2) ──────────────────────
    //
    // These drive the relay's "dumb byte forwarder": `session_open` pairs
    // us with a target peer, `relay_send` pushes opaque frames into the
    // pair, and `relay_recv` reads the peer's frames off the same
    // connection (buffering any interleaved presence events). Used by
    // origin-vcs to tunnel its pack protocol through the relay.

    /// Open a live forwarding pair to `target`. Returns the relay-issued
    /// `pair_id` that both endpoints use for `relay_send`/`relay_recv`.
    /// Fails (Error frame) if the target is not registered/online.
    pub async fn session_open(&self, target: &Fingerprint) -> Result<u64> {
        let mut state = self.state.lock().await;
        state
            .conn
            .send_frame(
                WireType::SessionOpen.to_u8(),
                &encode_payload(&SessionOpen {
                    target_fp: target.0,
                })?,
            )
            .await?;
        let ack: SessionOpenAck = state.read_response(WireType::SessionOpenAck).await?;
        Ok(ack.pair_id)
    }

    /// Tear down a forwarding pair.
    pub async fn session_close(&self, pair_id: u64) -> Result<()> {
        let mut state = self.state.lock().await;
        state
            .conn
            .send_frame(
                WireType::SessionClose.to_u8(),
                &encode_payload(&SessionClose { pair_id })?,
            )
            .await?;
        Ok(())
    }

    /// Push one opaque frame into a live pair (forwarded verbatim to the
    /// peer). The frame is bounded by the relay's frame-size cap.
    pub async fn relay_send(&self, pair_id: u64, seq: u64, frame: Vec<u8>) -> Result<()> {
        let mut state = self.state.lock().await;
        state
            .conn
            .send_frame(
                WireType::RelayData.to_u8(),
                &encode_payload(&RelayData {
                    pair_id,
                    seq,
                    frame,
                })?,
            )
            .await
    }

    /// Receive the next live `RelayData` frame forwarded from a paired
    /// peer. Presence events that interleave are buffered for the
    /// `PresenceStream`; a `WireError` frame (e.g. "peer not connected") is
    /// surfaced as an error. Returns `None` when the connection is closed.
    pub async fn relay_recv(&self) -> Result<Option<RelayData>> {
        let mut state = self.state.lock().await;
        // Frames a PresenceStream read already stashed for us come first.
        if let Some(pos) = state
            .pending_frames
            .iter()
            .position(|(t, _)| *t == WireType::RelayData.to_u8())
        {
            let (_, body) = state.pending_frames.remove(pos).unwrap();
            return decode_payload(&body).map(Some);
        }
        loop {
            let (rtag, body) = match state.conn.recv_frame().await {
                Ok(f) => f,
                Err(_) => return Ok(None),
            };
            match WireType::from_u8(rtag) {
                Some(WireType::PresenceEvent) => {
                    let evt: PresenceEvent = match decode_payload(&body) {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    state.buffered_events.push_back(evt);
                }
                Some(WireType::RelayData) => return decode_payload(&body).map(Some),
                Some(WireType::Error) => {
                    let err: WireError = decode_payload(&body)?;
                    return Err(NetworkError::RelayFull(format!(
                        "{}: {}",
                        err.code, err.detail
                    )));
                }
                other => {
                    // Not ours: stash for request/response callers.
                    state
                        .pending_frames
                        .push_back((other.map(|w| w.to_u8()).unwrap_or(rtag), body));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{EvictionSet, RelayState, DEFAULT_MAX_FORWARDINGS};
    use crate::relay_server::RelayServer;
    use crate::session::StaticResolver;
    use crate::transport::TcpTransport;

    fn relay_seed() -> [u8; 32] {
        [0xEE; 32]
    }
    fn alice_seed() -> [u8; 32] {
        [0xA1; 32]
    }
    fn bob_seed() -> [u8; 32] {
        [0xB2; 32]
    }

    async fn test_relay() -> (TransportAddr, Arc<RelayServer>) {
        let mut resolver = StaticResolver::new();
        resolver.add(PeerKeys::from_seed(&alice_seed(), 0).unwrap());
        resolver.add(PeerKeys::from_seed(&bob_seed(), 0).unwrap());
        let server = Arc::new(
            RelayServer::new(
                RelayState::new(DEFAULT_MAX_FORWARDINGS),
                EvictionSet::new(),
                Arc::new(resolver),
                relay_seed(),
            )
            .unwrap(),
        );
        let listener = TcpTransport::listen(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let serve = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = serve.serve(listener).await;
        });
        (addr, server)
    }

    async fn client_for(addr: &TransportAddr, seed: [u8; 32]) -> RelayClient {
        let relay_keys = PeerKeys::from_seed(&relay_seed(), 0).unwrap();
        let transport: Arc<dyn Transport> = Arc::new(TcpTransport::connector());
        RelayClient::connect(seed, 0, &transport, addr, &relay_keys)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn client_connects_and_gets_token() {
        let (addr, _server) = test_relay().await;
        let client = client_for(&addr, alice_seed()).await;
        assert!(!client.session_token().is_empty());
        assert_eq!(
            client.relay_fingerprint(),
            Fingerprint::from_seed_bytes(&relay_seed())
        );
    }

    #[tokio::test]
    async fn client_probe_online_and_offline() {
        let (addr, _server) = test_relay().await;
        let alice = client_for(&addr, alice_seed()).await;
        let bob_fp = Fingerprint::from_seed_bytes(&bob_seed());

        // Bob offline.
        assert!(!alice.probe(&bob_fp).await.unwrap());

        // Bob connects.
        let bob = client_for(&addr, bob_seed()).await;
        assert!(alice.probe(&bob_fp).await.unwrap());
        drop(bob);
        // Wait for the disconnect to propagate.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!alice.probe(&bob_fp).await.unwrap());
    }

    #[tokio::test]
    async fn client_advert_publish_fetch() {
        let (addr, _server) = test_relay().await;
        let alice = client_for(&addr, alice_seed()).await;
        let bob = client_for(&addr, bob_seed()).await;
        let alice_fp = Fingerprint::from_seed_bytes(&alice_seed());

        bob.advert_publish(Advert {
            protocol_version: 1,
            endpoints: vec!["192.168.1.5:9000".into()],
            ttl_secs: 60,
            presence: 1,
        })
        .await
        .unwrap();

        let got = alice.advert_fetch(&alice_fp).await.unwrap();
        // That's Alice's fp — she has no advert.
        assert!(got.is_none());
        let bob_fp = Fingerprint::from_seed_bytes(&bob_seed());
        let got = alice.advert_fetch(&bob_fp).await.unwrap().unwrap();
        assert_eq!(got.endpoints, vec!["192.168.1.5:9000".to_string()]);
        assert_eq!(got.ttl_secs, 60);
    }

    #[tokio::test]
    async fn client_inbox_push_pull_roundtrip() {
        let (addr, _server) = test_relay().await;
        let alice = client_for(&addr, alice_seed()).await;
        let bob = client_for(&addr, bob_seed()).await;
        let bob_fp = Fingerprint::from_seed_bytes(&bob_seed());

        alice
            .inbox_push(&bob_fp, b"hello-bob".to_vec())
            .await
            .unwrap();
        let frames = bob.inbox_pull().await.unwrap();
        assert_eq!(frames, vec![b"hello-bob".to_vec()]);
        // Read-once.
        assert!(bob.inbox_pull().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn client_presence_stream_full_cycle() {
        let (addr, _server) = test_relay().await;
        let alice = client_for(&addr, alice_seed()).await;
        let bob_fp = Fingerprint::from_seed_bytes(&bob_seed());

        let stream = alice.presence_subscribe(&bob_fp).await.unwrap();
        // First event: current state (offline).
        let evt = stream.recv().await.unwrap();
        assert_eq!(evt.target_fp, bob_fp.0);
        assert!(!evt.online);

        // Bob connects → online push.
        let bob = client_for(&addr, bob_seed()).await;
        let evt = tokio::time::timeout(std::time::Duration::from_secs(2), stream.recv())
            .await
            .expect("online push")
            .unwrap();
        assert!(evt.online);

        // Interleave: alice probes while the stream is live — responses
        // must route correctly around buffered presence traffic.
        assert!(alice.probe(&bob_fp).await.unwrap());

        // Bob drops → offline push.
        drop(bob);
        let evt = tokio::time::timeout(std::time::Duration::from_secs(2), stream.recv())
            .await
            .expect("offline push")
            .unwrap();
        assert!(!evt.online);
    }

    #[tokio::test]
    async fn client_presence_try_recv_buffers_interleaved_events() {
        let (addr, _server) = test_relay().await;
        let alice = client_for(&addr, alice_seed()).await;
        let bob_fp = Fingerprint::from_seed_bytes(&bob_seed());
        let stream = alice.presence_subscribe(&bob_fp).await.unwrap();
        // Consume the initial offline event.
        let _ = stream.recv().await.unwrap();

        // Bob connects and disconnects → both transitions queue at the
        // relay for Alice's push channel.
        let bob = client_for(&addr, bob_seed()).await;
        drop(bob);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Probe #1: the relay answers the probe before its next drain
        // iteration, so the response arrives first and the events are
        // still on the wire. Probe #2's read path sweeps them into the
        // stream's buffer en route to its own response.
        assert!(!alice.probe(&bob_fp).await.unwrap());
        assert!(!alice.probe(&bob_fp).await.unwrap());

        // Both transitions are now buffered for the stream.
        let e1 = stream.try_recv().await.unwrap();
        let e2 = stream.try_recv().await.unwrap();
        assert!(e1.online);
        assert!(!e2.online);
        assert!(stream.try_recv().await.is_none());
    }

    #[tokio::test]
    async fn client_connect_unknown_relay_rejected() {
        let (addr, _server) = test_relay().await;
        // Relay's resolver doesn't know this seed → AUTH reject.
        let rogue_keys = PeerKeys::from_seed(&relay_seed(), 0).unwrap();
        let transport: Arc<dyn Transport> = Arc::new(TcpTransport::connector());
        let err = RelayClient::connect([0x77; 32], 0, &transport, &addr, &rogue_keys)
            .await
            .unwrap_err();
        assert!(matches!(err, NetworkError::Auth(_)));
    }

    #[tokio::test]
    async fn client_wrong_relay_key_handshake_fails() {
        let (addr, _server) = test_relay().await;
        // Wrong transport key: IK completes (DH doesn't verify identity),
        // but the relay's claim check rejects: claimed relay fp mismatch
        // surfaces as AuthReject → Auth error.
        let wrong_keys = PeerKeys::from_seed(&[0x99; 32], 0).unwrap();
        let transport: Arc<dyn Transport> = Arc::new(TcpTransport::connector());
        let err = RelayClient::connect(alice_seed(), 0, &transport, &addr, &wrong_keys)
            .await
            .unwrap_err();
        // Handshake fails because the server-side IK uses the real static
        // key while the client DH'd against a different public key.
        assert!(
            matches!(err, NetworkError::Handshake(_) | NetworkError::Auth(_)),
            "got {err:?}"
        );
    }
}
