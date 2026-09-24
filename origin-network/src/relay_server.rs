// SPDX-License-Identifier: Apache-2.0

//! RelayServer — the wire-protocol layer over `RelayState` (spec §5.2).
//!
//! Control protocol: authenticated sessions exchange CONTROL frames
//! (SESSION_OPEN/CLOSE, INBOX_PUSH/PULL, PROBE, ADVERT_*). The relay is a
//! dumb byte forwarder — DATA frames between paired sessions are copied
//! verbatim; the relay never inspects or decrypts them.
//!
//! Auth shape A (signet pattern): Noise IK handshake + AUTH claim to a
//! known static key IS the authentication. Token-binding: the relay
//! resolves `from` ONLY from the session token.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::address::Fingerprint;
use crate::error::{NetworkError, Result};
use crate::identity::verify_auth_claim;
#[cfg(test)]
use crate::identity::PeerKeys;
use crate::relay::{EvictionSet, ForwardOutcome, RelayState};
use crate::replay::HandshakeReplayTracker;
use crate::session::PeerResolver;
use crate::transport::{FrameConn, TcpTransport, Transport, TransportAddr};
use crate::wire::{
    decode_payload, encode_payload, AdvertFetch, AdvertPublish, AuthClaim, AuthOk, AuthReject,
    InboxPull, InboxPush, PresenceEvent, PresenceSubscribe, Probe, RelayData, SessionClose,
    SessionOpen, SessionOpenAck, WireError, WireType,
};

/// Select-over-two helper for the control loop's inbound/outbound fan-in.
enum Either<T, U> {
    Inbound(T),
    Outbound(U),
}

/// Max distinct targets one client may subscribe to (spec §5.3 bounds —
/// never a RAM bomb).
const MAX_SUBSCRIPTIONS_PER_CLIENT: usize = 64;
/// Max subscribers one target may have (spec §5.3 bounds).
const MAX_SUBSCRIBERS_PER_TARGET: usize = 256;

/// Presence subscription registry (spec §8.2). Subscription-based, not
/// polling: the relay pushes `PresenceEvent` frames to every subscriber
/// of a target whenever that target registers or deregisters.
///
/// Bounded both ways: per-client subscription cap and per-target
/// subscriber cap. Cleanup is explicit on disconnect (`remove_client`).
#[derive(Default)]
struct PresenceRegistry {
    /// target → (subscriber fp → that connection's presence sender).
    by_target: HashMap<
        Fingerprint,
        HashMap<Fingerprint, tokio::sync::mpsc::UnboundedSender<PresenceEvent>>,
    >,
    /// subscriber → targets (disconnect cleanup + per-client cap).
    by_client: HashMap<Fingerprint, HashSet<Fingerprint>>,
    /// One sender per connected client, registered at connect time.
    senders: HashMap<Fingerprint, tokio::sync::mpsc::UnboundedSender<PresenceEvent>>,
}

impl PresenceRegistry {
    /// Register a client's presence sender (called once at connect time).
    /// Returns the matching receiver for that connection's push loop.
    fn register_client(
        &mut self,
        client: &Fingerprint,
    ) -> tokio::sync::mpsc::UnboundedReceiver<PresenceEvent> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.senders.insert(*client, tx);
        rx
    }

    /// Add `client` to `target`'s subscriber set.
    fn subscribe(&mut self, target: &Fingerprint, client: &Fingerprint) -> Result<()> {
        let client_targets = self.by_client.entry(*client).or_default();
        if client_targets.len() >= MAX_SUBSCRIPTIONS_PER_CLIENT && !client_targets.contains(target)
        {
            return Err(NetworkError::RelayFull(format!(
                "subscription cap reached ({MAX_SUBSCRIPTIONS_PER_CLIENT})"
            )));
        }
        let subs = self.by_target.entry(*target).or_default();
        if subs.len() >= MAX_SUBSCRIBERS_PER_TARGET && !subs.contains_key(client) {
            return Err(NetworkError::RelayFull(format!(
                "subscriber cap reached for target ({MAX_SUBSCRIBERS_PER_TARGET})"
            )));
        }
        let Some(tx) = self.senders.get(client).cloned() else {
            return Err(NetworkError::Auth(
                "presence subscribe before sender registration".into(),
            ));
        };
        // Re-subscribing is idempotent: replace is a no-op for the set.
        client_targets.insert(*target);
        subs.insert(*client, tx);
        Ok(())
    }

    /// Fan out a presence event to all of a target's subscribers.
    /// Closed channels (dead connections) are pruned lazily. Returns the
    /// number of subscribers actually notified.
    fn notify(&mut self, target: &Fingerprint, event: PresenceEvent) -> usize {
        let Some(subs) = self.by_target.get_mut(target) else {
            return 0;
        };
        let mut delivered = 0;
        let mut dead = Vec::new();
        for (client, tx) in subs.iter() {
            if tx.send(event.clone()).is_ok() {
                delivered += 1;
            } else {
                dead.push(*client);
            }
        }
        for d in dead {
            subs.remove(&d);
            if let Some(targets) = self.by_client.get_mut(&d) {
                targets.remove(target);
            }
        }
        delivered
    }

    /// Drop all of a client's subscriptions (disconnect cleanup).
    fn remove_client(&mut self, client: &Fingerprint) {
        self.senders.remove(client);
        if let Some(targets) = self.by_client.remove(client) {
            for t in targets {
                if let Some(subs) = self.by_target.get_mut(&t) {
                    subs.remove(client);
                    if subs.is_empty() {
                        self.by_target.remove(&t);
                    }
                }
            }
        }
    }

    /// Total live (target, subscriber) pairs.
    fn total_subscriptions(&self) -> usize {
        self.by_target.values().map(|m| m.len()).sum()
    }
}

/// Relay server: serves authenticated sessions over TCP.
pub struct RelayServer {
    state: RelayState,
    eviction: EvictionSet,
    resolver: Arc<dyn PeerResolver>,
    relay_fp: Fingerprint,
    replay: tokio::sync::Mutex<HandshakeReplayTracker>,
    /// Ingress flood control (spec §9). On TCP, source spoofing is already
    /// prevented by the TCP handshake itself, so the token bucket is the
    /// operative gate here; the cookie gate is reserved for the UDP/QUIC
    /// phase where spoofed sources become possible.
    ingress: tokio::sync::Mutex<crate::gate::IngressGate>,
    /// Relay's own static key for Noise IK (X25519 secret bytes).
    relay_static: origin_crypto_sdk::x25519::X25519KeyPair,
    /// Presence subscription registry (spec §8.2).
    presence: tokio::sync::Mutex<PresenceRegistry>,
    /// Outbound relay-data senders, keyed by connected client fingerprint.
    /// Lets one paired client's `control_loop` deliver `RelayData` frames
    /// straight into the other end's connection task (live forwarding,
    /// spec §5.2 — the "dumb byte forwarder"). Bounded: an entry is added
    /// at connect and removed at disconnect.
    conns: tokio::sync::Mutex<HashMap<Fingerprint, tokio::sync::mpsc::UnboundedSender<RelayData>>>,
}

impl RelayServer {
    pub fn new(
        state: RelayState,
        eviction: EvictionSet,
        resolver: Arc<dyn PeerResolver>,
        relay_seed: [u8; 32],
    ) -> Result<Self> {
        let relay_static = crate::identity::derive_transport_secret(&relay_seed, 0)?;
        Ok(Self {
            state,
            eviction,
            resolver,
            relay_fp: Fingerprint::from_seed_bytes(&relay_seed),
            replay: tokio::sync::Mutex::new(HandshakeReplayTracker::new()),
            // Default: 5 handshake attempts per minute per source (spec §5.3).
            ingress: tokio::sync::Mutex::new(crate::gate::IngressGate::new(5, 12)?),
            relay_static,
            presence: tokio::sync::Mutex::new(PresenceRegistry::default()),
            conns: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.relay_fp
    }

    pub fn state(&self) -> &RelayState {
        &self.state
    }

    pub fn eviction(&self) -> &EvictionSet {
        &self.eviction
    }

    /// Evidence bundle (spec §5.5, NetWatch pattern): a portable JSON
    /// snapshot of relay state for post-mortems — registered peers,
    /// forwarding pairs, inbox occupancy, eviction count.
    pub async fn evidence_bundle(&self) -> String {
        let bundle = serde_json::json!({
            "relay_fp": self.relay_fp.to_hex(),
            "online": self.state.online_count().await,
            "active_pairs": self.state.active_pair_count().await,
            "eviction_entries": self.eviction.len().await,
            "presence_subscriptions": self.presence.lock().await.total_subscriptions(),
            "caps": {
                "max_forwardings": self.state.max_forwardings(),
                "max_inbox_messages": self.state.max_inbox_messages(),
                "max_inbox_bytes": self.state.max_inbox_bytes(),
                "inbox_ttl_secs": self.state.inbox_ttl_secs(),
            },
        });
        serde_json::to_string_pretty(&bundle).unwrap_or_default()
    }

    /// Serve until the listener is closed / errors.
    pub async fn serve(self: Arc<Self>, transport: TcpTransport) -> Result<()> {
        loop {
            let conn = transport.accept().await?;
            let server = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(_e) = server.handle_connection(conn).await {
                    // Connection errors are per-client; the server lives on.
                }
            });
        }
    }

    /// Handle one connection: flood gate, handshake, AUTH, register, then
    /// the control loop.
    pub async fn handle_connection(&self, mut conn: Box<dyn FrameConn>) -> Result<()> {
        // Ingress flood control before any ECDH work (spec §9). Keyed by
        // IP only — per-port keying would give every connection a fresh
        // bucket and defeat the gate.
        let source = match conn.peer_addr() {
            TransportAddr::Tcp(sa) => sa.ip().to_string(),
            other => other.to_string(),
        };
        {
            let mut ingress = self.ingress.lock().await;
            if !ingress.allow_handshake(&source) {
                let _ = self
                    .send_error(&mut conn, "rate_limited", "too many handshakes")
                    .await;
                return Err(NetworkError::RateLimited(source));
            }
        }
        let fp = self.authenticate(&mut conn).await?;
        // Eviction checked inside register.
        self.state.register(&self.eviction, &fp).await?;
        // Presence: register this client's push channel and notify
        // subscribers that the peer came online (spec §8.2).
        let presence_rx = {
            let mut presence = self.presence.lock().await;
            let rx = presence.register_client(&fp);
            presence.notify(
                &fp,
                PresenceEvent {
                    target_fp: fp.0,
                    online: true,
                },
            );
            rx
        };
        // Live relay-data: register this connection's outbound sender so a
        // paired peer's control_loop can deliver frames straight here.
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::unbounded_channel::<RelayData>();
        self.conns.lock().await.insert(fp, outbound_tx);
        let token = self.state.issue_token(&fp).await;
        conn.send_frame(
            WireType::AuthOk.to_u8(),
            &encode_payload(&AuthOk {
                session_token: token.clone(),
            })?,
        )
        .await?;

        let result = self
            .control_loop(&mut conn, &fp, presence_rx, outbound_rx)
            .await;
        // Tear down: drop the outbound sender, deregister, notify offline.
        self.conns.lock().await.remove(&fp);
        self.state.deregister(&fp).await;
        // Presence: notify subscribers of the offline transition, then
        // drop the client's subscriptions and sender (spec §8.2).
        {
            let mut presence = self.presence.lock().await;
            presence.notify(
                &fp,
                PresenceEvent {
                    target_fp: fp.0,
                    online: false,
                },
            );
            presence.remove_client(&fp);
        }
        result
    }

    /// Noise IK + AUTH claim verification → the peer's fingerprint.
    async fn authenticate(&self, conn: &mut Box<dyn FrameConn>) -> Result<Fingerprint> {
        // msg1: learn initiator static key.
        let (_, body1) = conn.recv_frame().await?;
        {
            let mut tracker = self.replay.lock().await;
            if !tracker.check_and_track(&body1) {
                return Err(NetworkError::Handshake("handshake replay detected".into()));
            }
        }
        let msg1 = origin_channel::message::HandshakeMessage::from_bytes(
            &crate::session::reassemble_pub(body1.clone(), 0x01),
        )
        .map_err(|e| NetworkError::Handshake(e.to_string()))?;
        if msg1.payload.len() < 32 {
            return Err(NetworkError::Handshake("msg1 missing static key".into()));
        }
        let mut initiator_pk = [0u8; 32];
        initiator_pk.copy_from_slice(&msg1.payload[..32]);

        let mut hs = origin_channel::handshake::Handshake::new(
            origin_channel::dh::DhSecret::from_bytes(self.relay_static.secret_key_bytes()),
            origin_channel::dh::DhPublic::from_bytes(initiator_pk),
            false,
        );
        let mut msg2 = hs
            .process_msg1(&msg1)
            .map_err(|e| NetworkError::Handshake(e.to_string()))?;
        msg2.payload.extend_from_slice(
            crate::identity::transport_public_key(&self.relay_static).as_slice(),
        );
        let m1 = msg1.to_bytes();
        let m2 = msg2.to_bytes();
        conn.send_frame(msg2.msg_type, &m2[1..]).await?;

        // msg3
        let (_, body3) = conn.recv_frame().await?;
        let msg3 = origin_channel::message::HandshakeMessage::from_bytes(
            &crate::session::reassemble_pub(body3, 0x03),
        )
        .map_err(|e| NetworkError::Handshake(e.to_string()))?;
        hs.process_msg3(&msg3)
            .map_err(|e| NetworkError::Handshake(e.to_string()))?;
        let m3 = msg3.to_bytes();

        // AUTH claim (encrypted channel not yet established — claim rides
        // as a CONTROL frame; binding comes from the signature).
        let (tag, body) = conn.recv_frame().await?;
        if tag != WireType::AuthClaim.to_u8() {
            self.send_reject(conn, "expected AUTH claim").await?;
            return Err(NetworkError::Auth("expected AUTH claim".into()));
        }
        let claim: AuthClaim = decode_payload(&body)?;
        let claimed_fp = Fingerprint(claim.fingerprint);
        let keys = match self.resolver.resolve(&claimed_fp) {
            Some(k) => k,
            None => {
                self.send_reject(conn, "unknown peer").await?;
                return Err(NetworkError::Auth("unknown peer".into()));
            }
        };
        if claim.x25519_pk != keys.transport_pk_bytes()? {
            self.send_reject(conn, "claimed key != handshake key")
                .await?;
            return Err(NetworkError::Auth(
                "claimed key does not match handshake key".into(),
            ));
        }
        if self.eviction.is_evicted(&claimed_fp).await {
            self.send_reject(conn, "evicted").await?;
            return Err(NetworkError::Evicted(claimed_fp.to_hex()));
        }
        let transcript = crate::session::transcript_pub(&m1, &m2, &m3);
        if let Err(e) = verify_auth_claim(&keys, &claim, &self.relay_fp, &transcript) {
            self.send_reject(conn, "signature verification failed")
                .await?;
            return Err(e);
        }
        Ok(claimed_fp)
    }

    async fn send_reject(&self, conn: &mut Box<dyn FrameConn>, reason: &str) -> Result<()> {
        conn.send_frame(
            WireType::AuthReject.to_u8(),
            &encode_payload(&AuthReject {
                reason: reason.to_string(),
            })?,
        )
        .await
    }

    /// Presence push latency bound (spec §8.2): the control loop drains
    /// pending events at least this often. `recv_frame` is cancellation-
    /// safe (partial frames stay buffered), so the timeout costs nothing.
    const PRESENCE_PUSH_LATENCY: std::time::Duration = std::time::Duration::from_millis(250);

    /// The authenticated control loop. Selects between inbound frames,
    /// presence pushes, and outbound relayed data via a bounded-latency
    /// drain: events/data are pushed to the client within
    /// `PRESENCE_PUSH_LATENCY` of arrival. Inbound frames drive CONTROL
    /// handling; `RelayData` frames received inbound are forwarded to the
    /// paired peer's connection task (the "dumb byte forwarder").
    async fn control_loop(
        &self,
        conn: &mut Box<dyn FrameConn>,
        fp: &Fingerprint,
        mut presence_rx: tokio::sync::mpsc::UnboundedReceiver<PresenceEvent>,
        mut outbound_rx: tokio::sync::mpsc::UnboundedReceiver<RelayData>,
    ) -> Result<()> {
        loop {
            // Presence push: drain all pending events first. Subscription
            // caps bound the queue size, so this cannot starve frames.
            while let Ok(event) = presence_rx.try_recv() {
                conn.send_frame(WireType::PresenceEvent.to_u8(), &encode_payload(&event)?)
                    .await?;
            }
            // Outbound relay data: drain all pending frames for this
            // connection (delivered from a paired peer's control_loop).
            while let Ok(data) = outbound_rx.try_recv() {
                conn.send_frame(WireType::RelayData.to_u8(), &encode_payload(&data)?)
                    .await?;
            }
            // Inbound frame OR next outbound relay frame, with a deadline so
            // queued presence events / data get out even when idle.
            let next = tokio::select! {
                frame = conn.recv_frame() => Some(Either::Inbound(frame)),
                data = outbound_rx.recv() => {
                    data.map(Either::Outbound)
                }
                _ = tokio::time::sleep(Self::PRESENCE_PUSH_LATENCY) => None,
            };
            let Some(work) = next else {
                // Outbound channel closed (peer gone) — keep serving inbound.
                continue;
            };
            // Presence push interleaving: a slow inbound frame must not stall
            // presence; re-loop to drain presence before handling the frame.
            match work {
                Either::Outbound(data) => {
                    conn.send_frame(WireType::RelayData.to_u8(), &encode_payload(&data)?)
                        .await?;
                    continue;
                }
                Either::Inbound(frame) => {
                    let (tag, body) = frame?;
                    let Some(wt) = WireType::from_u8(tag) else {
                        self.send_error(conn, "bad_type", "unknown wire type")
                            .await?;
                        continue;
                    };
                    match wt {
                        WireType::SessionOpen => {
                            let open: SessionOpen = decode_payload(&body)?;
                            let target = Fingerprint(open.target_fp);
                            match self.state.open_pair(&self.eviction, fp, &target).await {
                                Ok(pair_id) => {
                                    conn.send_frame(
                                        WireType::SessionOpenAck.to_u8(),
                                        &encode_payload(&SessionOpenAck { pair_id })?,
                                    )
                                    .await?;
                                }
                                Err(e) => {
                                    self.send_error(conn, "session_open", &e.to_string())
                                        .await?;
                                }
                            }
                        }
                        WireType::SessionClose => {
                            let close: SessionClose = decode_payload(&body)?;
                            self.state.close_pair(close.pair_id).await;
                        }
                        WireType::InboxPush => {
                            let push: InboxPush = decode_payload(&body)?;
                            let target = Fingerprint(push.target_fp);
                            match self
                                .state
                                .inbox_push(&self.eviction, fp, &target, push.frame)
                                .await
                            {
                                Ok(ForwardOutcome::Buffered) => {}
                                Ok(ForwardOutcome::TargetOffline) => {
                                    self.send_error(conn, "target_offline", &target.to_hex())
                                        .await?;
                                }
                                Err(e) => {
                                    self.send_error(conn, "inbox_push", &e.to_string()).await?;
                                }
                            }
                        }
                        WireType::InboxPull => {
                            let _pull: InboxPull = decode_payload(&body)?;
                            let frames = self.state.inbox_pull(fp).await;
                            // Frames ride as a single JSON payload (bounded by caps).
                            conn.send_frame(
                                WireType::InboxPull.to_u8(),
                                &encode_payload(&InboxPullResponse { frames })?,
                            )
                            .await?;
                        }
                        WireType::Probe => {
                            let probe: Probe = decode_payload(&body)?;
                            let target = Fingerprint(probe.target_fp);
                            let online = self.state.is_online(&target).await;
                            conn.send_frame(
                                WireType::Probe.to_u8(),
                                &encode_payload(&ProbeResponse { online })?,
                            )
                            .await?;
                        }
                        WireType::AdvertPublish => {
                            let pub_msg: AdvertPublish = decode_payload(&body)?;
                            if let Err(e) = self.state.advert_publish(fp, pub_msg.advert).await {
                                self.send_error(conn, "advert_publish", &e.to_string())
                                    .await?;
                            }
                        }
                        WireType::AdvertFetch => {
                            let fetch: AdvertFetch = decode_payload(&body)?;
                            let target = Fingerprint(fetch.target_fp);
                            let advert = self.state.advert_fetch(&target).await;
                            conn.send_frame(
                                WireType::AdvertFetch.to_u8(),
                                &encode_payload(&AdvertFetchResponse { advert })?,
                            )
                            .await?;
                        }
                        WireType::PresenceSubscribe => {
                            let sub: PresenceSubscribe = decode_payload(&body)?;
                            let target = Fingerprint(sub.target_fp);
                            // Lock scope ends before touching state — no nesting.
                            let sub_res = self.presence.lock().await.subscribe(&target, fp);
                            match sub_res {
                                Ok(()) => {
                                    // Immediate state push: the subscriber never
                                    // waits for the next transition to learn the
                                    // current situation.
                                    let online = self.state.is_online(&target).await;
                                    conn.send_frame(
                                        WireType::PresenceEvent.to_u8(),
                                        &encode_payload(&PresenceEvent {
                                            target_fp: sub.target_fp,
                                            online,
                                        })?,
                                    )
                                    .await?;
                                }
                                Err(e) => {
                                    self.send_error(conn, "presence_subscribe", &e.to_string())
                                        .await?;
                                }
                            }
                        }
                        WireType::RelayData => {
                            // Live relayed application data. Forward verbatim to the
                            // paired peer's connection task. Zero-trust: the sender
                            // must be one of the pair's two endpoints, and the pair
                            // must exist (looked up by id).
                            let msg: RelayData = match decode_payload(&body) {
                                Ok(m) => m,
                                Err(e) => {
                                    self.send_error(conn, "relay_data", &e.to_string()).await?;
                                    continue;
                                }
                            };
                            if msg.frame.len() > self.state.max_frame_size() {
                                self.send_error(
                                    conn,
                                    "relay_data",
                                    &format!("frame exceeds {} bytes", self.state.max_frame_size()),
                                )
                                .await?;
                                continue;
                            }
                            let pair = self.state.lookup_pair(msg.pair_id).await;
                            let Some(pair) = pair else {
                                self.send_error(conn, "relay_data", "unknown pair_id")
                                    .await?;
                                continue;
                            };
                            // Sender must be an endpoint; forward to the other end.
                            let peer = if pair.from == *fp {
                                pair.to
                            } else if pair.to == *fp {
                                pair.from
                            } else {
                                self.send_error(conn, "relay_data", "not a member of pair")
                                    .await?;
                                continue;
                            };
                            let delivered = {
                                let conns = self.conns.lock().await;
                                conns.get(&peer).map(|tx| tx.send(msg)).is_some()
                            };
                            if !delivered {
                                // Peer disconnected mid-session: surface as an error
                                // so the sender can fall back to inbox / reconnect.
                                self.send_error(conn, "relay_data", "peer not connected")
                                    .await?;
                            }
                        }
                        other => {
                            self.send_error(conn, "bad_type", &format!("frame {other:?}"))
                                .await?;
                        }
                    }
                }
            }
        }
    }

    async fn send_error(
        &self,
        conn: &mut Box<dyn FrameConn>,
        code: &str,
        detail: &str,
    ) -> Result<()> {
        conn.send_frame(
            WireType::Error.to_u8(),
            &encode_payload(&WireError {
                code: code.to_string(),
                detail: detail.to_string(),
            })?,
        )
        .await
    }
}

/// Inbox pull response (read-once drain).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct InboxPullResponse {
    pub frames: Vec<Vec<u8>>,
}

/// Probe response — boolean only (leakage-minimal, spec §5.2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProbeResponse {
    pub online: bool,
}

/// Advert fetch response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AdvertFetchResponse {
    pub advert: Option<crate::wire::Advert>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::DEFAULT_MAX_FORWARDINGS;
    use crate::session::StaticResolver;
    use crate::transport::{TcpTransport, Transport};
    use crate::wire::SessionClose;

    fn relay_seed() -> [u8; 32] {
        [0xEE; 32]
    }
    fn client_seed() -> [u8; 32] {
        [0xCC; 32]
    }

    fn test_server() -> RelayServer {
        let mut resolver = StaticResolver::new();
        resolver.add(PeerKeys::from_seed(&client_seed(), 0).unwrap());
        RelayServer::new(
            RelayState::new(DEFAULT_MAX_FORWARDINGS),
            EvictionSet::new(),
            Arc::new(resolver),
            relay_seed(),
        )
        .unwrap()
    }

    /// Full client-side handshake + AUTH against a server conn.
    async fn authenticated_client(
        server: &Arc<RelayServer>,
        addr: &crate::transport::TransportAddr,
    ) -> Result<Box<dyn FrameConn>> {
        authenticated_client_with_seed(server, addr, client_seed()).await
    }

    /// Parameterized variant — different seeds = different identities.
    async fn authenticated_client_with_seed(
        server: &Arc<RelayServer>,
        addr: &crate::transport::TransportAddr,
        seed: [u8; 32],
    ) -> Result<Box<dyn FrameConn>> {
        let tc = TcpTransport::connector();
        let mut conn = tc.connect(addr).await?;

        // Drive the client side of Noise IK.
        let secret = crate::identity::derive_transport_secret(&seed, 0)?;
        let relay_pk = crate::identity::transport_public_key(
            &crate::identity::derive_transport_secret(&relay_seed(), 0)?,
        );
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

        // AUTH claim.
        let transcript = crate::session::transcript_pub(&m1, &m2, &m3);
        let relay_fp = Fingerprint::from_seed_bytes(&relay_seed());
        let claim = crate::identity::sign_auth_claim(&seed, 0, &relay_fp, &transcript)?;
        conn.send_frame(
            WireType::AuthClaim.to_u8(),
            &encode_payload(&claim).unwrap(),
        )
        .await?;

        // Expect AuthOk.
        let (tag, body) = conn.recv_frame().await?;
        assert_eq!(tag, WireType::AuthOk.to_u8());
        let ok: AuthOk = decode_payload(&body)?;
        assert!(!ok.session_token.is_empty());
        let _ = server;
        Ok(conn)
    }

    async fn server_with_listener() -> (Arc<RelayServer>, crate::transport::TransportAddr) {
        let server = Arc::new(test_server());
        let listener = TcpTransport::listen(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = srv.serve(listener).await;
        });
        (server, addr)
    }

    #[tokio::test]
    async fn relay_handshake_authenticates_client() {
        let (server, listener) = server_with_listener().await;
        let conn = authenticated_client(&server, &listener).await;
        assert!(conn.is_ok());
        // Client is now registered (online).
        let fp = Fingerprint::from_seed_bytes(&client_seed());
        // Give the server task a moment to register.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(server.state().is_online(&fp).await);
    }

    #[tokio::test]
    async fn relay_probe_reports_status() {
        let (server, listener) = server_with_listener().await;
        let mut conn = authenticated_client(&server, &listener).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let fp = Fingerprint::from_seed_bytes(&client_seed());
        conn.send_frame(
            WireType::Probe.to_u8(),
            &encode_payload(&Probe { target_fp: fp.0 }).unwrap(),
        )
        .await
        .unwrap();
        let (tag, body) = conn.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::Probe.to_u8());
        let resp: ProbeResponse = decode_payload(&body).unwrap();
        assert!(resp.online);

        // Unknown fingerprint → offline.
        conn.send_frame(
            WireType::Probe.to_u8(),
            &encode_payload(&Probe {
                target_fp: [0x99; 32],
            })
            .unwrap(),
        )
        .await
        .unwrap();
        let (_tag, body) = conn.recv_frame().await.unwrap();
        let resp: ProbeResponse = decode_payload(&body).unwrap();
        assert!(!resp.online);
    }

    #[tokio::test]
    async fn relay_inbox_push_pull() {
        let (server, listener) = server_with_listener().await;
        let mut conn = authenticated_client(&server, &listener).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let fp = Fingerprint::from_seed_bytes(&client_seed());

        // Push to self (we're registered).
        conn.send_frame(
            WireType::InboxPush.to_u8(),
            &encode_payload(&InboxPush {
                target_fp: fp.0,
                frame: b"offline-msg".to_vec(),
            })
            .unwrap(),
        )
        .await
        .unwrap();
        // Pull.
        conn.send_frame(
            WireType::InboxPull.to_u8(),
            &encode_payload(&InboxPull).unwrap(),
        )
        .await
        .unwrap();
        let (tag, body) = conn.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::InboxPull.to_u8());
        let resp: InboxPullResponse = decode_payload(&body).unwrap();
        assert_eq!(resp.frames, vec![b"offline-msg".to_vec()]);
        // Read-once.
        conn.send_frame(
            WireType::InboxPull.to_u8(),
            &encode_payload(&InboxPull).unwrap(),
        )
        .await
        .unwrap();
        let (_, body) = conn.recv_frame().await.unwrap();
        let resp: InboxPullResponse = decode_payload(&body).unwrap();
        assert!(resp.frames.is_empty());
    }

    #[tokio::test]
    async fn relay_advert_publish_fetch() {
        let (server, listener) = server_with_listener().await;
        let mut conn = authenticated_client(&server, &listener).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let fp = Fingerprint::from_seed_bytes(&client_seed());

        let advert = crate::wire::Advert {
            protocol_version: 1,
            endpoints: vec!["10.0.0.5:7331".into()],
            ttl_secs: 120,
            presence: 1,
        };
        conn.send_frame(
            WireType::AdvertPublish.to_u8(),
            &encode_payload(&AdvertPublish {
                advert: advert.clone(),
            })
            .unwrap(),
        )
        .await
        .unwrap();
        conn.send_frame(
            WireType::AdvertFetch.to_u8(),
            &encode_payload(&AdvertFetch { target_fp: fp.0 }).unwrap(),
        )
        .await
        .unwrap();
        let (tag, body) = conn.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::AdvertFetch.to_u8());
        let resp: AdvertFetchResponse = decode_payload(&body).unwrap();
        assert_eq!(resp.advert, Some(advert));
    }

    #[tokio::test]
    async fn relay_session_open_close() {
        let (server, listener) = server_with_listener().await;
        let mut conn = authenticated_client(&server, &listener).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let fp = Fingerprint::from_seed_bytes(&client_seed());

        // Pair to self (both endpoints registered under one fingerprint).
        conn.send_frame(
            WireType::SessionOpen.to_u8(),
            &encode_payload(&SessionOpen { target_fp: fp.0 }).unwrap(),
        )
        .await
        .unwrap();
        let (tag, body) = conn.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::SessionOpenAck.to_u8());
        let ack: SessionOpenAck = decode_payload(&body).unwrap();
        assert!(ack.pair_id > 0);
        assert_eq!(server.state().active_pair_count().await, 1);

        conn.send_frame(
            WireType::SessionClose.to_u8(),
            &encode_payload(&SessionClose {
                pair_id: ack.pair_id,
            })
            .unwrap(),
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(server.state().active_pair_count().await, 0);
    }

    /// Live relay: a `RelayData` frame from one paired client is copied
    /// verbatim to the other end (the "dumb byte forwarder", spec §5.2).
    #[tokio::test]
    async fn relay_live_data_forwards_between_paired_clients() {
        let (server, addr) = server_with_two_identities().await;
        let mut alice = authenticated_client_with_seed(&server, &addr, client_seed())
            .await
            .unwrap();
        let mut bob = authenticated_client_with_seed(&server, &addr, watcher_seed())
            .await
            .unwrap();
        let alice_fp = Fingerprint::from_seed_bytes(&client_seed());
        let bob_fp = Fingerprint::from_seed_bytes(&watcher_seed());
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        // Alice opens a pair to Bob.
        alice
            .send_frame(
                WireType::SessionOpen.to_u8(),
                &encode_payload(&SessionOpen {
                    target_fp: bob_fp.0,
                })
                .unwrap(),
            )
            .await
            .unwrap();
        let (tag, body) = alice.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::SessionOpenAck.to_u8());
        let open_ack: SessionOpenAck = decode_payload(&body).unwrap();
        let pair_id = open_ack.pair_id;
        assert!(pair_id > 0);
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        // Alice sends live data on the pair; Bob must receive it verbatim.
        // (bob may have a queued PresenceEvent for alice's online; drain it.)
        let payload = b"hello relayed world".to_vec();
        alice
            .send_frame(
                WireType::RelayData.to_u8(),
                &encode_payload(&RelayData {
                    pair_id,
                    seq: 1,
                    frame: payload.clone(),
                })
                .unwrap(),
            )
            .await
            .unwrap();

        // Find the RelayData frame among whatever Bob receives.
        let mut got: Option<Vec<u8>> = None;
        for _ in 0..10 {
            let (t, b) = bob.recv_frame().await.unwrap();
            if t == WireType::RelayData.to_u8() {
                let d: RelayData = decode_payload(&b).unwrap();
                assert_eq!(d.pair_id, pair_id);
                assert_eq!(d.seq, 1);
                got = Some(d.frame);
                break;
            }
            // Otherwise it's a PresenceEvent (alice came online) — ignore.
        }
        assert_eq!(got, Some(payload));

        // Frame size cap: oversize RelayData is rejected with an error.
        let big = vec![0xAB; server.state().max_frame_size() + 1];
        alice
            .send_frame(
                WireType::RelayData.to_u8(),
                &encode_payload(&RelayData {
                    pair_id,
                    seq: 2,
                    frame: big,
                })
                .unwrap(),
            )
            .await
            .unwrap();
        let mut rejected = false;
        for _ in 0..5 {
            let (t, b) = alice.recv_frame().await.unwrap();
            if t == WireType::Error.to_u8() {
                let e: WireError = decode_payload(&b).unwrap();
                assert_eq!(e.code, "relay_data");
                rejected = true;
                break;
            }
        }
        assert!(rejected, "oversize RelayData should be rejected");
        let _ = (alice_fp, bob_fp);
    }

    #[tokio::test]
    async fn relay_unknown_client_rejected() {
        let server = Arc::new(test_server());
        let listener = TcpTransport::listen(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = srv.serve(listener).await;
        });

        // Client with a seed the resolver doesn't know.
        let stranger = [0x77; 32];
        let tc = TcpTransport::connector();
        let mut conn = tc.connect(&addr).await.unwrap();
        let secret = crate::identity::derive_transport_secret(&stranger, 0).unwrap();
        let relay_pk = crate::identity::transport_public_key(
            &crate::identity::derive_transport_secret(&relay_seed(), 0).unwrap(),
        );
        let mut hs = origin_channel::handshake::Handshake::new(
            origin_channel::dh::DhSecret::from_bytes(secret.secret_key_bytes()),
            origin_channel::dh::DhPublic::from_bytes(relay_pk),
            true,
        );
        let mut msg1 = hs.start().unwrap();
        msg1.payload
            .extend_from_slice(crate::identity::transport_public_key(&secret).as_slice());
        let wire = msg1.to_bytes();
        conn.send_frame(msg1.msg_type, &wire[1..]).await.unwrap();
        let (_, body2) = conn.recv_frame().await.unwrap();
        let msg2 = origin_channel::message::HandshakeMessage::from_bytes(
            &crate::session::reassemble_pub(body2, 0x02),
        )
        .unwrap();
        let msg3 = hs.process_msg2(&msg2).unwrap();
        let wire3 = msg3.to_bytes();
        conn.send_frame(msg3.msg_type, &wire3[1..]).await.unwrap();

        let claim = crate::identity::sign_auth_claim(
            &stranger,
            0,
            &Fingerprint::from_seed_bytes(&relay_seed()),
            b"irrelevant",
        )
        .unwrap();
        conn.send_frame(
            WireType::AuthClaim.to_u8(),
            &encode_payload(&claim).unwrap(),
        )
        .await
        .unwrap();
        let (tag, body) = conn.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::AuthReject.to_u8());
        let rej: AuthReject = decode_payload(&body).unwrap();
        assert!(!rej.reason.is_empty());
    }

    #[tokio::test]
    async fn server_fingerprint_stable() {
        let s = test_server();
        assert_eq!(s.fingerprint(), Fingerprint::from_seed_bytes(&relay_seed()));
    }

    #[tokio::test]
    async fn evidence_bundle_snapshot() {
        let (server, _addr) = server_with_listener().await;
        let bundle = server.evidence_bundle().await;
        assert!(bundle.contains("relay_fp"));
        assert!(bundle.contains("max_forwardings"));
        let v: serde_json::Value = serde_json::from_str(&bundle).unwrap();
        assert_eq!(v["eviction_entries"], 0);
    }

    #[tokio::test]
    async fn ingress_rate_limits_handshake_flood() {
        let (server, addr) = server_with_listener().await;
        // Gate: 5 per 12s per source. Open 6 bare connections from the
        // same loopback source without completing any handshake.
        let tc = TcpTransport::connector();
        for _ in 0..5 {
            let _ = tc.connect(&addr).await.unwrap();
            // Connection sits: admitted past the bucket, blocks in recv.
        }
        // Let the five admitted handlers consume their bucket tokens.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let mut sixth = tc.connect(&addr).await.unwrap();
        // The sixth is rate-limited: relay sends a WireError, then closes.
        let (tag, body) = sixth.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::Error.to_u8());
        let err: WireError = decode_payload(&body).unwrap();
        assert_eq!(err.code, "rate_limited");
        let _ = server;
    }

    #[tokio::test]
    async fn msg1_without_static_key_rejected() {
        let (server, addr) = server_with_listener().await;
        let tc = TcpTransport::connector();
        let mut conn = tc.connect(&addr).await.unwrap();
        // msg1 with empty payload → server must reject before ECDH.
        conn.send_frame(0x01, &[0u8; 32]).await.unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), conn.recv_frame()).await;
        // Server closes without responding.
        if let Ok(Ok(_)) = res {
            panic!("server answered a keyless msg1");
        }
        let _ = server;
    }

    #[tokio::test]
    async fn non_auth_frame_after_handshake_rejected() {
        let (server, addr) = server_with_listener().await;
        let tc = TcpTransport::connector();
        let mut conn = tc.connect(&addr).await.unwrap();
        // Handshake up to AUTH stage, then send a Probe instead of claim.
        let secret = crate::identity::derive_transport_secret(&client_seed(), 0).unwrap();
        let relay_pk = crate::identity::transport_public_key(
            &crate::identity::derive_transport_secret(&relay_seed(), 0).unwrap(),
        );
        let mut hs = origin_channel::handshake::Handshake::new(
            origin_channel::dh::DhSecret::from_bytes(secret.secret_key_bytes()),
            origin_channel::dh::DhPublic::from_bytes(relay_pk),
            true,
        );
        let mut msg1 = hs.start().unwrap();
        msg1.payload
            .extend_from_slice(crate::identity::transport_public_key(&secret).as_slice());
        let m1 = msg1.to_bytes();
        conn.send_frame(msg1.msg_type, &m1[1..]).await.unwrap();
        let (_, body2) = conn.recv_frame().await.unwrap();
        let msg2 = origin_channel::message::HandshakeMessage::from_bytes(
            &crate::session::reassemble_pub(body2, 0x02),
        )
        .unwrap();
        let msg3 = hs.process_msg2(&msg2).unwrap();
        let m3 = msg3.to_bytes();
        conn.send_frame(msg3.msg_type, &m3[1..]).await.unwrap();
        // Wrong frame type where AUTH claim belongs.
        conn.send_frame(
            WireType::Probe.to_u8(),
            &encode_payload(&Probe { target_fp: [0; 32] }).unwrap(),
        )
        .await
        .unwrap();
        let (tag, body) = conn.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::AuthReject.to_u8());
        let rej: AuthReject = decode_payload(&body).unwrap();
        assert!(rej.reason.contains("AUTH"));
        let _ = server;
    }

    #[tokio::test]
    async fn evicted_client_rejected_at_register() {
        let server = Arc::new(test_server());
        let fp = Fingerprint::from_seed_bytes(&client_seed());
        server.eviction().revoke(&fp).await;
        let listener = TcpTransport::listen(([127, 0, 0, 1], 0).into())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = srv.serve(listener).await;
        });

        // Full handshake + valid claim — rejected because evicted.
        let tc = TcpTransport::connector();
        let mut conn = tc.connect(&addr).await.unwrap();
        let secret = crate::identity::derive_transport_secret(&client_seed(), 0).unwrap();
        let relay_pk = crate::identity::transport_public_key(
            &crate::identity::derive_transport_secret(&relay_seed(), 0).unwrap(),
        );
        let mut hs = origin_channel::handshake::Handshake::new(
            origin_channel::dh::DhSecret::from_bytes(secret.secret_key_bytes()),
            origin_channel::dh::DhPublic::from_bytes(relay_pk),
            true,
        );
        let mut msg1 = hs.start().unwrap();
        msg1.payload
            .extend_from_slice(crate::identity::transport_public_key(&secret).as_slice());
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
        let transcript = crate::session::transcript_pub(&m1, &m2, &m3);
        let claim = crate::identity::sign_auth_claim(
            &client_seed(),
            0,
            &Fingerprint::from_seed_bytes(&relay_seed()),
            &transcript,
        )
        .unwrap();
        conn.send_frame(
            WireType::AuthClaim.to_u8(),
            &encode_payload(&claim).unwrap(),
        )
        .await
        .unwrap();
        let (tag, body) = conn.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::AuthReject.to_u8());
        let rej: AuthReject = decode_payload(&body).unwrap();
        assert_eq!(rej.reason, "evicted");
    }

    // ── PresenceRegistry unit tests ─────────────────────────────────────

    fn fp_of(byte: u8) -> Fingerprint {
        Fingerprint([byte; 32])
    }

    #[test]
    fn presence_registry_subscribe_notify_delivers() {
        let mut reg = PresenceRegistry::default();
        let sub_a = fp_of(0xA1);
        let sub_b = fp_of(0xB2);
        let target = fp_of(0xC3);
        let mut _rx_a = reg.register_client(&sub_a);
        let mut _rx_b = reg.register_client(&sub_b);
        reg.subscribe(&target, &sub_a).unwrap();
        reg.subscribe(&target, &sub_b).unwrap();
        assert_eq!(reg.total_subscriptions(), 2);

        let n = reg.notify(
            &target,
            PresenceEvent {
                target_fp: target.0,
                online: true,
            },
        );
        assert_eq!(n, 2);
        // Both receivers got the event.
        let evt = _rx_a.try_recv().unwrap();
        assert!(evt.online);
        assert_eq!(evt.target_fp, target.0);
        assert!(_rx_b.try_recv().is_ok());
    }

    #[test]
    fn presence_registry_re_subscribe_idempotent() {
        let mut reg = PresenceRegistry::default();
        let sub = fp_of(0xA1);
        let target = fp_of(0xC3);
        let mut _rx = reg.register_client(&sub);
        reg.subscribe(&target, &sub).unwrap();
        reg.subscribe(&target, &sub).unwrap();
        assert_eq!(reg.total_subscriptions(), 1);
        // Notify once → exactly one delivery (no duplicates).
        reg.notify(
            &target,
            PresenceEvent {
                target_fp: target.0,
                online: false,
            },
        );
        assert!(_rx.try_recv().is_ok());
        assert!(_rx.try_recv().is_err());
    }

    #[test]
    fn presence_registry_notify_prunes_dead_receivers() {
        let mut reg = PresenceRegistry::default();
        let sub = fp_of(0xA1);
        let target = fp_of(0xC3);
        let rx = reg.register_client(&sub);
        reg.subscribe(&target, &sub).unwrap();
        drop(rx); // connection gone

        let n = reg.notify(
            &target,
            PresenceEvent {
                target_fp: target.0,
                online: true,
            },
        );
        assert_eq!(n, 0);
        assert_eq!(reg.total_subscriptions(), 0);
    }

    #[test]
    fn presence_registry_notify_unknown_target_zero() {
        let mut reg = PresenceRegistry::default();
        let n = reg.notify(
            &fp_of(0x99),
            PresenceEvent {
                target_fp: [0x99; 32],
                online: true,
            },
        );
        assert_eq!(n, 0);
    }

    #[test]
    fn presence_registry_remove_client_cleans_all() {
        let mut reg = PresenceRegistry::default();
        let sub = fp_of(0xA1);
        let t1 = fp_of(0xC3);
        let t2 = fp_of(0xC4);
        let _rx = reg.register_client(&sub);
        reg.subscribe(&t1, &sub).unwrap();
        reg.subscribe(&t2, &sub).unwrap();
        assert_eq!(reg.total_subscriptions(), 2);
        reg.remove_client(&sub);
        assert_eq!(reg.total_subscriptions(), 0);
        // Re-subscribe after removal requires re-registration.
        let err = reg.subscribe(&t1, &sub).unwrap_err();
        assert!(matches!(err, NetworkError::Auth(_)));
    }

    #[test]
    fn presence_registry_per_client_cap_enforced() {
        let mut reg = PresenceRegistry::default();
        let sub = fp_of(0xA1);
        let _rx = reg.register_client(&sub);
        for i in 0..MAX_SUBSCRIPTIONS_PER_CLIENT {
            reg.subscribe(&fp_of(i as u8), &sub).unwrap();
        }
        // One more distinct target → cap.
        let err = reg.subscribe(&fp_of(0xFE), &sub).unwrap_err();
        assert!(matches!(err, NetworkError::RelayFull(_)));
        // Re-subscribing an existing target stays allowed.
        reg.subscribe(&fp_of(0x01), &sub).unwrap();
        assert_eq!(reg.total_subscriptions(), MAX_SUBSCRIPTIONS_PER_CLIENT);
    }

    #[test]
    fn presence_registry_per_target_cap_enforced() {
        let mut reg = PresenceRegistry::default();
        let target = fp_of(0xC3);
        // 0..255 as the first byte, plus 0x7F variants via second byte.
        for i in 0..MAX_SUBSCRIBERS_PER_TARGET {
            let mut bytes = [0u8; 32];
            bytes[0] = (i % 256) as u8;
            bytes[1] = (i / 256) as u8;
            let sub = Fingerprint(bytes);
            let _rx = reg.register_client(&sub);
            reg.subscribe(&target, &sub).unwrap();
        }
        let mut overflow = [0u8; 32];
        overflow[0] = 0xFF;
        overflow[1] = 0xFF;
        let extra = Fingerprint(overflow);
        let _rx = reg.register_client(&extra);
        let err = reg.subscribe(&target, &extra).unwrap_err();
        assert!(matches!(err, NetworkError::RelayFull(_)));
    }

    // ── Presence end-to-end tests ───────────────────────────────────────

    fn watcher_seed() -> [u8; 32] {
        [0xDD; 32]
    }

    /// A server whose resolver knows both the default client and the
    /// watcher identity (presence tests need two real identities).
    async fn server_with_two_identities() -> (Arc<RelayServer>, crate::transport::TransportAddr) {
        let mut resolver = StaticResolver::new();
        resolver.add(PeerKeys::from_seed(&client_seed(), 0).unwrap());
        resolver.add(PeerKeys::from_seed(&watcher_seed(), 0).unwrap());
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
        let serve_server = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = serve_server.serve(listener).await;
        });
        (server, addr)
    }

    #[tokio::test]
    async fn presence_subscribe_pushes_current_then_transitions() {
        let (_server, addr) = server_with_two_identities().await;
        let target_fp = Fingerprint::from_seed_bytes(&client_seed());

        // Watcher connects first, subscribes to the (offline) target.
        let mut watcher = authenticated_client_with_seed(&_server, &addr, watcher_seed())
            .await
            .unwrap();
        watcher
            .send_frame(
                WireType::PresenceSubscribe.to_u8(),
                &encode_payload(&PresenceSubscribe {
                    target_fp: target_fp.0,
                })
                .unwrap(),
            )
            .await
            .unwrap();
        // Immediate state push: target is offline.
        let (tag, body) = watcher.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::PresenceEvent.to_u8());
        let evt: PresenceEvent = decode_payload(&body).unwrap();
        assert_eq!(evt.target_fp, target_fp.0);
        assert!(!evt.online);

        // Target connects → watcher receives online transition.
        let target = authenticated_client(&_server, &addr).await.unwrap();
        let (tag, body) =
            tokio::time::timeout(std::time::Duration::from_secs(2), watcher.recv_frame())
                .await
                .expect("online push within latency bound")
                .unwrap();
        assert_eq!(tag, WireType::PresenceEvent.to_u8());
        let evt: PresenceEvent = decode_payload(&body).unwrap();
        assert!(evt.online);

        // Target drops → watcher receives offline transition.
        drop(target);
        let (tag, body) =
            tokio::time::timeout(std::time::Duration::from_secs(2), watcher.recv_frame())
                .await
                .expect("offline push within latency bound")
                .unwrap();
        assert_eq!(tag, WireType::PresenceEvent.to_u8());
        let evt: PresenceEvent = decode_payload(&body).unwrap();
        assert!(!evt.online);
    }

    #[tokio::test]
    async fn presence_subscribe_online_target_reports_online() {
        let (_server, addr) = server_with_two_identities().await;
        let target_fp = Fingerprint::from_seed_bytes(&client_seed());

        // Target connects FIRST.
        let _target = authenticated_client(&_server, &addr).await.unwrap();

        // Watcher subscribes → immediate state push says online.
        let mut watcher = authenticated_client_with_seed(&_server, &addr, watcher_seed())
            .await
            .unwrap();
        watcher
            .send_frame(
                WireType::PresenceSubscribe.to_u8(),
                &encode_payload(&PresenceSubscribe {
                    target_fp: target_fp.0,
                })
                .unwrap(),
            )
            .await
            .unwrap();
        let (tag, body) = watcher.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::PresenceEvent.to_u8());
        let evt: PresenceEvent = decode_payload(&body).unwrap();
        assert!(evt.online);
    }

    #[tokio::test]
    async fn presence_subscription_cap_over_wire() {
        let (_server, addr) = server_with_two_identities().await;
        let mut watcher = authenticated_client_with_seed(&_server, &addr, watcher_seed())
            .await
            .unwrap();

        for i in 0..MAX_SUBSCRIPTIONS_PER_CLIENT {
            watcher
                .send_frame(
                    WireType::PresenceSubscribe.to_u8(),
                    &encode_payload(&PresenceSubscribe {
                        target_fp: [i as u8; 32],
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
            // Each subscribe answers with an immediate state push.
            let (tag, _body) = watcher.recv_frame().await.unwrap();
            assert_eq!(tag, WireType::PresenceEvent.to_u8());
        }

        // One past the cap → error frame, not a presence event.
        watcher
            .send_frame(
                WireType::PresenceSubscribe.to_u8(),
                &encode_payload(&PresenceSubscribe {
                    target_fp: [0xEE; 32],
                })
                .unwrap(),
            )
            .await
            .unwrap();
        let (tag, body) = watcher.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::Error.to_u8());
        let err: WireError = decode_payload(&body).unwrap();
        assert_eq!(err.code, "presence_subscribe");
        assert!(err.detail.contains("cap"));
    }

    #[tokio::test]
    async fn control_loop_error_paths() {
        let (server, addr) = server_with_listener().await;
        let mut conn = authenticated_client(&server, &addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // InboxPush to an offline target → target_offline error frame.
        conn.send_frame(
            WireType::InboxPush.to_u8(),
            &encode_payload(&InboxPush {
                target_fp: [0xAB; 32],
                frame: b"x".to_vec(),
            })
            .unwrap(),
        )
        .await
        .unwrap();
        let (tag, body) = conn.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::Error.to_u8());
        let err: WireError = decode_payload(&body).unwrap();
        assert_eq!(err.code, "target_offline");

        // SessionOpen to offline target → session_open error.
        conn.send_frame(
            WireType::SessionOpen.to_u8(),
            &encode_payload(&SessionOpen {
                target_fp: [0xCD; 32],
            })
            .unwrap(),
        )
        .await
        .unwrap();
        let (tag, body) = conn.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::Error.to_u8());
        let err: WireError = decode_payload(&body).unwrap();
        assert_eq!(err.code, "session_open");

        // Unknown wire type → bad_type.
        conn.send_frame(0x60, b"nonsense").await.unwrap();
        let (tag, body) = conn.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::Error.to_u8());
        let err: WireError = decode_payload(&body).unwrap();
        assert_eq!(err.code, "bad_type");

        // Known type with no control-loop meaning (AuthClaim) → bad_type.
        conn.send_frame(WireType::AuthClaim.to_u8(), b"{}")
            .await
            .unwrap();
        let (tag, body) = conn.recv_frame().await.unwrap();
        assert_eq!(tag, WireType::Error.to_u8());
        let err: WireError = decode_payload(&body).unwrap();
        assert_eq!(err.code, "bad_type");
    }
}
