// SPDX-License-Identifier: Apache-2.0

//! Relay state — authenticated registry, forward pairs, bounded inboxes,
//! eviction, adverts (spec REV 3 §5.1–§5.4).
//!
//! Extracted from signet-relay/state.rs (290 LOC, extraction item #1),
//! adapted: byte cap added, eviction persistence split, advert store
//! added, token binding kept verbatim (zero-trust: `from` is resolved
//! ONLY from the session token, never from client-supplied identity).

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::address::Fingerprint;
use crate::error::{NetworkError, Result};
use crate::wire::Advert;

/// Default maximum concurrent forwarding sessions (spec §5.3).
pub const DEFAULT_MAX_FORWARDINGS: usize = 1000;
/// Default maximum buffered frames per agent inbox (spec §5.3).
pub const DEFAULT_MAX_INBOX_MESSAGES: usize = 256;
/// Default per-agent inbox byte cap (spec §5.3) — prevents 256×1MB.
pub const DEFAULT_MAX_INBOX_BYTES: usize = 8 * 1024 * 1024;
/// Default inbox frame TTL (spec §5.3).
pub const DEFAULT_INBOX_TTL_SECS: u64 = 300;
/// Default relay frame size cap (spec §5.3).
pub const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;

/// A buffered inbound frame with its enqueue timestamp.
#[derive(Clone)]
struct TimestampedFrame {
    bytes: Vec<u8>,
    enqueued_at: Instant,
}

/// One active forwarding relationship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardPair {
    pub id: u64,
    pub from: Fingerprint,
    pub to: Fingerprint,
}

/// Relay state. Cheap to clone (Arc-wrapped fields) — share one instance
/// across all server tasks.
#[derive(Clone)]
pub struct RelayState {
    inner: std::sync::Arc<Mutex<RelayStateInner>>,
    max_forwardings: usize,
    max_inbox_messages: usize,
    max_inbox_bytes: usize,
    inbox_ttl: Duration,
    max_frame_size: usize,
}

struct RelayStateInner {
    /// Registered (online) fingerprints.
    online: HashSet<Fingerprint>,
    /// Session tokens → authenticated fingerprint. The token is the ONLY
    /// way the relay learns `from` for a forward (zero-trust boundary).
    tokens: HashMap<String, Fingerprint>,
    /// Active forwardings.
    forwarding: Vec<ForwardPair>,
    next_pair_id: u64,
    /// Bounded offline inboxes.
    inboxes: HashMap<Fingerprint, (Vec<TimestampedFrame>, usize)>,
    /// Endpoint adverts (latest wins, TTL-expired on read).
    adverts: HashMap<Fingerprint, (Advert, Instant)>,
}

/// Result of a forward attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardOutcome {
    /// Frame buffered into the target's inbox.
    Buffered,
    /// Target offline — frame rejected.
    TargetOffline,
}

impl RelayState {
    pub fn new(max_forwardings: usize) -> Self {
        Self::with_caps(
            max_forwardings,
            DEFAULT_MAX_INBOX_MESSAGES,
            DEFAULT_MAX_INBOX_BYTES,
            DEFAULT_INBOX_TTL_SECS,
        )
    }

    pub fn with_caps(
        max_forwardings: usize,
        max_inbox_messages: usize,
        max_inbox_bytes: usize,
        inbox_ttl_secs: u64,
    ) -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(RelayStateInner {
                online: HashSet::new(),
                tokens: HashMap::new(),
                forwarding: Vec::new(),
                next_pair_id: 1,
                inboxes: HashMap::new(),
                adverts: HashMap::new(),
            })),
            max_forwardings,
            max_inbox_messages,
            max_inbox_bytes,
            inbox_ttl: Duration::from_secs(inbox_ttl_secs),
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }

    // ── Eviction (PERSISTED — spec §5.4) ───────────────────────────────

    /// Revoke a fingerprint. Returns true if newly added.
    pub async fn revoke(&self, eviction: &EvictionSet, fp: &Fingerprint) -> bool {
        eviction.revoke(fp).await
    }

    // ── Registration ───────────────────────────────────────────────────

    /// Register an authenticated agent. Refuses evicted fingerprints.
    pub async fn register(&self, eviction: &EvictionSet, fp: &Fingerprint) -> Result<()> {
        if eviction.is_evicted(fp).await {
            return Err(NetworkError::Evicted(fp.to_hex()));
        }
        let mut inner = self.inner.lock().await;
        inner.online.insert(*fp);
        Ok(())
    }

    /// Drop a registration (disconnect) + its tokens and forwardings.
    pub async fn deregister(&self, fp: &Fingerprint) {
        let mut inner = self.inner.lock().await;
        inner.online.remove(fp);
        inner.tokens.retain(|_, v| v != fp);
        inner.forwarding.retain(|p| p.from != *fp && p.to != *fp);
    }

    pub async fn is_online(&self, fp: &Fingerprint) -> bool {
        self.inner.lock().await.online.contains(fp)
    }

    pub async fn online_count(&self) -> usize {
        self.inner.lock().await.online.len()
    }

    // ── Tokens (zero-trust from-resolution) ────────────────────────────

    /// Issue a session token bound to an authenticated fingerprint.
    pub async fn issue_token(&self, fp: &Fingerprint) -> String {
        let mut raw = [0u8; 32];
        origin_crypto_sdk::fill_random(&mut raw).expect("OS CSPRNG available");
        let token = hex::encode(raw);
        self.inner.lock().await.tokens.insert(token.clone(), *fp);
        token
    }

    /// Resolve a token to its fingerprint (None if unknown/revoked).
    pub async fn resolve_token(&self, token: &str) -> Option<Fingerprint> {
        self.inner.lock().await.tokens.get(token).copied()
    }

    pub async fn revoke_token(&self, token: &str) {
        self.inner.lock().await.tokens.remove(token);
    }

    // ── Forwarding pairs ───────────────────────────────────────────────

    /// Open a forwarding pair from→to. Both must be registered; the cap
    /// is enforced. Returns the pair id.
    pub async fn open_pair(
        &self,
        eviction: &EvictionSet,
        from: &Fingerprint,
        to: &Fingerprint,
    ) -> Result<u64> {
        if eviction.is_evicted(from).await {
            return Err(NetworkError::Evicted(from.to_hex()));
        }
        let mut inner = self.inner.lock().await;
        if !inner.online.contains(from) {
            return Err(NetworkError::TargetOffline(from.to_hex()));
        }
        if !inner.online.contains(to) {
            return Err(NetworkError::TargetOffline(to.to_hex()));
        }
        if inner.forwarding.len() >= self.max_forwardings {
            return Err(NetworkError::RelayFull(format!(
                "at capacity {}",
                self.max_forwardings
            )));
        }
        let id = inner.next_pair_id;
        inner.next_pair_id += 1;
        inner.forwarding.push(ForwardPair {
            id,
            from: *from,
            to: *to,
        });
        Ok(id)
    }

    /// Look up an active forwarding pair by id (for live DATA relay).
    pub async fn lookup_pair(&self, pair_id: u64) -> Option<ForwardPair> {
        self.inner
            .lock()
            .await
            .forwarding
            .iter()
            .find(|p| p.id == pair_id)
            .cloned()
    }

    /// Close a forwarding pair by id; both sides would be notified by
    /// the server layer.
    pub async fn close_pair(&self, pair_id: u64) -> Option<ForwardPair> {
        let mut inner = self.inner.lock().await;
        let pos = inner.forwarding.iter().position(|p| p.id == pair_id)?;
        Some(inner.forwarding.remove(pos))
    }

    pub async fn active_pair_count(&self) -> usize {
        self.inner.lock().await.forwarding.len()
    }

    // ── Inboxes (memory-only, bounded, TTL) ────────────────────────────

    /// Push a frame into `target`'s inbox. Enforces frame size cap, frame
    /// count cap (drop-oldest), and byte cap (drop-oldest). Target must be
    /// registered — the relay only buffers for identities it knows.
    pub async fn inbox_push(
        &self,
        eviction: &EvictionSet,
        from: &Fingerprint,
        target: &Fingerprint,
        frame: Vec<u8>,
    ) -> Result<ForwardOutcome> {
        if eviction.is_evicted(from).await {
            return Err(NetworkError::Evicted(from.to_hex()));
        }
        if frame.len() > self.max_frame_size {
            return Err(NetworkError::Codec(format!(
                "frame {} exceeds relay cap {}",
                frame.len(),
                self.max_frame_size
            )));
        }
        let mut inner = self.inner.lock().await;
        if !inner.online.contains(target) {
            return Ok(ForwardOutcome::TargetOffline);
        }
        let (inbox, byte_count) = inner.inboxes.entry(*target).or_default();
        // Frame cap: drop oldest.
        if inbox.len() >= self.max_inbox_messages {
            if let Some(dropped) = inbox.first().cloned() {
                *byte_count = byte_count.saturating_sub(dropped.bytes.len());
                inbox.remove(0);
            }
        }
        // Byte cap: drop oldest until the new frame fits (or the frame
        // alone exceeds the cap, which the size check above prevents for
        // sane caps; guard anyway).
        while *byte_count + frame.len() > self.max_inbox_bytes && !inbox.is_empty() {
            let dropped = inbox.remove(0);
            *byte_count = byte_count.saturating_sub(dropped.bytes.len());
        }
        if *byte_count + frame.len() > self.max_inbox_bytes {
            return Err(NetworkError::RelayFull(
                "frame exceeds inbox byte cap".into(),
            ));
        }
        *byte_count += frame.len();
        inbox.push(TimestampedFrame {
            bytes: frame,
            enqueued_at: Instant::now(),
        });
        Ok(ForwardOutcome::Buffered)
    }

    /// Drain the target's inbox (read-once). Expired frames are dropped.
    pub async fn inbox_pull(&self, fp: &Fingerprint) -> Vec<Vec<u8>> {
        let mut inner = self.inner.lock().await;
        match inner.inboxes.remove(fp) {
            Some((frames, _)) => {
                let now = Instant::now();
                frames
                    .into_iter()
                    .filter(|f| now.duration_since(f.enqueued_at) < self.inbox_ttl)
                    .map(|f| f.bytes)
                    .collect()
            }
            None => Vec::new(),
        }
    }

    /// Purge expired frames across all inboxes. Returns frames removed.
    pub async fn cleanup_expired(&self) -> usize {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let mut removed = 0;
        for (_fp, (frames, byte_count)) in inner.inboxes.iter_mut() {
            let before = frames.len();
            frames.retain(|f| {
                let keep = now.duration_since(f.enqueued_at) < self.inbox_ttl;
                if !keep {
                    *byte_count = byte_count.saturating_sub(f.bytes.len());
                }
                keep
            });
            removed += before - frames.len();
        }
        inner.inboxes.retain(|_, (frames, _)| !frames.is_empty());
        removed
    }

    /// Inbox occupancy diagnostics (evidence bundle, spec §5.5).
    pub async fn inbox_stats(&self, fp: &Fingerprint) -> (usize, usize) {
        let inner = self.inner.lock().await;
        inner
            .inboxes
            .get(fp)
            .map(|(frames, bytes)| (frames.len(), *bytes))
            .unwrap_or((0, 0))
    }

    // ── Adverts (§5.2: ADVERT_PUBLISH / ADVERT_FETCH) ──────────────────

    /// Publish (replace) the advert for a registered identity.
    pub async fn advert_publish(&self, fp: &Fingerprint, advert: Advert) -> Result<()> {
        let mut inner = self.inner.lock().await;
        if !inner.online.contains(fp) {
            return Err(NetworkError::TargetOffline(fp.to_hex()));
        }
        inner.adverts.insert(*fp, (advert, Instant::now()));
        Ok(())
    }

    /// Fetch an identity's current advert (None if absent/expired).
    pub async fn advert_fetch(&self, fp: &Fingerprint) -> Option<Advert> {
        let mut inner = self.inner.lock().await;
        if let Some((advert, published)) = inner.adverts.get(fp).cloned() {
            let age = Instant::now().duration_since(published);
            if age < Duration::from_secs(advert.ttl_secs) {
                return Some(advert);
            }
            inner.adverts.remove(fp);
        }
        None
    }

    // ── Config accessors ───────────────────────────────────────────────

    pub fn max_forwardings(&self) -> usize {
        self.max_forwardings
    }
    pub fn max_inbox_messages(&self) -> usize {
        self.max_inbox_messages
    }
    pub fn max_inbox_bytes(&self) -> usize {
        self.max_inbox_bytes
    }
    pub fn inbox_ttl_secs(&self) -> u64 {
        self.inbox_ttl.as_secs()
    }
    /// Relay frame size cap (spec §5.3) — the max bytes a single relayed
    /// DATA / inbox frame may carry.
    pub fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }
}

/// Revocation set — checked at session-establish time. Persisted to disk
/// (spec §5.4: a restart must not resurrect revoked peers).
#[derive(Clone)]
pub struct EvictionSet {
    inner: std::sync::Arc<Mutex<HashSet<Fingerprint>>>,
}

impl EvictionSet {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub async fn revoke(&self, fp: &Fingerprint) -> bool {
        self.inner.lock().await.insert(*fp)
    }

    pub async fn is_evicted(&self, fp: &Fingerprint) -> bool {
        self.inner.lock().await.contains(fp)
    }

    pub async fn pardon(&self, fp: &Fingerprint) -> bool {
        self.inner.lock().await.remove(fp)
    }

    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    /// Persist the eviction set (atomic write).
    pub async fn save(&self, path: &Path) -> Result<()> {
        let set = self.inner.lock().await;
        let mut buf = Vec::with_capacity(5 + set.len() * 32);
        buf.extend_from_slice(b"ONEV");
        buf.push(1);
        for fp in set.iter() {
            buf.extend_from_slice(fp.as_bytes());
        }
        drop(set);
        origin_common::atomic_write(path, &buf)
            .map_err(|e| NetworkError::Transport(format!("eviction save: {e}")))?;
        Ok(())
    }

    /// Load the eviction set. Missing file → empty (first run). Corrupt
    /// file → error (never silently drop revocations).
    pub async fn load(path: &Path) -> Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(e) => {
                return Err(NetworkError::Transport(format!("eviction read: {e}")));
            }
        };
        if bytes.len() < 5 || &bytes[..4] != b"ONEV" || bytes[4] != 1 {
            return Err(NetworkError::Transport("bad eviction file".into()));
        }
        let body = &bytes[5..];
        if body.len() % 32 != 0 {
            return Err(NetworkError::Transport("eviction body misaligned".into()));
        }
        let set = Self::new();
        for chunk in body.chunks_exact(32) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(chunk);
            set.inner.lock().await.insert(Fingerprint(arr));
        }
        Ok(set)
    }
}

impl Default for EvictionSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(n: u8) -> Fingerprint {
        Fingerprint([n; 32])
    }

    fn state() -> RelayState {
        RelayState::new(3)
    }

    #[tokio::test]
    async fn register_and_online() {
        let s = state();
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        assert!(s.is_online(&fp(1)).await);
        assert!(!s.is_online(&fp(2)).await);
        assert_eq!(s.online_count().await, 1);
    }

    #[tokio::test]
    async fn evicted_cannot_register() {
        let s = state();
        let ev = EvictionSet::new();
        ev.revoke(&fp(1)).await;
        match s.register(&ev, &fp(1)).await {
            Err(NetworkError::Evicted(_)) => {}
            other => panic!("expected Evicted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deregister_cleans_tokens_and_pairs() {
        let s = state();
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        s.register(&ev, &fp(2)).await.unwrap();
        let tok = s.issue_token(&fp(1)).await;
        s.open_pair(&ev, &fp(1), &fp(2)).await.unwrap();
        assert_eq!(s.active_pair_count().await, 1);

        s.deregister(&fp(1)).await;
        assert!(!s.is_online(&fp(1)).await);
        assert!(s.resolve_token(&tok).await.is_none());
        assert_eq!(s.active_pair_count().await, 0);
    }

    #[tokio::test]
    async fn token_issue_resolve_revoke() {
        let s = state();
        let tok = s.issue_token(&fp(7)).await;
        assert_eq!(s.resolve_token(&tok).await, Some(fp(7)));
        s.revoke_token(&tok).await;
        assert!(s.resolve_token(&tok).await.is_none());
        assert!(s.resolve_token("bogus").await.is_none());
    }

    #[tokio::test]
    async fn token_is_random_per_issue() {
        let s = state();
        let a = s.issue_token(&fp(1)).await;
        let b = s.issue_token(&fp(1)).await;
        assert_ne!(a, b);
        assert_eq!(a.len(), 64); // 32 bytes hex
    }

    #[tokio::test]
    async fn open_pair_requires_both_online() {
        let s = state();
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        match s.open_pair(&ev, &fp(1), &fp(2)).await {
            Err(NetworkError::TargetOffline(_)) => {}
            other => panic!("expected TargetOffline, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn open_pair_capacity_enforced() {
        let s = RelayState::new(2);
        let ev = EvictionSet::new();
        for i in 1..=4 {
            s.register(&ev, &fp(i)).await.unwrap();
        }
        s.open_pair(&ev, &fp(1), &fp(2)).await.unwrap();
        s.open_pair(&ev, &fp(3), &fp(4)).await.unwrap();
        match s.open_pair(&ev, &fp(1), &fp(3)).await {
            Err(NetworkError::RelayFull(_)) => {}
            other => panic!("expected RelayFull, got {other:?}"),
        }
        assert_eq!(s.active_pair_count().await, 2);
    }

    #[tokio::test]
    async fn open_pair_evicted_sender_rejected() {
        let s = state();
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        s.register(&ev, &fp(2)).await.unwrap();
        ev.revoke(&fp(1)).await;
        match s.open_pair(&ev, &fp(1), &fp(2)).await {
            Err(NetworkError::Evicted(_)) => {}
            other => panic!("expected Evicted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn close_pair_removes() {
        let s = state();
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        s.register(&ev, &fp(2)).await.unwrap();
        let id = s.open_pair(&ev, &fp(1), &fp(2)).await.unwrap();
        let closed = s.close_pair(id).await.unwrap();
        assert_eq!(closed.from, fp(1));
        assert_eq!(closed.to, fp(2));
        assert_eq!(s.active_pair_count().await, 0);
        assert!(s.close_pair(id).await.is_none());
        assert!(s.close_pair(999).await.is_none());
    }

    #[tokio::test]
    async fn inbox_push_pull_roundtrip() {
        let s = state();
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        s.register(&ev, &fp(2)).await.unwrap();

        let out = s
            .inbox_push(&ev, &fp(1), &fp(2), b"frame-one".to_vec())
            .await
            .unwrap();
        assert_eq!(out, ForwardOutcome::Buffered);
        s.inbox_push(&ev, &fp(1), &fp(2), b"frame-two".to_vec())
            .await
            .unwrap();

        let frames = s.inbox_pull(&fp(2)).await;
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], b"frame-one");
        assert_eq!(frames[1], b"frame-two");
        // Read-once: second pull is empty.
        assert!(s.inbox_pull(&fp(2)).await.is_empty());
    }

    #[tokio::test]
    async fn inbox_offline_target_rejected() {
        let s = state();
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        let out = s
            .inbox_push(&ev, &fp(1), &fp(9), b"x".to_vec())
            .await
            .unwrap();
        assert_eq!(out, ForwardOutcome::TargetOffline);
    }

    #[tokio::test]
    async fn inbox_frame_cap_drops_oldest() {
        let s = RelayState::with_caps(10, 3, DEFAULT_MAX_INBOX_BYTES, 300);
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        s.register(&ev, &fp(2)).await.unwrap();
        for i in 0..5u8 {
            s.inbox_push(&ev, &fp(1), &fp(2), vec![i]).await.unwrap();
        }
        let frames = s.inbox_pull(&fp(2)).await;
        // Cap 3 → oldest two dropped.
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], vec![2]);
        assert_eq!(frames[2], vec![4]);
    }

    #[tokio::test]
    async fn inbox_byte_cap_drops_oldest() {
        // Byte cap 100: three 50-byte frames → first dropped each time.
        let s = RelayState::with_caps(10, 256, 100, 300);
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        s.register(&ev, &fp(2)).await.unwrap();
        for i in 0..3u8 {
            s.inbox_push(&ev, &fp(1), &fp(2), vec![i; 50])
                .await
                .unwrap();
        }
        let (count, bytes) = s.inbox_stats(&fp(2)).await;
        assert_eq!(count, 2);
        assert_eq!(bytes, 100);
        let frames = s.inbox_pull(&fp(2)).await;
        assert_eq!(frames[0][0], 1); // frame 0 was dropped
    }

    #[tokio::test]
    async fn inbox_frame_size_cap() {
        let s = RelayState::with_caps(10, 256, 10_000, 300);
        let ev = EvictionSet::new();
        s.register(&ev, &fp(2)).await.unwrap();
        let big = vec![0u8; DEFAULT_MAX_FRAME_SIZE + 1];
        match s.inbox_push(&ev, &fp(2), &fp(2), big).await {
            Err(NetworkError::Codec(_)) => {}
            other => panic!("expected Codec error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inbox_evicted_sender_rejected() {
        let s = state();
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        s.register(&ev, &fp(2)).await.unwrap();
        ev.revoke(&fp(1)).await;
        match s.inbox_push(&ev, &fp(1), &fp(2), b"x".to_vec()).await {
            Err(NetworkError::Evicted(_)) => {}
            other => panic!("expected Evicted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inbox_ttl_expiry() {
        let s = RelayState::with_caps(10, 256, DEFAULT_MAX_INBOX_BYTES, 0); // 0s TTL
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        s.register(&ev, &fp(2)).await.unwrap();
        s.inbox_push(&ev, &fp(1), &fp(2), b"gone".to_vec())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(s.inbox_pull(&fp(2)).await.is_empty());
    }

    #[tokio::test]
    async fn cleanup_expired_counts() {
        let s = RelayState::with_caps(10, 256, DEFAULT_MAX_INBOX_BYTES, 0);
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        s.register(&ev, &fp(2)).await.unwrap();
        s.register(&ev, &fp(3)).await.unwrap();
        s.inbox_push(&ev, &fp(1), &fp(2), b"a".to_vec())
            .await
            .unwrap();
        s.inbox_push(&ev, &fp(1), &fp(3), b"b".to_vec())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(s.cleanup_expired().await, 2);
        // Empty entries freed — stats report zero.
        assert_eq!(s.inbox_stats(&fp(2)).await, (0, 0));
    }

    #[tokio::test]
    async fn eviction_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eviction.bin");

        let ev = EvictionSet::new();
        ev.revoke(&fp(1)).await;
        ev.revoke(&fp(2)).await;
        ev.save(&path).await.unwrap();

        let loaded = EvictionSet::load(&path).await.unwrap();
        assert!(loaded.is_evicted(&fp(1)).await);
        assert!(loaded.is_evicted(&fp(2)).await);
        assert!(!loaded.is_evicted(&fp(3)).await);
        assert_eq!(loaded.len().await, 2);
    }

    #[tokio::test]
    async fn eviction_survives_relay_restart_semantics() {
        // The §5.4 invariant: restart must not resurrect revoked peers.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eviction.bin");
        let ev = EvictionSet::new();
        ev.revoke(&fp(9)).await;
        ev.save(&path).await.unwrap();

        // "Restart": fresh state loads persisted eviction.
        let s = state();
        let ev2 = EvictionSet::load(&path).await.unwrap();
        match s.register(&ev2, &fp(9)).await {
            Err(NetworkError::Evicted(_)) => {}
            other => panic!("expected Evicted after restart, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn eviction_load_missing_gives_empty() {
        let dir = tempfile::tempdir().unwrap();
        let ev = EvictionSet::load(&dir.path().join("none.bin"))
            .await
            .unwrap();
        assert!(ev.is_empty().await);
    }

    #[tokio::test]
    async fn eviction_load_corrupt_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.bin");

        std::fs::write(&path, b"junk").unwrap(); // truncated/no magic
        assert!(EvictionSet::load(&path).await.is_err());

        let mut bad_magic = Vec::new();
        bad_magic.extend_from_slice(b"XXXX");
        bad_magic.push(1);
        std::fs::write(&path, &bad_magic).unwrap();
        assert!(EvictionSet::load(&path).await.is_err());

        let mut bad_ver = Vec::new();
        bad_ver.extend_from_slice(b"ONEV");
        bad_ver.push(9);
        std::fs::write(&path, &bad_ver).unwrap();
        assert!(EvictionSet::load(&path).await.is_err());

        // Misaligned body (5 bytes is not a multiple of 32).
        let mut misaligned = Vec::new();
        misaligned.extend_from_slice(b"ONEV");
        misaligned.push(1);
        misaligned.extend_from_slice(&[0u8; 5]);
        std::fs::write(&path, &misaligned).unwrap();
        assert!(EvictionSet::load(&path).await.is_err());
    }

    #[tokio::test]
    async fn advert_publish_fetch_roundtrip() {
        let s = state();
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        let advert = Advert {
            protocol_version: 1,
            endpoints: vec!["192.168.1.5:7331".into()],
            ttl_secs: 300,
            presence: 1,
        };
        s.advert_publish(&fp(1), advert.clone()).await.unwrap();
        assert_eq!(s.advert_fetch(&fp(1)).await, Some(advert));
    }

    #[tokio::test]
    async fn advert_latest_wins() {
        let s = state();
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        let a1 = Advert {
            protocol_version: 1,
            endpoints: vec!["old:1".into()],
            ttl_secs: 300,
            presence: 1,
        };
        let a2 = Advert {
            protocol_version: 1,
            endpoints: vec!["new:2".into()],
            ttl_secs: 300,
            presence: 2,
        };
        s.advert_publish(&fp(1), a1).await.unwrap();
        s.advert_publish(&fp(1), a2.clone()).await.unwrap();
        assert_eq!(s.advert_fetch(&fp(1)).await, Some(a2));
    }

    #[tokio::test]
    async fn advert_expiry() {
        let s = state();
        let ev = EvictionSet::new();
        s.register(&ev, &fp(1)).await.unwrap();
        let expired = Advert {
            protocol_version: 1,
            endpoints: vec![],
            ttl_secs: 0,
            presence: 0,
        };
        s.advert_publish(&fp(1), expired).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(s.advert_fetch(&fp(1)).await, None);
    }

    #[tokio::test]
    async fn advert_requires_registration() {
        let s = state();
        let advert = Advert {
            protocol_version: 1,
            endpoints: vec![],
            ttl_secs: 60,
            presence: 0,
        };
        match s.advert_publish(&fp(5), advert).await {
            Err(NetworkError::TargetOffline(_)) => {}
            other => panic!("expected TargetOffline, got {other:?}"),
        }
        assert_eq!(s.advert_fetch(&fp(5)).await, None);
    }

    #[tokio::test]
    async fn config_accessors() {
        let s = RelayState::with_caps(11, 22, 33, 44);
        assert_eq!(s.max_forwardings(), 11);
        assert_eq!(s.max_inbox_messages(), 22);
        assert_eq!(s.max_inbox_bytes(), 33);
        assert_eq!(s.inbox_ttl_secs(), 44);
    }
}
