// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-network` as a foundational dependency.
//!
//! The universal transport substrate as a library: an in-process
//! `RelayServer` on loopback with two authenticated `RelayClient`s —
//! presence probing, advert publish/fetch, and store-and-forward
//! inbox push/pull. All handshakes are real (Noise IK + identity
//! AUTH claims over the SDK), no external daemon needed.
//!
//! Run with: `cargo run -p origin-network --example dogfood`

use std::sync::Arc;

use origin_network::address::Fingerprint;
use origin_network::client::RelayClient;
use origin_network::identity::PeerKeys;
use origin_network::relay::{EvictionSet, RelayState, DEFAULT_MAX_FORWARDINGS};
use origin_network::relay_server::RelayServer;
use origin_network::session::StaticResolver;
use origin_network::transport::{TcpTransport, Transport, TransportAddr};
use origin_network::wire::Advert;

fn relay_seed() -> [u8; 32] {
    [0xEE; 32]
}
fn alice_seed() -> [u8; 32] {
    [0xA1; 32]
}
fn bob_seed() -> [u8; 32] {
    [0xB2; 32]
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── identity substrate: PeerKeys + fingerprints ──────────────────
    let relay_keys = PeerKeys::from_seed(&relay_seed(), 0).map_err(|e| e.to_string())?;
    let alice_keys = PeerKeys::from_seed(&alice_seed(), 0).map_err(|e| e.to_string())?;
    let bob_keys = PeerKeys::from_seed(&bob_seed(), 0).map_err(|e| e.to_string())?;
    let alice_fp = Fingerprint::from_seed_bytes(&alice_seed());
    let bob_fp = Fingerprint::from_seed_bytes(&bob_seed());
    assert_ne!(alice_fp, bob_fp, "distinct identities");
    assert_eq!(
        PeerKeys::from_seed(&alice_seed(), 0)
            .map_err(|e| e.to_string())?
            .fingerprint(),
        alice_keys.fingerprint()
    );
    println!("✓ PeerKeys / Fingerprint identity substrate");

    // ── in-process relay: StaticResolver allowlist + serve ───────────
    let mut resolver = StaticResolver::new();
    resolver.add(alice_keys);
    resolver.add(bob_keys);
    let server = Arc::new(
        RelayServer::new(
            RelayState::new(DEFAULT_MAX_FORWARDINGS),
            EvictionSet::new(),
            Arc::new(resolver),
            relay_seed(),
        )
        .map_err(|e| e.to_string())?,
    );
    let listener = TcpTransport::listen(([127, 0, 0, 1], 0).into())
        .await
        .map_err(|e| e.to_string())?;
    let addr: TransportAddr = listener
        .local_addr()
        .ok_or("listener has no local address")?;
    let serve = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = serve.serve(listener).await;
    });
    println!("✓ RelayServer bound at {addr:?}");

    // ── authenticated clients ────────────────────────────────────────
    let transport: Arc<dyn Transport> = Arc::new(TcpTransport::connector());
    let alice = RelayClient::connect(alice_seed(), 0, &transport, &addr, &relay_keys)
        .await
        .map_err(|e| e.to_string())?;
    assert!(!alice.session_token().is_empty());
    assert_eq!(
        alice.relay_fingerprint(),
        Fingerprint::from_seed_bytes(&relay_seed())
    );
    println!("✓ alice connected (authenticated, session token issued)");

    // Bob offline → probe false.
    assert!(!alice.probe(&bob_fp).await.map_err(|e| e.to_string())?);

    let bob = RelayClient::connect(bob_seed(), 0, &transport, &addr, &relay_keys)
        .await
        .map_err(|e| e.to_string())?;
    assert!(alice.probe(&bob_fp).await.map_err(|e| e.to_string())?);
    println!("✓ presence probe: offline → online transition");

    // ── advert publish / fetch ───────────────────────────────────────
    bob.advert_publish(Advert {
        protocol_version: 1,
        endpoints: vec!["10.0.0.7:7331".to_string()],
        ttl_secs: 60,
        presence: 1,
    })
    .await
    .map_err(|e| e.to_string())?;
    // Publish and fetch run over separate connections, so poll briefly
    // until bob's advert is visible to alice.
    let mut advert = None;
    for _ in 0..100 {
        if let Some(a) = alice
            .advert_fetch(&bob_fp)
            .await
            .map_err(|e| e.to_string())?
        {
            advert = Some(a);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let advert = advert.ok_or("bob's advert must exist")?;
    assert_eq!(advert.endpoints, vec!["10.0.0.7:7331"]);
    println!(
        "✓ advert publish → fetch (endpoints {})",
        advert.endpoints.join(",")
    );

    // ── store-and-forward inbox (read-once) ──────────────────────────
    alice
        .inbox_push(&bob_fp, b"hello-bob".to_vec())
        .await
        .map_err(|e| e.to_string())?;
    alice
        .inbox_push(&bob_fp, b"second-frame".to_vec())
        .await
        .map_err(|e| e.to_string())?;
    // Delivery is async across connections; pull is read-once, so poll
    // until both frames land (bounded), accumulating drained frames.
    let mut frames = Vec::new();
    for _ in 0..100 {
        let got = bob.inbox_pull().await.map_err(|e| e.to_string())?;
        let had = frames.len();
        frames.extend(got);
        if frames.len() >= 2 {
            break;
        }
        if frames.len() == had {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    assert_eq!(
        frames,
        vec![b"hello-bob".to_vec(), b"second-frame".to_vec()]
    );
    assert!(
        bob.inbox_pull()
            .await
            .map_err(|e| e.to_string())?
            .is_empty(),
        "inbox is read-once"
    );
    println!("✓ relayed inbox push → pull (2 frames, read-once)");

    // ── identity helpers are exported for downstream use ─────────────
    let secret =
        origin_network::derive_transport_secret(&alice_seed(), 0).map_err(|e| e.to_string())?;
    let pk = origin_network::transport_public_key(&secret);
    assert_eq!(pk.len(), 32);
    let _ = alice_fp;
    println!("✓ derive_transport_secret / transport_public_key");

    println!("\norigin-network dogfood OK — usable as a foundational dependency");
    Ok(())
}
