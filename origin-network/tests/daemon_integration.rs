// SPDX-License-Identifier: Apache-2.0

//! Integration test: spawn the standalone `origin-relay` daemon binary and
//! verify the daemon boots, authenticates clients, and serves the full
//! control plane end-to-end via `RelayClient`.
//!
//! This validates the `origin-network/src/bin/relay_main.rs` binary path —
//! the standalone `origin-relay` daemon that operators run directly.
//! The in-process `RelayServer` tests already cover message-level behavior;
//! this test covers the daemon wiring: seed loading, allowlist loading,
//! eviction persistence, and the serve loop.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use origin_network::address::Fingerprint;
use origin_network::client::RelayClient;
use origin_network::identity::PeerKeys;
use origin_network::transport::{TcpTransport, TransportAddr};
use origin_network::wire::Advert;
use origin_network::Transport;

/// Tests spawn the real `origin-relay` daemon on fixed ports, so they must
/// run sequentially. This mutex serializes all tests in this binary.
static DAEMON_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn relay_seed() -> [u8; 32] {
    [0xEE; 32]
}
fn alice_seed() -> [u8; 32] {
    [0xAA; 32]
}
fn bob_seed() -> [u8; 32] {
    [0xBB; 32]
}

/// Write a JSONL allowlist containing the given PeerKeys records.
fn write_allowlist(path: &PathBuf, seeds: &[[u8; 32]]) {
    let mut lines = Vec::new();
    for s in seeds {
        let pk = PeerKeys::from_seed(s, 0).unwrap();
        lines.push(serde_json::to_string(&pk).unwrap());
    }
    std::fs::write(path, lines.join("\n") + "\n").unwrap();
}

/// Write the binary eviction file format (ONEV v1: magic + version + 32-byte fps).
fn write_eviction(path: &PathBuf, fps: &[Fingerprint]) {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"ONEV");
    buf.push(1);
    for fp in fps {
        buf.extend_from_slice(fp.as_bytes());
    }
    std::fs::write(path, &buf).unwrap();
}

/// Spawn the standalone origin-relay binary on the given address.
/// Sets up the home directory (including seed) but does NOT spawn the daemon
/// until after `post_setup` callback runs. This allows callers to pre-write
/// eviction files etc. before the daemon starts.
fn spawn_relay<F>(home: &PathBuf, allowlist: Option<&PathBuf>, port: u16, post_setup: F) -> (SocketAddr, Child)
where
    F: FnOnce(&PathBuf),
{
    let bin = env!("CARGO_BIN_EXE_origin-relay");
    let addr = format!("127.0.0.1:{port}");

    let _ = std::fs::remove_dir_all(home);
    std::fs::create_dir_all(home).unwrap();
    std::fs::write(home.join("relay.seed"), relay_seed()).unwrap();

    // Caller can pre-write eviction files etc. BEFORE the daemon starts.
    post_setup(home);

    let mut cmd = Command::new(bin);
    cmd.args([
        "serve",
        "--listen",
        &addr,
        "--home",
        home.to_str().unwrap(),
        "--no-sandbox",
    ]);
    if let Some(al) = allowlist {
        cmd.args(["--allowlist", al.to_str().unwrap()]);
    }
    let child = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn origin-relay");

    std::thread::sleep(Duration::from_millis(500));

    let socket_addr: SocketAddr = addr.parse().unwrap();
    (socket_addr, child)
}

fn kill_relay(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Connect a relay client — returns Result so callers can inspect errors.
async fn connect_client(addr: SocketAddr, seed: [u8; 32]) -> Result<RelayClient, String> {
    let relay_keys = PeerKeys::from_seed(&relay_seed(), 0).unwrap();
    let transport: std::sync::Arc<dyn Transport> = std::sync::Arc::new(TcpTransport::connector());
    let taddr = TransportAddr::Tcp(addr);
    RelayClient::connect(seed, 0, &transport, &taddr, &relay_keys).await.map_err(|e| e.to_string())
}

#[tokio::test]
async fn daemon_authenticates_and_serves_probe_advert_inbox() {
    let _guard = DAEMON_GUARD.lock().unwrap();
    let home = std::env::temp_dir().join("origin-relay-itest-probe");
    let allowlist = home.parent().unwrap().join("allowlist_probe.jsonl");
    write_allowlist(&allowlist, &[alice_seed(), bob_seed()]);
    let (addr, child) = spawn_relay(&home, Some(&allowlist), 17341, |_h| {});

    let alice = connect_client(addr, alice_seed()).await.unwrap();
    assert!(!alice.session_token().is_empty());

    let bob_fp = Fingerprint::from_seed_bytes(&bob_seed());

    // Bob offline — probe reports offline.
    assert!(!alice.probe(&bob_fp).await.unwrap());

    // Bob connects (separate client).
    let bob = connect_client(addr, bob_seed()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Now Bob should be online.
    assert!(alice.probe(&bob_fp).await.unwrap());

    // Bob publishes an advert.
    bob.advert_publish(Advert {
        protocol_version: 1,
        endpoints: vec!["10.0.0.5:7331".into()],
        ttl_secs: 60,
        presence: 1,
    })
    .await
    .unwrap();

    // Alice fetches Bob's advert.
    let advert = alice.advert_fetch(&bob_fp).await.unwrap().unwrap();
    assert_eq!(advert.endpoints, vec!["10.0.0.5:7331".to_string()]);

    // Alice pushes to Bob's inbox.
    alice
        .inbox_push(&bob_fp, b"relayed-hello".to_vec())
        .await
        .unwrap();

    // Bob pulls his inbox.
    let frames = bob.inbox_pull().await.unwrap();
    assert_eq!(frames, vec![b"relayed-hello".to_vec()]);
    // Read-once.
    assert!(bob.inbox_pull().await.unwrap().is_empty());

    kill_relay(child);
}

#[tokio::test]
async fn daemon_rejects_unknown_peer() {
    let _guard = DAEMON_GUARD.lock().unwrap();
    let home = std::env::temp_dir().join("origin-relay-itest-unknown");
    let allowlist = home.parent().unwrap().join("allowlist_unknown.jsonl");
    write_allowlist(&allowlist, &[]);
    let (addr, child) = spawn_relay(&home, Some(&allowlist), 17342, |_h| {});

    // Alice tries to connect but isn't in the allowlist.
    let result = connect_client(addr, alice_seed()).await;
    kill_relay(child);

    assert!(result.is_err(), "client with no PeerKeys record should be rejected");
    let err = result.unwrap_err();
    assert!(err.contains("unknown peer"), "expected 'unknown peer' error, got: {err}");
}

#[tokio::test]
async fn daemon_eviction_prevents_registration() {
    let _guard = DAEMON_GUARD.lock().unwrap();
    let home = std::env::temp_dir().join("origin-relay-itest-evict");
    let allowlist = home.parent().unwrap().join("allowlist_evict.jsonl");
    write_allowlist(&allowlist, &[alice_seed(), bob_seed()]);

    // Pre-write the eviction file with Bob's fingerprint BEFORE the daemon starts.
    let bob_fp = Fingerprint::from_seed_bytes(&bob_seed());
    let (addr, child) = spawn_relay(&home, Some(&allowlist), 17343, |h| {
        write_eviction(&h.join("eviction.bin"), &[bob_fp]);
    });

    // Alice should connect fine (allowlist has her, not evicted).
    let alice = connect_client(addr, alice_seed()).await.unwrap();
    assert!(!alice.session_token().is_empty());

    // Bob should be rejected (evicted).
    let result = connect_client(addr, bob_seed()).await;
    kill_relay(child);

    assert!(result.is_err(), "evicted peer should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("evicted"), "expected 'evicted' error, got: {err}");
}

#[tokio::test]
async fn daemon_status_command_works() {
    let _guard = DAEMON_GUARD.lock().unwrap();
    let home = std::env::temp_dir().join("origin-relay-itest-status");
    let allowlist = home.parent().unwrap().join("allowlist_status.jsonl");
    write_allowlist(&allowlist, &[alice_seed()]);
    let (addr, child) = spawn_relay(&home, Some(&allowlist), 17344, |_h| {});

    let bin = env!("CARGO_BIN_EXE_origin-relay");
    let output = Command::new(bin)
        .args(["status", "--home", home.to_str().unwrap()])
        .output()
        .expect("run origin-relay status");

    kill_relay(child);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("eviction set"), "status output should mention eviction set: {stdout}");
    assert!(stdout.contains("0 entries"), "should start with 0 revoked entries: {stdout}");
    let _ = addr;
}
