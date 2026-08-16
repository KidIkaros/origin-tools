// SPDX-License-Identifier: Apache-2.0

//! The two-process relayed-pay end-to-end test (A→relay→C):
//!
//! - **Process 1** — the real `origin-wallet relay serve` CLI binary,
//!   spawned as a child process (a wallet-derived node serving circuits).
//! - **Process 2** — this test: the payee's node + the payer's wallet.
//!   The payer connects ONLY to the relay's address (never dials the
//!   payee), and the payee's node ingests the receipt via gossip fanout
//!   to the relay + registry sync (§6.2).
//!
//! This proves the *CLI surface* works across a process boundary — the
//! relay the wallet pays through is a real running binary, not an
//! in-process mesh.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use origin_wallet::network::{pay_native_via_relay, settle_channel_with};
use origin_wallet::Wallet;

/// A free port on loopback: bind a temp socket, note its port, drop it.
/// (A tiny race window before the relay binds it, acceptable in tests.)
fn free_port() -> u16 {
    let s = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let port = s.local_addr().expect("probe addr").port();
    drop(s);
    port
}

/// Spawn the real relay CLI binary as a child process on a *known*
/// address (pinned via `--addr`, so no stdout parsing). The relay's
/// MeshId is derived from the relay wallet's seed — the same identity
/// the wallet library computes — so the caller already knows it.
fn spawn_relay_cli(relay_wallet: &str, passphrase: &str) -> (Child, stoa::MeshId, std::net::SocketAddr) {
    let bin = env!("CARGO_BIN_EXE_origin-wallet");
    let relay_addr: std::net::SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();

    let child = Command::new(bin)
        .args([
            "relay",
            "serve",
            "--file",
            relay_wallet,
            "--difficulty",
            "8",
            "--stun-server",
            "stun.l.google.com:19302",
            "--addr",
            &relay_addr.to_string(),
            "--passphrase",
            passphrase,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn relay CLI");

    // The relay MeshId is seed-derived: the wallet library computes the
    // same identity the CLI serves under.
    let relay_wallet = Wallet::open(std::path::Path::new(relay_wallet), passphrase)
        .expect("open relay wallet");
    let relay_id = *relay_wallet.stoa_node_keys().expect("node keys").mesh_id();

    // Give the child a moment to bind before the test dials it.
    std::thread::sleep(Duration::from_millis(1500));
    (child, relay_id, relay_addr)
}

fn kill(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn e2e_relayed_pay_across_the_cli_relay_process() {
    // Isolate STOA_HOME so the relay's persisted state (and the wallets'
    // stores) don't collide with other tests.
    let dir = std::env::temp_dir().join(format!("e2e-relay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("STOA_HOME", dir.join("stoa"));

    let relay_wallet = dir.join("relay.dat");
    let payee_wallet = dir.join("payee.dat");
    let payer_wallet = dir.join("payer.dat");
    for w in [&relay_wallet, &payee_wallet, &payer_wallet] {
        Wallet::create("e2e-pass").expect("create").save(w, "e2e-pass").expect("save");
    }

    // Process 1: the real relay CLI binary.
    let (relay_child, relay_id, relay_addr) = spawn_relay_cli(
        relay_wallet.to_str().unwrap(),
        "e2e-pass",
    );

    // Process 2 (this test): the payee's node + the payer's wallet.
    let payee = Wallet::open(&payee_wallet, "e2e-pass").expect("open payee");
    let payee_keys = payee.stoa_node_keys().unwrap();
    let payee_id = *payee_keys.mesh_id();
    let (payee_mesh, _) = stoa::Mesh::bind(payee_keys, "127.0.0.1:0".parse().unwrap()).unwrap();
    // The payee hops to the relay so it has a route and syncs with it.
    payee_mesh.connect(relay_id, relay_addr).await.expect("payee → relay");

    let mut payer = Wallet::open(&payer_wallet, "e2e-pass").expect("open payer");
    let entry = pay_native_via_relay(
        &mut payer,
        payee_id,
        relay_id,
        relay_addr,
        999,
        b"two-process relayed pay".to_vec(),
    )
    .await
    .expect("relayed pay through the CLI relay process");

    assert_eq!(entry.amount, 999);
    assert_eq!(entry.counterparty, payee_id);
    assert_eq!(payer.transaction_count(), 1);

    // The payee ingests the receipt: gossip fanout to the relay + the
    // payee's registry sync (driven here like the wallet's periodic
    // re-sync — the same path the standing network uses).
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let _ = payee_mesh.sync_registries().await;
            if payee_mesh
                .ledger_snapshot()
                .await
                .iter()
                .any(|e| e.amount == 999)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("payee never ingested the relayed receipt");
    assert!(
        payee_mesh.ledger_snapshot().await.iter().any(|e| e.amount == 999),
        "the payee's ledger holds the receipt paid through the CLI relay"
    );

    payee_mesh.shutdown().await.expect("payee shutdown");
    kill(relay_child);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Run the real `origin-wallet network sync` CLI binary as a child
/// process and return (exit status, captured stdout).
fn run_network_sync_cli(
    wallet: &str,
    passphrase: &str,
    peer: stoa::MeshId,
    peer_addr: std::net::SocketAddr,
) -> (bool, String) {
    let bin = env!("CARGO_BIN_EXE_origin-wallet");
    let out = Command::new(bin)
        .args([
            "network",
            "sync",
            "--file",
            wallet,
            "--passphrase",
            passphrase,
            "--peer",
            &peer.to_string(),
            "--peer-addr",
            &peer_addr.to_string(),
        ])
        .output()
        .expect("spawn network sync CLI");
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse the CLI summary's `ledger : N entries` line.
fn ledger_count(stdout: &str) -> Option<usize> {
    stdout.lines().find_map(|l| {
        let l = l.trim();
        l.strip_prefix("ledger").and_then(|_| {
            let digits: String = l.chars().filter(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        })
    })
}

#[tokio::test]
async fn e2e_relayed_pay_pulled_on_demand_by_network_sync_cli() {
    // The standing-network story the `network sync` command was built for:
    // the payee has NO node running while the payment happens. The payer
    // pays through the relay; the receipt sits on the mesh (at the relay)
    // until the payee comes online and runs the real `network sync` CLI to
    // pull it on demand — instead of waiting for the 60 s periodic cadence.
    let dir = std::env::temp_dir().join(format!("e2e-relay-sync-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("STOA_HOME", dir.join("stoa"));

    let relay_wallet = dir.join("relay.dat");
    let payee_wallet = dir.join("payee.dat");
    let payer_wallet = dir.join("payer.dat");
    for w in [&relay_wallet, &payee_wallet, &payer_wallet] {
        Wallet::create("e2e-pass").expect("create").save(w, "e2e-pass").expect("save");
    }

    // Process 1: the real relay CLI binary.
    let (relay_child, relay_id, relay_addr) = spawn_relay_cli(
        relay_wallet.to_str().unwrap(),
        "e2e-pass",
    );

    // The payer pays the payee through the relay. The payee's node is
    // never bound in this test — its wallet file is all that exists.
    let payee = Wallet::open(&payee_wallet, "e2e-pass").expect("open payee");
    let payee_id = *payee.stoa_node_keys().unwrap().mesh_id();
    let mut payer = Wallet::open(&payer_wallet, "e2e-pass").expect("open payer");
    let entry = pay_native_via_relay(
        &mut payer,
        payee_id,
        relay_id,
        relay_addr,
        999,
        b"on-demand sync pull".to_vec(),
    )
    .await
    .expect("relayed pay");
    assert_eq!(entry.amount, 999);

    // Prove the receipt is ON the mesh (at the relay) before the payee
    // pulls: a throwaway probe node connects to the relay and syncs until
    // it sees the 999 entry. The payee still has no node.
    {
        let probe_keys = stoa::NodeKeys::generate().unwrap();
        let (probe, _) = stoa::Mesh::bind(probe_keys, "127.0.0.1:0".parse().unwrap()).unwrap();
        probe.connect(relay_id, relay_addr).await.expect("probe → relay");
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let _ = probe.sync_registries().await;
                if probe
                    .ledger_snapshot()
                    .await
                    .iter()
                    .any(|e| e.amount == 999)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the receipt never reached the relay (nothing to pull)");
        probe.shutdown().await.expect("probe shutdown");
    }

    // Process 2 — the payee comes online ON DEMAND: run the real
    // `network sync` CLI against the relay and assert it pulled the
    // receipt that was sitting on the mesh.
    let (ok, stdout) = run_network_sync_cli(
        payee_wallet.to_str().unwrap(),
        "e2e-pass",
        relay_id,
        relay_addr,
    );
    assert!(ok, "network sync CLI must exit 0\n--- stdout ---\n{stdout}");
    assert!(
        stdout.contains("Registry checkpoint pulled"),
        "CLI must report the pull\n--- stdout ---\n{stdout}"
    );
    let count = ledger_count(&stdout).expect("CLI must print a ledger count");
    assert!(
        count >= 1,
        "the payee's on-demand sync must pull the relayed receipt (ledger={count})\n--- stdout ---\n{stdout}"
    );

    kill(relay_child);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn e2e_relayed_pay_then_settle_through_the_cli_relay() {
    // The full lifecycle across the CLI relay: pay through it, then settle
    // the channel (SPEC §10.3 time-boxed finality) — the operator's
    // `settle` command's underlying path.
    let dir = std::env::temp_dir().join(format!("e2e-relay-settle-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("STOA_HOME", dir.join("stoa"));

    let relay_wallet = dir.join("relay.dat");
    let payee_wallet = dir.join("payee.dat");
    let payer_wallet = dir.join("payer.dat");
    for w in [&relay_wallet, &payee_wallet, &payer_wallet] {
        Wallet::create("e2e-pass").expect("create").save(w, "e2e-pass").expect("save");
    }

    let (relay_child, relay_id, relay_addr) = spawn_relay_cli(
        relay_wallet.to_str().unwrap(),
        "e2e-pass",
    );

    let payee = Wallet::open(&payee_wallet, "e2e-pass").expect("open payee");
    let payee_keys = payee.stoa_node_keys().unwrap();
    let payee_id = *payee_keys.mesh_id();
    let (payee_mesh, _) = stoa::Mesh::bind(payee_keys, "127.0.0.1:0".parse().unwrap()).unwrap();
    payee_mesh.connect(relay_id, relay_addr).await.expect("payee → relay");

    let mut payer = Wallet::open(&payer_wallet, "e2e-pass").expect("open payer");
    let entry = pay_native_via_relay(
        &mut payer,
        payee_id,
        relay_id,
        relay_addr,
        500,
        b"settle e2e".to_vec(),
    )
    .await
    .expect("relayed pay");
    assert_eq!(entry.amount, 500);

    // The payer settles the channel toward the payee (the CLI `settle`
    // path): the ENTRY_SETTLE records the 500 paid out.
    let settle = settle_channel_with(&payer, payee_id, None).await.expect("settle");
    assert_eq!(settle.amount, 500);
    assert_eq!(settle.counterparty, payee_id);

    // Time-boxed finality: not final at settlement time, final after the
    // dispute window (SPEC §10.3).
    let view = {
        let keys = payer.stoa_node_keys().unwrap();
        let (mesh, _) = stoa::Mesh::bind(keys, "127.0.0.1:0".parse().unwrap()).unwrap();
        let v = mesh.channel_state(payee_id).await.expect("channel view");
        mesh.shutdown().await.expect("shutdown");
        v
    };
    assert_eq!(
        view.state,
        stoa::channel::ChannelState::Settled { total: 500, ts: settle.ts }
    );
    assert!(!view.final_at(settle.ts), "not final at settlement time");
    assert!(
        view.final_at(settle.ts + stoa::DISPUTE_WINDOW_SECS),
        "final after the dispute window"
    );

    payee_mesh.shutdown().await.expect("payee shutdown");
    kill(relay_child);
    let _ = std::fs::remove_dir_all(&dir);
}
