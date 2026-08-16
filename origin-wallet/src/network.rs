// SPDX-License-Identifier: Apache-2.0

//! Wallet-side Stoa network operations (INTEGRATION.md §4).
//!
//! The wallet embeds Stoa as a library: these functions bind the node
//! derived from the wallet seed (`Wallet::stoa_node_keys`), drive the mesh
//! APIs, and fold the results into the wallet's own records (MMR history).
//! There is no separate daemon or RPC boundary — the node lives for the
//! duration of the call and drops when it returns.

use std::net::SocketAddr;

use sha2::{Digest, Sha256};

use crate::address::{Address, AddressType, Network};
use crate::error::{Result, WalletError};
use crate::transaction::Transaction;
use crate::Wallet;

/// Pay `to` on the native rail (INTEGRATION.md build-order step 3): bind
/// this wallet's Stoa node, connect to the counterparty's node, open a
/// credit line, stream the payment, and record a `Transaction` in the
/// wallet's MMR history. Returns the signed ledger entry (the receipt
/// evidence).
///
/// The wallet's own history is the human-facing record; the ledger entry is
/// the verifiable evidence — the same evidence a settle would present.
pub async fn pay_native(
    wallet: &mut Wallet,
    to: stoa::MeshId,
    peer_addr: SocketAddr,
    amount: u64,
    memo: Vec<u8>,
) -> Result<stoa::ledger::LedgerEntry> {
    let node_keys = wallet.stoa_node_keys()?;
    let bind_addr = "0.0.0.0:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| WalletError::Network(e.to_string()))?;
    let (mesh, _) = stoa::Mesh::bind(node_keys.clone(), bind_addr)?;

    // Connect to the counterparty's node, open a credit line that covers
    // the payment, and stream it.
    mesh.connect(to, peer_addr).await.map_err(|e| {
        WalletError::Transaction(format!("connect to {to} at {peer_addr} failed: {e}"))
    })?;
    mesh.open_channel(to, amount.max(1), memo.clone()).await.map_err(|e| {
        WalletError::Transaction(format!("open channel to {to} failed: {e}"))
    })?;
    let entry = mesh.stream_payment(to, amount, memo).await.map_err(|e| {
        WalletError::Transaction(format!("stream payment to {to} failed: {e}"))
    })?;

    // Record the payment in the wallet's MMR history (INTEGRATION.md §4).
    // The sender address is derived from the wallet's node identity; the
    // recipient address is a deterministic hash of the counterparty MeshId.
    let sender = Address::from_ed25519(
        &ed25519_dalek::VerifyingKey::from_bytes(&node_keys.public_keys().0)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?,
        AddressType::Bech32,
        Network::Mainnet,
    );
    let digest = Sha256::digest(to.as_bytes());
    let mut to_hash = [0u8; 20];
    to_hash.copy_from_slice(&digest[..20]);
    let recipient = Address::from_hash(to_hash, AddressType::Bech32, Network::Mainnet);

    let tx = Transaction::new(&sender, &recipient, amount, 0, wallet.transaction_count());
    wallet.add_transaction(&tx)?;

    // Graceful shutdown: the receipt's gossip to the counterparty is
    // written before `stream_payment` returns, but a dropped Mesh can
    // lose in-flight bytes — shutdown flushes them so the payee's ledger
    // actually ingests the entry.
    let _ = mesh.shutdown().await;
    Ok(entry)
}

/// Pay `to` on the native rail **through a relay** (the A→relay→C
/// dogfood): bind this wallet's Stoa node, connect only to the relay,
/// open a credit line to the counterparty, and stream the payment —
/// never dialing the counterparty directly.
///
/// Delivery rides the mesh, not a direct link: the ledger entries gossip
/// to the relay (fanout), and the counterparty's node ingests them via
/// registry sync (§6.2 — the on-connect hello + periodic checkpoint
/// exchange, default 60 s). This is the standing-network shape: the
/// payee doesn't need to be dialable by the payer, just connected to the
/// mesh.
pub async fn pay_native_via_relay(
    wallet: &mut Wallet,
    to: stoa::MeshId,
    relay: stoa::MeshId,
    relay_addr: SocketAddr,
    amount: u64,
    memo: Vec<u8>,
) -> Result<stoa::ledger::LedgerEntry> {
    let node_keys = wallet.stoa_node_keys()?;
    let bind_addr = "0.0.0.0:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| WalletError::Network(e.to_string()))?;
    let (mesh, _) = stoa::Mesh::bind(node_keys.clone(), bind_addr)?;

    // Connect only to the relay — the payer never dials the counterparty.
    mesh.connect(relay, relay_addr).await.map_err(|e| {
        WalletError::Transaction(format!("connect to relay {relay} at {relay_addr} failed: {e}"))
    })?;
    mesh.open_channel(to, amount.max(1), memo.clone()).await.map_err(|e| {
        WalletError::Transaction(format!("open channel to {to} failed: {e}"))
    })?;
    let entry = mesh.stream_payment(to, amount, memo).await.map_err(|e| {
        WalletError::Transaction(format!("stream payment to {to} failed: {e}"))
    })?;

    // Record the payment in the wallet's MMR history — same evidence
    // recording as the direct path.
    let sender = Address::from_ed25519(
        &ed25519_dalek::VerifyingKey::from_bytes(&node_keys.public_keys().0)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?,
        AddressType::Bech32,
        Network::Mainnet,
    );
    let digest = Sha256::digest(to.as_bytes());
    let mut to_hash = [0u8; 20];
    to_hash.copy_from_slice(&digest[..20]);
    let recipient = Address::from_hash(to_hash, AddressType::Bech32, Network::Mainnet);

    let tx = Transaction::new(&sender, &recipient, amount, 0, wallet.transaction_count());
    wallet.add_transaction(&tx)?;

    let _ = mesh.shutdown().await;
    Ok(entry)
}

/// Discover services for a query (INTEGRATION.md step 4): bind this
/// wallet's node (identity from the wallet seed), optionally dial a peer
/// first so DHT lookups can reach it, then rank known services. `room` +
/// `point` narrow discovery to a rendezvous room's members.
///
/// Returns the ranked hits (`service`, `payment`, `profile`, `cosine`,
/// `trust`); the wallet renders the brief — never the raw graph.
pub async fn discover_with(
    wallet: &Wallet,
    query: &str,
    room: Option<String>,
    point: Option<stoa::MeshId>,
    peer_addr: Option<SocketAddr>,
) -> Result<Vec<stoa::RankedService>> {
    let node_keys = wallet.stoa_node_keys()?;
    let bind_addr = "0.0.0.0:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| WalletError::Network(e.to_string()))?;
    let (mesh, _) = stoa::Mesh::bind(node_keys, bind_addr)?;

    if let (Some(addr), Some(peer)) = (peer_addr, point) {
        let _ = mesh.connect(peer, addr).await; // best-effort: discovery still works locally
    }

    match (room, point) {
        (Some(room), Some(point)) => Ok(mesh.discover_in_room(point, &room, query).await),
        _ => Ok(mesh.discover(query).await),
    }
}

/// Dial a peer and send it a mail message (INTEGRATION.md step 4 — the
/// point-to-point rail for anything beyond payments): bind, connect,
/// `send_mail`, and return the signed envelope.
pub async fn send_mail(
    to: stoa::MeshId,
    peer_addr: SocketAddr,
    body: Vec<u8>,
) -> Result<stoa::mail::MailEnvelope> {
    let keys = stoa::NodeKeys::generate()
        .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
    let bind_addr = "0.0.0.0:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| WalletError::Network(e.to_string()))?;
    let (mesh, _) = stoa::Mesh::bind(keys, bind_addr)?;
    mesh.connect(to, peer_addr)
        .await
        .map_err(|e| WalletError::Network(format!("connect to {to} at {peer_addr} failed: {e}")))?;
    // The sender announces its identity AFTER connecting, so the gossip
    // reaches the recipient (a pre-connect publish has no peers to reach)
    // — the recipient's poll loop discovers senders from the identities
    // registry (mail is pull). The recipient must publish its own
    // identity to receive.
    let _ = mesh.publish_identity(b"capability:mail".to_vec()).await;

    // Mail encrypts to the recipient's KEM key, which arrives via the
    // on-connect registry sync — an async round trip. Wait for the
    // identity record to land before encrypting (bounded: 10 s).
    mesh.sync_registries()
        .await
        .map_err(|e| WalletError::Network(format!("sync with {to} failed: {e}")))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let known = mesh
            .identity(to)
            .await
            .map_err(|e| WalletError::Network(format!("identity lookup failed: {e}")))?
            .is_some();
        if known {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err(WalletError::Network(format!(
                "timed out waiting for {to}'s identity record (no KEM key to encrypt to)"
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let result = mesh
        .send_mail(to, body)
        .await
        .map_err(|e| WalletError::Network(format!("send_mail to {to} failed: {e}")));
    // Graceful shutdown: the envelope's DHT replication is written before
    // `send_mail` returns, but a dropped Mesh can still lose in-flight
    // bytes to the recipient — shutdown flushes them (the recipient's
    // poll loop then finds the envelope).
    let _ = mesh.shutdown().await;
    result
}

/// `mail inbox` — bind this wallet's node (same seed → same store root, so
/// the persisted deduped mailbox reloads from disk) and return the
/// decrypted inbox. This is the receive side of the mail contract
/// (INTEGRATION.md §5a): envelopes are delivered to the mesh (DHT + store)
/// and land here when this node has been running to ingest them — or when
/// a later bind syncs the registry. Sorted by `(sender, seq)`.
pub async fn mail_inbox(wallet: &Wallet) -> Result<Vec<stoa::mail::MailPayload>> {
    let node_keys = wallet.stoa_node_keys()?;
    let bind_addr = "0.0.0.0:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| WalletError::Network(e.to_string()))?;
    let (mesh, _) = stoa::Mesh::bind(node_keys, bind_addr)?;
    Ok(mesh.mailbox().await)
}

/// The private chat topic for `peer` — a per-recipient addressed topic
/// (INTEGRATION.md §4, the dial-based chat rail). Real-time pubsub, not
/// store-and-forward: the recipient subscribes when listening, so a
/// message published by a directly-connected peer is delivered over the
/// mesh link immediately; an indirect (relayed) peer still reaches it
/// through mesh gossip.
pub fn chat_topic(peer: stoa::MeshId) -> String {
    format!("stoa:chat:{peer}")
}

/// Save the top-ranked discovery hit into the wallet's contacts table
/// under `label` (INTEGRATION.md §5 — a discovered provider becomes a
/// contact in one step). No-op when `hits` is empty.
pub fn save_top_contact(
    wallet_path: &std::path::Path,
    hits: &[stoa::RankedService],
    label: &str,
) -> Result<()> {
    let Some(top) = hits.first() else {
        return Ok(());
    };
    let mut contacts = crate::Contacts::load(wallet_path)?;
    contacts.add(label, &top.service.to_string())
}

/// Send store-and-forward mail over an already-bound mesh (the REPL's
/// fallback rail, INTEGRATION.md §5a): sync registries with the connected
/// peers, wait (bounded) for the recipient's identity record — the sender
/// needs their KEM key to encrypt — then send. The recipient must have
/// published its identity and must poll its mailbox; mail is delivery
/// without a live session, unlike chat.
pub async fn mail_on(
    mesh: &stoa::Mesh,
    to: stoa::MeshId,
    body: Vec<u8>,
) -> Result<stoa::mail::MailEnvelope> {
    // Same announce-before-send as [`send_mail`]: the recipient's poll
    // loop discovers senders from the identities registry.
    let _ = mesh.publish_identity(b"capability:mail".to_vec()).await;
    mesh.sync_registries()
        .await
        .map_err(|e| WalletError::Network(format!("sync with {to} failed: {e}")))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let known = mesh
            .identity(to)
            .await
            .map_err(|e| WalletError::Network(format!("identity lookup failed: {e}")))?
            .is_some();
        if known {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err(WalletError::Network(format!(
                "timed out waiting for {to}'s identity record (no KEM key to encrypt to — has the recipient published its identity?)"
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // The caller owns `mesh` — no shutdown here (the REPL's mail
    // fallback keeps its node alive for the rest of the session).
    mesh.send_mail(to, body)
        .await
        .map_err(|e| WalletError::Network(format!("send_mail to {to} failed: {e}")))
}

/// The outcome of one chat send: which tier carried it and the reply (if
/// any was awaited).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatOutcome {
    /// `relayed` (L3 session pipe through a relay), `direct` (mesh link /
    /// addressed topic), or `direct-upgraded` (relayed session moved onto
    /// a direct leg, RELAY.md §5.3).
    pub tier: &'static str,
    /// The peer's reply, when `wait_reply` was set.
    pub reply: Option<Vec<u8>>,
}

/// The dial-based chat rail (INTEGRATION.md §4): open a session to the
/// peer — a relayed L3 pipe (via `--relay`, or `dial_any`'s automatic
/// punch→relay fallback, upgraded to direct when possible) — or, when the
/// peer is directly reachable with no circuit in play, deliver over the
/// addressed chat topic on the live mesh link. Real-time either way;
/// never a DHT mailbox. `wait_reply` awaits one frame on the session pipe
/// (relayed tier only).
/// The core chat send against an already-bound mesh: the session pipe
/// (named relay, or `dial_any`'s automatic punch→relay fallback, upgraded
/// to direct when possible) or, when the peer is directly reachable with
/// no circuit in play, the addressed topic on the live mesh link.
/// Real-time either way; never a DHT mailbox. Shared by [`chat_send`]
/// (bind-per-call) and the REPL (one long-lived node).
async fn chat_send_on(
    mesh: &stoa::Mesh,
    to: stoa::MeshId,
    relay: Option<(stoa::MeshId, SocketAddr)>,
    body: Vec<u8>,
    wait_reply: bool,
) -> Result<ChatOutcome> {
    // 1. The session pipe: named relay, or dial_any's automatic chain.
    let session = match relay {
        Some((relay_id, relay_addr)) => Some(
            mesh.dial_relayed(relay_id, relay_addr, to)
                .await
                .map_err(|e| {
                    WalletError::Network(format!("relayed dial to {to} failed: {e}"))
                })?,
        ),
        None => match mesh.dial_any(to).await {
            Ok(stoa::DialResult::Relayed(sess)) => Some(sess),
            Ok(stoa::DialResult::Direct(_)) => None,
            Err(_) => None, // no route — fall through to the topic on the mesh link
        },
    };

    if let Some(mut sess) = session {
        // Best-effort: move the circuit onto a direct leg when the relay
        // introduced the peer (RELAY.md §5.3). Failure just means the
        // chat stays relayed.
        let relay = sess.relay();
        let _ = mesh.upgrade_to_direct(relay, sess.circuit_id()).await;
        let tier = if sess.is_upgraded().await.unwrap_or(false) {
            "direct-upgraded"
        } else {
            "relayed"
        };
        sess.send(&body).await.map_err(|e| {
            WalletError::Network(format!("chat send over session failed: {e}"))
        })?;
        let reply = if wait_reply {
            tokio::time::timeout(std::time::Duration::from_secs(30), sess.receiver().recv())
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        return Ok(ChatOutcome { tier, reply });
    }

    // 2. Direct tier: no circuit in play — deliver over the addressed
    //    topic on the live mesh link (the recipient's `chat listen`).
    mesh.publish(&chat_topic(to), body).await.map_err(|e| {
        WalletError::Network(format!("chat publish to {to} failed: {e}"))
    })?;
    Ok(ChatOutcome {
        tier: "direct",
        reply: None,
    })
}

/// The dial-based chat rail (INTEGRATION.md §4): bind a node, open a
/// session to the peer — a relayed L3 pipe (via `--relay`, or `dial_any`'s
/// automatic punch→relay fallback, upgraded to direct when possible) — or,
/// when the peer is directly reachable with no circuit in play, deliver
/// over the addressed chat topic on the live mesh link.
pub async fn chat_send(
    wallet: &Wallet,
    to: stoa::MeshId,
    peer_addr: Option<SocketAddr>,
    relay: Option<(stoa::MeshId, SocketAddr)>,
    body: Vec<u8>,
    wait_reply: bool,
) -> Result<ChatOutcome> {
    let node_keys = wallet.stoa_node_keys()?;
    let bind_addr = "127.0.0.1:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| WalletError::Network(e.to_string()))?;
    let (mesh, _) = stoa::Mesh::bind(node_keys, bind_addr)?;

    // A live mesh link helps dial_any resolve the target (DHT punch
    // records, relay hints) and is the direct tier's carrier.
    if let Some(addr) = peer_addr {
        let _ = mesh.connect(to, addr).await;
    }
    chat_send_on(&mesh, to, relay, body, wait_reply).await
}

/// Interactive chat REPL (INTEGRATION.md §4): one long-lived node, a
/// background listener on the wallet's addressed chat topic (incoming
/// messages print inline), and a prompt loop for `send <meshid|label>
/// <text…>`, `whoami`, `help`, and `quit`. `send` accepts a raw MeshId
/// or a contact label (resolved via the wallet's contacts table);
/// `peer`/`peer_addr` is the optional way in: a known node to dial at
/// startup so `dial_any` and gossip have somewhere to reach. Ctrl-D or
/// `quit` exits.
pub async fn chat_repl(
    wallet: &Wallet,
    contacts: &crate::Contacts,
    peer: Option<stoa::MeshId>,
    peer_addr: Option<SocketAddr>,
) -> Result<()> {
    let node_keys = wallet.stoa_node_keys()?;
    let bind_addr = "127.0.0.1:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| WalletError::Network(e.to_string()))?;
    let (mesh, bound) = stoa::Mesh::bind(node_keys, bind_addr)?;
    let me = mesh.local_mesh_id();

    if let (Some(peer), Some(addr)) = (peer, peer_addr) {
        println!("Connecting to {peer} at {addr}…");
        match mesh.connect(peer, addr).await {
            Ok(()) => println!("  connected (mesh link up)"),
            Err(e) => println!("  note: connect failed ({e}) — continuing without it"),
        }
    }

    let mut rx = mesh
        .subscribe(&chat_topic(me))
        .await
        .map_err(|e| WalletError::Network(format!("subscribe {} failed: {e}", chat_topic(me))))?;

    // The mail contract's receive side (INTEGRATION.md §5a): a node that
    // wants mail announces its KEM identity, so any sender can encrypt to
    // it after the on-connect registry sync.
    match mesh.publish_identity(b"capability:chat,mail".to_vec()).await {
        Ok(_) => println!("  mail    : receiving (identity published)"),
        Err(e) => println!("  note    : identity publish failed ({e}) — mail cannot be received"),
    }

    println!("Chat REPL — you are {me}");
    println!("  bound : {bound}");
    println!("  type  : send <meshid|label> <text…> | contacts | whoami | help | quit");

    // The main loop's send handle (chat sends below).
    let mesh2 = mesh.clone();
    // Background listener: print incoming chat inline, poll the mailbox
    // for new mail (mail is DHT-PUT — the recipient must poll to fetch +
    // decrypt), and re-prompt. The poller gets its own clone so the main
    // loop's `mesh2` is untouched.
    let poller = mesh.clone();
    let listener = tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some(msg) => {
                        let body = String::from_utf8_lossy(&msg.data);
                        println!("\n✉ {}: {body}", msg.from);
                        print!("> ");
                        use std::io::Write;
                        let _ = std::io::stdout().flush();
                    }
                    None => break,
                },
                _ = tick.tick() => {
                    if let Ok(known) = poller.identities().await {
                        for rec in known {
                            if rec.author != poller.local_mesh_id() {
                                if let Ok(Some(payload)) = poller.poll_mail(rec.author).await {
                                    println!("\n✉ mail from {}: {}", payload.from,
                                        String::from_utf8_lossy(&payload.body));
                                    print!("> ");
                                    use std::io::Write;
                                    let _ = std::io::stdout().flush();
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        print!("> ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        line.clear();
        let n = stdin
            .read_line(&mut line)
            .map_err(|e| WalletError::Network(format!("stdin: {e}")))?;
        if n == 0 {
            println!(); // Ctrl-D
            break;
        }
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        let mut parts = input.splitn(3, ' ');
        let cmd = parts.next().unwrap_or_default();
        match cmd {
            "quit" | "exit" | "q" => break,
            "help" => {
                println!("  send <meshid|label> <text…>  — deliver a chat message (label resolves via contacts)");
                println!("  contacts                    — list your contacts");
                println!("  whoami                      — show your MeshId and bound address");
                println!("  help                        — this list");
                println!("  quit / Ctrl-D               — leave");
            }
            "contacts" => {
                if contacts.entries.is_empty() {
                    println!("  (no contacts — add with `contact add --label <label> --mesh <meshid>`)");
                } else {
                    for (label, mesh) in &contacts.entries {
                        println!("  {label} → {mesh}");
                    }
                }
            }
            "whoami" => {
                println!("  mesh id : {me}");
                println!("  bound   : {bound}");
            }
            "send" => {
                let Some(to) = parts.next() else {
                    println!("  usage: send <meshid|label> <text…>");
                    continue;
                };
                // Accept a raw MeshId or a contact label (resolved via
                // the wallet's contacts table).
                let to = match to.parse::<stoa::MeshId>() {
                    Ok(id) => id,
                    Err(_) => match contacts.entries.get(to) {
                        Some(mesh) => match mesh.parse::<stoa::MeshId>() {
                            Ok(id) => {
                                println!("  (contact '{to}' → {id})");
                                id
                            }
                            Err(_) => {
                                println!("  contact '{to}' holds a bad MeshId '{mesh}'");
                                continue;
                            }
                        },
                        None => {
                            println!("  '{to}' is neither a MeshId (64 hex chars) nor a contact label — try 'contact add --label {to} --mesh <meshid>'");
                            continue;
                        }
                    },
                };
                let Some(body) = parts.next() else {
                    println!("  usage: send <meshid|label> <text…>");
                    continue;
                };
                let body = body.as_bytes().to_vec();
                match chat_send_on(&mesh2, to, None, body.clone(), false).await {
                    Ok(outcome) => println!("✓ sent over the {}", outcome.tier),
                    Err(e) => {
                        // No live route — escalate to store-and-forward mail
                        // (delivery without a session; the recipient must
                        // publish its identity + poll its mailbox).
                        println!("✗ chat failed ({e}) — trying mail (store-and-forward)…");
                        match mail_on(&mesh2, to, body).await {
                            Ok(env) => println!(
                                "✓ delivered as mail (envelope {}…)",
                                hex::encode(&env.envelope_hash()[..4])
                            ),
                            Err(m) => println!("✗ mail failed too: {m}"),
                        }
                    }
                }
            }
            other => println!("  unknown command '{other}' — try 'help'"),
        }
    }
    listener.abort();
    Ok(())
}

/// Listen for chat on the addressed topic: subscribe to `stoa:chat:<me>`
/// (all senders) or a specific peer's topic, and return the live message
/// receiver (INTEGRATION.md §4).
pub async fn chat_listen(
    wallet: &Wallet,
    peer: Option<stoa::MeshId>,
) -> Result<stoa::PubsubMessage> {
    let node_keys = wallet.stoa_node_keys()?;
    let bind_addr = "127.0.0.1:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| WalletError::Network(e.to_string()))?;
    let (mesh, _) = stoa::Mesh::bind(node_keys, bind_addr)?;
    let me = mesh.local_mesh_id();
    let topic = match peer {
        Some(p) => chat_topic(p), // a peer's addressed topic (we send TO it)
        None => chat_topic(me),   // our own (others send TO us)
    };
    let mut rx = mesh
        .subscribe(&topic)
        .await
        .map_err(|e| WalletError::Network(format!("subscribe {topic} failed: {e}")))?;
    let msg = tokio::time::timeout(std::time::Duration::from_secs(60), rx.recv())
        .await
        .map_err(|_| WalletError::Network("chat listen timed out (60 s)".into()))?
        .ok_or_else(|| WalletError::Network("chat topic closed".into()))?;
    Ok(msg)
}

/// Opt the wallet's node into serving as a circuit relay (INTEGRATION.md
/// step 5 — the "help the network" toggle, off by default): bind the node
/// derived from the wallet seed, serve the relay role with the given PoW
/// difficulty, and start the punch-refresh loop so the node's DHT
/// candidates survive NAT remaps. Returns the live `Mesh` (drop it to
/// stop serving); the relay's abuse-control state persists under
/// `$STOA_HOME/nodes/<meshid>/`.
pub async fn serve_relay(
    wallet: &Wallet,
    pow_difficulty: u32,
    stun_server: std::net::SocketAddr,
    bind_addr: std::net::SocketAddr,
) -> Result<stoa::Mesh> {
    let node_keys = wallet.stoa_node_keys()?;
    let (mesh, _) = stoa::Mesh::bind(node_keys, bind_addr)?;
    let config = stoa::relay::RelayConfig {
        pow_difficulty,
        ..stoa::relay::RelayConfig::default()
    };
    mesh.serve_relay_with(config)
        .await
        .map_err(|e| WalletError::Network(format!("serve relay failed: {e}")))?;
    // Publish the relay hint (RELAY.md §7) so `dial_any` can find this
    // relay — a wallet serving as a relay is undiscoverable otherwise.
    // TTL ~5 min; `run_punch_refresh` below keeps the DHT records fresh.
    let bound = mesh.local_addr();
    let _ = mesh
        .publish_relay_hint(mesh.local_mesh_id(), bound, 300)
        .await;
    // Punch records are TTL'd (~5 min); refresh them so a NAT remap never
    // leaves the node's candidates stale. Best-effort background loop.
    mesh.run_punch_refresh(stun_server, std::time::Duration::from_secs(300));
    Ok(mesh)
}

/// Pay a *discovered service* (INTEGRATION.md §5 — the "call this
/// provider" action): bind this wallet's node, resolve the service's
/// signed record (local cache or DHT fetch), pay its payment address on
/// the native rail, and record the receipt in the wallet's MMR history.
/// Returns `(receipt entry, service record)`.
pub async fn pay_service(
    wallet: &mut Wallet,
    service: stoa::MeshId,
    peer_addr: Option<SocketAddr>,
    amount: u64,
    memo: Vec<u8>,
) -> Result<(stoa::ledger::LedgerEntry, stoa::ServiceRecord)> {
    let node_keys = wallet.stoa_node_keys()?;
    let bind_addr = "0.0.0.0:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| WalletError::Network(e.to_string()))?;
    let (mesh, _) = stoa::Mesh::bind(node_keys.clone(), bind_addr)?;

    if let Some(addr) = peer_addr {
        let _ = mesh.connect(service, addr).await;
    }
    let record = mesh
        .lookup_service(service)
        .await
        .ok_or_else(|| WalletError::Network(format!("no service record for {service} (has it published one?)")))?;

    // Pay the service's payment address on the native rail. The service's
    // own node (or a relay it hops through) ingests the receipt via
    // gossip + registry sync — the same delivery as `pay_native`.
    mesh.open_channel(record.payment, amount.max(1), memo.clone())
        .await
        .map_err(|e| WalletError::Network(format!("open channel to {service} failed: {e}")))?;
    let entry = mesh
        .stream_payment(record.payment, amount, memo)
        .await
        .map_err(|e| WalletError::Network(format!("stream payment to {service} failed: {e}")))?;

    // Record the payment in the wallet's MMR history (recipient = the
    // service's payment address hash).
    let sender = Address::from_ed25519(
        &ed25519_dalek::VerifyingKey::from_bytes(&node_keys.public_keys().0)
            .map_err(|e| WalletError::KeyDerivation(e.to_string()))?,
        AddressType::Bech32,
        Network::Mainnet,
    );
    let digest = Sha256::digest(record.payment.as_bytes());
    let mut to_hash = [0u8; 20];
    to_hash.copy_from_slice(&digest[..20]);
    let recipient = Address::from_hash(to_hash, AddressType::Bech32, Network::Mainnet);
    let tx = Transaction::new(&sender, &recipient, amount, 0, wallet.transaction_count());
    wallet.add_transaction(&tx)?;

    let _ = mesh.shutdown().await;
    Ok((entry, record))
}

/// Settle this wallet's channel toward `counterparty` (SPEC §10.3 —
/// time-boxed finality): bind, `settle_channel`, and return the signed
/// `ENTRY_SETTLE` recording the total paid out. The peer's symmetric
/// settle is the double-entry leg; finality is 60 s with no
/// counter-evidence.
pub async fn settle_channel_with(
    wallet: &Wallet,
    counterparty: stoa::MeshId,
    peer_addr: Option<SocketAddr>,
) -> Result<stoa::ledger::LedgerEntry> {
    let node_keys = wallet.stoa_node_keys()?;
    let bind_addr = "0.0.0.0:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| WalletError::Network(e.to_string()))?;
    let (mesh, _) = stoa::Mesh::bind(node_keys, bind_addr)?;
    if let Some(addr) = peer_addr {
        let _ = mesh.connect(counterparty, addr).await;
    }
    let entry = mesh
        .settle_channel(counterparty)
        .await
        .map_err(|e| WalletError::Network(format!("settle with {counterparty} failed: {e}")))?;
    let _ = mesh.shutdown().await;
    Ok(entry)
}

/// Bind the wallet's node with the relay role *loaded* (its persisted
/// cookie/eviction state restored from the store) but not advertised —
/// the shape behind `relay stats` / `relay evict` / `relay pardon`. The
/// relay serves no circuits here and publishes no hint; the command
/// mutates state and shuts down (persisting it).
pub async fn relay_admin(wallet: &Wallet) -> Result<stoa::Mesh> {
    let node_keys = wallet.stoa_node_keys()?;
    let bind_addr = "127.0.0.1:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| WalletError::Network(e.to_string()))?;
    let (mesh, _) = stoa::Mesh::bind(node_keys, bind_addr)?;
    let config = stoa::relay::RelayConfig::default();
    mesh.serve_relay_with(config)
        .await
        .map_err(|e| WalletError::Network(format!("load relay state failed: {e}")))?;
    Ok(mesh)
}

/// Fetch a peer's signed service record by MeshId (INTEGRATION.md §5 —
/// DHT address resolution), caching it in the node for discovery.
pub async fn lookup_service(
    service: stoa::MeshId,
    peer_addr: Option<SocketAddr>,
) -> Result<Option<stoa::ServiceRecord>> {
    let keys = stoa::NodeKeys::generate()
        .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
    let bind_addr = "0.0.0.0:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| WalletError::Network(e.to_string()))?;
    let (mesh, _) = stoa::Mesh::bind(keys, bind_addr)?;
    if let Some(addr) = peer_addr {
        let _ = mesh.connect(service, addr).await;
    }
    Ok(mesh.lookup_service(service).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wallet_pays_counterparty_and_records_history() {
        // INTEGRATION.md step 3, end-to-end: wallet A pays wallet B on the
        // native rail. The receipt is a signed ledger entry that B's node
        // ingests via gossip, and A's wallet records it in its MMR history.
        let mut payer = Wallet::create("payer-pass").unwrap();
        let payee = Wallet::create("payee-pass").unwrap();

        let payee_keys = payee.stoa_node_keys().unwrap();
        let payee_id = *payee_keys.mesh_id();
        let (payee_mesh, payee_addr) =
            stoa::Mesh::bind(payee_keys, "127.0.0.1:0".parse().unwrap()).unwrap();

        let entry = pay_native(&mut payer, payee_id, payee_addr, 777, b"step-3 test".to_vec())
            .await
            .expect("pay");

        assert_eq!(entry.amount, 777);
        assert_eq!(entry.counterparty, payee_id);
        assert_eq!(entry.kind, stoa::ledger::ENTRY_RECEIPT);
        assert_eq!(payer.transaction_count(), 1, "receipt recorded in the MMR history");

        // The payee's node ingests the signed receipt via gossip — evidence
        // settles on both sides.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if !payee_mesh.ledger_snapshot().await.is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("payee never ingested the receipt");
        assert_eq!(payee_mesh.ledger_snapshot().await[0].amount, 777);
    }

    #[tokio::test]
    async fn wallet_pays_through_relay_and_payee_ingests() {
        // The A→relay→C dogfood: payer A connects ONLY to relay B (never
        // dials C); C is connected to B. A's ledger entries reach the
        // relay by gossip fanout, and C's node ingests them via registry
        // sync — the standing-network shape where the payee isn't
        // dialable by the payer.
        let mut payer = Wallet::create("payer-pass").unwrap();
        let payee = Wallet::create("payee-pass").unwrap();

        // The payee's node binds and connects to the relay.
        let payee_keys = payee.stoa_node_keys().unwrap();
        let payee_id = *payee_keys.mesh_id();
        let (payee_mesh, _) =
            stoa::Mesh::bind(payee_keys, "127.0.0.1:0".parse().unwrap()).unwrap();

        // The relay (a wallet-derived node serving circuits).
        let relay_wallet = Wallet::create("relay-pass").unwrap();
        let relay_mesh = serve_relay(
            &relay_wallet,
            8,
            "127.0.0.1:9".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .expect("serve relay");
        let relay_id = relay_mesh.local_mesh_id();
        let relay_addr = relay_mesh.local_addr();

        // C hops to the relay so the relay has a route and C syncs with it.
        payee_mesh.connect(relay_id, relay_addr).await.expect("C→relay");

        // A pays C through the relay — never dialing C directly.
        let entry = pay_native_via_relay(
            &mut payer,
            payee_id,
            relay_id,
            relay_addr,
            4242,
            b"relayed dogfood".to_vec(),
        )
        .await
        .expect("relayed pay");

        assert_eq!(entry.amount, 4242);
        assert_eq!(entry.counterparty, payee_id);
        assert_eq!(payer.transaction_count(), 1, "receipt recorded in the MMR history");

        // C ingests A's receipt via gossip (relay fanout) + registry sync.
        // C's node actively re-syncs like the wallet's periodic check.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let _ = payee_mesh.sync_registries().await;
                let snap = payee_mesh.ledger_snapshot().await;
                if snap.iter().any(|e| e.amount == 4242) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("payee never ingested the relayed receipt");
        assert!(
            payee_mesh.ledger_snapshot().await.iter().any(|e| e.amount == 4242),
            "payee's ledger holds the relayed receipt"
        );

        payee_mesh.shutdown().await.expect("payee shutdown");
        relay_mesh.shutdown().await.expect("relay shutdown");
    }

    #[tokio::test]
    async fn relay_admin_evicts_pardons_and_persists() {
        // The relay operator surface: `relay_admin` loads the relay's
        // persisted state (no circuits served, no hint published), and
        // evict/pardon mutate it — surviving a restart through the store.
        let wallet = Wallet::create("relay-admin-pass").unwrap();

        // The client to evict (a fresh identity).
        let client_keys = stoa::NodeKeys::generate().unwrap();
        let client_id = *client_keys.mesh_id();

        // Evict through the admin handle.
        {
            let mesh = relay_admin(&wallet).await.expect("admin bind");
            let removed = mesh.relay_evict(client_id).await.expect("evict");
            assert_eq!(removed, 0, "no live circuits to revoke (not serving)");
            let stats = mesh.relay_stats().await;
            assert_eq!(stats.evicted, 1, "client on the eviction set");
            mesh.shutdown().await.expect("shutdown persists eviction");
        }

        // A fresh admin handle (what `relay evict` would be re-run as —
        // and what a relay restart does) reloads the eviction set: the
        // client is still evicted. The relay now refuses it.
        {
            let mesh = relay_admin(&wallet).await.expect("admin re-bind");
            let stats = mesh.relay_stats().await;
            assert_eq!(stats.evicted, 1, "eviction survives the admin handle");
            mesh.shutdown().await.expect("shutdown");
        }

        // Pardon: removed from the eviction set, persisted again.
        {
            let mesh = relay_admin(&wallet).await.expect("admin re-bind");
            mesh.relay_pardon(client_id).await.expect("pardon");
            let stats = mesh.relay_stats().await;
            assert_eq!(stats.evicted, 0, "pardon clears the eviction set");
            mesh.shutdown().await.expect("shutdown persists pardon");
        }
        {
            let mesh = relay_admin(&wallet).await.expect("admin re-bind");
            assert_eq!(mesh.relay_stats().await.evicted, 0, "pardon survives restart");
            mesh.shutdown().await.expect("shutdown");
        }
    }

    #[tokio::test]
    async fn wallet_pays_service_resolving_its_published_record() {
        // The "call this provider" action: A pays a discovered service's
        // *payment address* (resolved from its signed DHT record), not a
        // hard-coded MeshId.
        let mut payer = Wallet::create("payer-pass").unwrap();

        // The service: a node that has published a signed ServiceRecord
        // (its payment address may differ from its identity — here they
        // coincide for simplicity; the record is the resolution step).
        let service_keys = stoa::NodeKeys::generate().unwrap();
        let service_id = *service_keys.mesh_id();
        let (service_mesh, service_addr) =
            stoa::Mesh::bind(service_keys.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let record = stoa::ServiceRecord::sign(
            &service_keys,
            service_id,
            "reliable inference provider".into(),
            vec!["stoa:cap:inference".into()],
            stoa::store::unix_now(),
        )
        .expect("sign record");
        service_mesh
            .publish_service(record.clone())
            .await
            .expect("publish service");

        let (entry, got) = pay_service(
            &mut payer,
            service_id,
            Some(service_addr),
            555,
            b"call the provider".to_vec(),
        )
        .await
        .expect("pay service");

        assert_eq!(entry.amount, 555);
        assert_eq!(entry.counterparty, service_id, "paid the service's payment address");
        assert_eq!(got.service, service_id, "resolved the service record");
        assert_eq!(got.profile, "reliable inference provider");
        assert_eq!(payer.transaction_count(), 1, "receipt recorded in the MMR history");

        // The service's node ingests the receipt via gossip.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if !service_mesh.ledger_snapshot().await.is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("service never ingested the receipt");
        assert_eq!(service_mesh.ledger_snapshot().await[0].amount, 555);
    }

    #[tokio::test]
    async fn wallet_settles_channel_with_timeboxed_finality() {
        // SPEC §10.3 via the wallet surface: A opens a channel, streams
        // payments, then settles. The settle entry records the total paid
        // out, and finality is time-boxed (DISPUTE_WINDOW_SECS) — not
        // eternal.
        let mut payer = Wallet::create("payer-pass").unwrap();
        let payee_keys = stoa::NodeKeys::generate().unwrap();
        let payee_id = *payee_keys.mesh_id();
        let (payee_mesh, payee_addr) =
            stoa::Mesh::bind(payee_keys, "127.0.0.1:0".parse().unwrap()).unwrap();

        // A opens + streams directly (the pay path), then settles.
        let (mesh, _) = stoa::Mesh::bind(
            payer.stoa_node_keys().unwrap().clone(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        mesh.connect(payee_id, payee_addr).await.expect("connect");
        mesh.open_channel(payee_id, 10_000, b"line".to_vec())
            .await
            .expect("open");
        mesh.stream_payment(payee_id, 1200, b"work".to_vec())
            .await
            .expect("pay");
        mesh.shutdown().await.expect("shutdown");

        // settle_channel_with binds fresh (what the CLI does) and signs
        // the ENTRY_SETTLE for the total paid out.
        let settle = settle_channel_with(&payer, payee_id, Some(payee_addr))
            .await
            .expect("settle");
        assert_eq!(settle.counterparty, payee_id);
        assert_eq!(settle.amount, 1200, "settle records the total paid out");

        // Time-boxed finality: the settled channel view is final only
        // after the dispute window passes.
        let view = {
            let (mesh, _) = stoa::Mesh::bind(
                payer.stoa_node_keys().unwrap().clone(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let v = mesh.channel_state(payee_id).await.expect("channel");
            mesh.shutdown().await.expect("shutdown");
            v
        };
        assert_eq!(view.state, stoa::channel::ChannelState::Settled { total: 1200, ts: settle.ts });
        assert!(!view.final_at(settle.ts), "not final at settlement time");
        assert!(
            view.final_at(settle.ts + stoa::DISPUTE_WINDOW_SECS),
            "final after the dispute window"
        );

        // A settled channel rejects further payments.
        let (mesh, _) = stoa::Mesh::bind(
            payer.stoa_node_keys().unwrap().clone(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        mesh.connect(payee_id, payee_addr).await.expect("connect");
        assert!(mesh.stream_payment(payee_id, 1, b"after-settle".to_vec()).await.is_err());
        mesh.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn wallet_sends_mail_point_to_point() {
        // INTEGRATION.md step 4 — the mail rail: a fresh node sends a
        // signed envelope to a bound recipient node, and the recipient's
        // mesh delivers it.
        let recipient = Wallet::create("recipient-pass").unwrap();
        let recipient_keys = recipient.stoa_node_keys().unwrap();
        let recipient_id = *recipient_keys.mesh_id();
        let (recipient_mesh, recipient_addr) =
            stoa::Mesh::bind(recipient_keys, "127.0.0.1:0".parse().unwrap()).unwrap();

        // A recipient that wants mail publishes its identity record (its
        // KEM key) — the sender encrypts to it (the mail contract, §6.3).
        recipient_mesh
            .publish_identity(b"capability:mail".to_vec())
            .await
            .expect("recipient publishes identity");

        let env = send_mail(
            recipient_id,
            recipient_addr,
            b"step-4 mail body".to_vec(),
        )
        .await
        .expect("send mail");

        assert_eq!(env.to, recipient_id);
        assert!(!env.ct.is_empty(), "body is encrypted, not plaintext");
        // The envelope hash is deterministic: same envelope, same hash.
        assert_eq!(env.envelope_hash(), env.envelope_hash());

        // The recipient polls its DHT slot and decrypts — the only party
        // able to — then the inbox holds the original body. Delivery is
        // async (the envelope replicates to this node on the wire), so
        // wait bounded for it, like the pay test does.
        let payload = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if let Some(p) = recipient_mesh.poll_mail(env.from).await.expect("poll") {
                    break p;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("envelope never replicated to the recipient");
        assert_eq!(payload.body, b"step-4 mail body");
        assert_eq!(recipient_mesh.mailbox().await.len(), 1);
    }

    #[tokio::test]
    async fn mail_inbox_reloads_persisted_mailbox_after_restart() {
        // The `mail inbox` command's contract: the deduped inbox persists
        // through the P3 store, so a *fresh bind* of the same wallet's
        // node (same seed → same store root) reloads the mail. This is
        // what makes recipient-side delivery visible after the fact.
        let recipient = Wallet::create("recipient-pass").unwrap();
        let recipient_keys = recipient.stoa_node_keys().unwrap();
        let recipient_id = *recipient_keys.mesh_id();
        let (recipient_mesh, recipient_addr) =
            stoa::Mesh::bind(recipient_keys, "127.0.0.1:0".parse().unwrap()).unwrap();
        recipient_mesh
            .publish_identity(b"capability:mail".to_vec())
            .await
            .expect("recipient publishes identity");

        let env = send_mail(
            recipient_id,
            recipient_addr,
            b"persisted mail body".to_vec(),
        )
        .await
        .expect("send mail");
        assert_eq!(env.to, recipient_id);

        // Deliver into the recipient's mailbox (waiting bounded for the
        // async replication), then shut the node down cleanly — the
        // envelope must survive the node's death in the store.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if recipient_mesh.poll_mail(env.from).await.expect("poll").is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("envelope never replicated to the recipient");
        recipient_mesh.shutdown().await.expect("clean shutdown");

        // A fresh bind (what `mail inbox` does) reloads the persisted
        // mailbox: the body is intact and decrypted.
        let inbox = mail_inbox(&recipient).await.expect("inbox");
        assert_eq!(inbox.len(), 1, "mailbox reloads across node restarts");
        assert_eq!(inbox[0].body, b"persisted mail body");
    }

    #[tokio::test]
    async fn mail_on_delivers_over_the_bound_mesh() {
        // The REPL's mail fallback: send over an ALREADY-bound mesh (no
        // fresh bind+connect), which is what `chat repl` does when the
        // real-time rail fails.
        let sender = Wallet::create("sender-pass").unwrap();
        let sender_keys = sender.stoa_node_keys().unwrap();
        let (sender_mesh, _) =
            stoa::Mesh::bind(sender_keys, "127.0.0.1:0".parse().unwrap()).unwrap();

        let recipient = Wallet::create("recipient-pass").unwrap();
        let recipient_keys = recipient.stoa_node_keys().unwrap();
        let recipient_id = *recipient_keys.mesh_id();
        let (recipient_mesh, recipient_addr) =
            stoa::Mesh::bind(recipient_keys, "127.0.0.1:0".parse().unwrap()).unwrap();
        recipient_mesh
            .publish_identity(b"capability:mail".to_vec())
            .await
            .expect("recipient publishes identity");

        sender_mesh
            .connect(recipient_id, recipient_addr)
            .await
            .expect("sender connects");

        let env = mail_on(&sender_mesh, recipient_id, b"repl-fallback body".to_vec())
            .await
            .expect("mail over the bound mesh");
        assert_eq!(env.to, recipient_id);

        let payload = recipient_mesh
            .poll_mail(env.from)
            .await
            .expect("poll")
            .expect("payload present");
        assert_eq!(payload.body, b"repl-fallback body");
    }

    #[test]
    fn save_top_contact_writes_the_contacts_table() {
        // discover --save: the top-ranked hit lands in the wallet's
        // contacts sidecar under the label.
        let dir = std::env::temp_dir().join(format!("wallet-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let wallet_path = dir.join("wallet.dat");
        let top = stoa::MeshId([0xaa; 32]);
        let hits = vec![stoa::RankedService {
            service: top,
            payment: top,
            profile: "provider".into(),
            cosine: 0.9,
            trust: 1.0,
            score: 0.9,
        }];

        save_top_contact(&wallet_path, &hits, "alice").expect("save");
        let contacts = crate::Contacts::load(&wallet_path).unwrap();
        assert_eq!(
            contacts.entries.get("alice").map(String::as_str),
            Some(top.to_string().as_str())
        );

        // Empty hits: no-op, no table created.
        save_top_contact(&wallet_path, &[], "nobody").expect("no-op");
        let contacts = crate::Contacts::load(&wallet_path).unwrap();
        assert!(!contacts.entries.contains_key("nobody"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wallet_relay_toggle_serves_circuits() {
        // INTEGRATION.md step 5 — the "help the network" toggle: the
        // wallet's own node serves as a circuit relay, and a third node
        // dials a target through it (the doctor self-test pattern, but
        // with the wallet-derived identity as the relay).
        let wallet = Wallet::create("relay-pass").unwrap();
        let relay_mesh = serve_relay(
            &wallet,
            8,
            "127.0.0.1:9".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .expect("serve relay");
        let relay_id = relay_mesh.local_mesh_id();
        let relay_addr = relay_mesh.local_addr();

        // Serving publishes the relay hint so `dial_any` can find it
        // (RELAY.md §7) — a wallet relay is undiscoverable otherwise.
        let hint = relay_mesh
            .resolve_relay_hint(relay_id)
            .await
            .expect("resolve hint")
            .expect("serve_relay must publish its relay hint");
        assert_eq!(hint.relay, relay_id);
        assert_eq!(hint.relay_addr, Some(relay_addr));

        // Target hops to the relay so the relay has a route to it.
        let target_keys = stoa::NodeKeys::generate().unwrap();
        let target_id = *target_keys.mesh_id();
        let (target_mesh, _) = stoa::Mesh::bind(target_keys, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut listener = target_mesh.accept_relayed().await.unwrap();
        target_mesh.connect(relay_id, relay_addr).await.unwrap();

        // Caller dials the target through the wallet's relay.
        let caller_keys = stoa::NodeKeys::generate().unwrap();
        let (caller_mesh, _) = stoa::Mesh::bind(caller_keys, "127.0.0.1:0".parse().unwrap()).unwrap();
        let sess = caller_mesh
            .dial_relayed(relay_id, relay_addr, target_id)
            .await
            .expect("relayed dial through wallet node");
        const HELLO: &[u8] = b"wallet relay hello";
        sess.send(HELLO).await.unwrap();

        let mut target_sess = tokio::time::timeout(std::time::Duration::from_secs(30), listener.recv())
            .await
            .expect("no circuit")
            .expect("listener closed");
        let recv = tokio::time::timeout(std::time::Duration::from_secs(30), target_sess.receiver().recv())
            .await
            .expect("no data")
            .expect("channel closed");
        assert_eq!(recv, HELLO, "payload must arrive intact through the wallet relay");
    }

    #[tokio::test]
    async fn chat_direct_tier_delivers_on_the_mesh_link() {
        // INTEGRATION.md §4 direct tier: B's node connects to A's node and
        // publishes to A's addressed chat topic; A's live subscription
        // receives it — real-time, no mailbox.
        let a_wallet = Wallet::create("chat-a-pass").unwrap();
        let a_keys = a_wallet.stoa_node_keys().unwrap();
        let a_id = *a_keys.mesh_id();
        let (a_mesh, a_addr) = stoa::Mesh::bind(a_keys, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut rx = a_mesh
            .subscribe(&chat_topic(a_id))
            .await
            .expect("A subscribes to its chat topic");

        let b_wallet = Wallet::create("chat-b-pass").unwrap();
        let outcome = chat_send(
            &b_wallet,
            a_id,
            Some(a_addr),
            None,
            b"direct hello".to_vec(),
            false,
        )
        .await
        .expect("chat send");
        assert_eq!(outcome.tier, "direct");

        let msg = tokio::time::timeout(std::time::Duration::from_secs(30), rx.recv())
            .await
            .expect("A never received the chat")
            .expect("topic closed");
        assert_eq!(msg.data, b"direct hello");
    }

    #[tokio::test]
    async fn chat_relayed_tier_rides_the_session_pipe() {
        // INTEGRATION.md §4 relayed tier: B opens a circuit through the
        // relay (a third wallet node serving) and the chat rides the
        // encrypted L3 pipe — the relay sees ciphertext only.
        let relay_wallet = Wallet::create("chat-relay-pass").unwrap();
        let relay_mesh = serve_relay(
            &relay_wallet,
            8,
            "127.0.0.1:9".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .expect("serve relay");
        let relay_id = relay_mesh.local_mesh_id();
        let relay_addr = relay_mesh.local_addr();

        // A hops to the relay and accepts circuits.
        let a_wallet = Wallet::create("chat-a-pass").unwrap();
        let a_keys = a_wallet.stoa_node_keys().unwrap();
        let a_id = *a_keys.mesh_id();
        let (a_mesh, _) = stoa::Mesh::bind(a_keys, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut listener = a_mesh.accept_relayed().await.unwrap();
        a_mesh.connect(relay_id, relay_addr).await.unwrap();

        // B chats through the relay — no direct knowledge of A's address.
        // A's side runs concurrently: accept the circuit, read the frame,
        // and reply while B's --wait-reply is awaiting.
        let a_task = tokio::spawn(async move {
            let mut sess = tokio::time::timeout(std::time::Duration::from_secs(30), listener.recv())
                .await
                .expect("no circuit")
                .expect("listener closed");
            let got =
                tokio::time::timeout(std::time::Duration::from_secs(30), sess.receiver().recv())
                    .await
                    .expect("no data")
                    .expect("channel closed");
            assert_eq!(got, b"relayed hello");
            sess.send(b"got it").await.expect("reply send");
        });

        let b_wallet = Wallet::create("chat-b-pass").unwrap();
        let outcome = chat_send(
            &b_wallet,
            a_id,
            None,
            Some((relay_id, relay_addr)),
            b"relayed hello".to_vec(),
            true,
        )
        .await
        .expect("relayed chat");
        assert!(outcome.tier == "relayed" || outcome.tier == "direct-upgraded");

        // With --wait-reply, B's session awaited the reply frame.
        let reply = outcome.reply.expect("wait_reply must capture the reply");
        assert_eq!(reply, b"got it");
        a_task.await.expect("A's side of the chat");
    }
}
