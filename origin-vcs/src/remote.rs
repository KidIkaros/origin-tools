// SPDX-License-Identifier: Apache-2.0

//! File-based remotes for origin-vcs (Phase 10).
//!
//! A remote is a directory that mirrors a store's **reachable** object set as
//! encrypted envelopes plus a plaintext manifest of branch/tag tips. Because
//! objects are content-addressed by plaintext hash, their ids and fan-out paths
//! are key-agnostic — a clone you own (same seed/identity) can be mirrored
//! byte-for-byte, and a remote never needs the storage key to index objects.
//!
//! Layout:
//! ```text
//! <remote>/
//!   objects/aa/rest.env        # verbatim encrypted envelopes
//!   manifest.json              # { branches, tags, object_ids }
//! ```
//!
//! The transport seam is intentionally small: `push` exports and `fetch`
//! imports. Swapping in an `origin-network` address later only changes how the
//! object bytes and manifest are moved; the pack format is stable.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use origin_network::address::Fingerprint;
use origin_network::identity::PeerKeys;
use origin_network::session::SecurePipe;
use origin_network::transport::{FrameConn, Transport, TransportAddr};

use crate::crypto::{KeySource, Signature};
use crate::store::Store;

/// Plaintext snapshot of a remote's tips + object set (key-agnostic).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteManifest {
    pub branches: BTreeMap<String, [u8; 32]>,
    pub tags: BTreeMap<String, [u8; 32]>,
    /// Hex addresses of every envelope mirrored into `objects/`.
    pub object_ids: Vec<String>,
    /// Push policy override: when true the receiver may overwrite branch tips
    /// that are not a fast-forward of what it already has.
    #[serde(default)]
    pub force: bool,
}

/// A configured remote: name → target directory (local path today; an
/// origin-network address in a later phase).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remote {
    pub name: String,
    pub target: String,
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("manifest.json")
}

fn remote_objects_root(root: &Path) -> PathBuf {
    root.join("objects")
}

fn id_from_hex(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("bad id hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("id must be 32 bytes, got {}", bytes.len()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

// --------------------------------------------------------------------------
// remote catalog (name -> target), stored in <store>/remotes.json
// --------------------------------------------------------------------------

fn catalog_path(store_root: &Path) -> PathBuf {
    store_root.join("remotes.json")
}

pub fn list(store_root: &Path) -> Result<Vec<Remote>, String> {
    let path = catalog_path(store_root);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("remotes parse: {e}")),
        Err(_) => Ok(Vec::new()),
    }
}

pub fn add(store_root: &Path, name: &str, target: &str) -> Result<Remote, String> {
    let mut remotes = list(store_root)?;
    if remotes.iter().any(|r| r.name == name) {
        return Err(format!("remote already exists: {name}"));
    }
    let remote = Remote {
        name: name.to_string(),
        target: target.to_string(),
    };
    remotes.push(remote.clone());
    let body = serde_json::to_vec(&remotes).map_err(|e| format!("remotes ser: {e}"))?;
    origin_common::atomic_write(&catalog_path(store_root), &body)
        .map_err(|e| format!("write remotes: {e}"))?;
    Ok(remote)
}

pub fn remove(store_root: &Path, name: &str) -> Result<(), String> {
    let mut remotes = list(store_root)?;
    let before = remotes.len();
    remotes.retain(|r| r.name != name);
    if remotes.len() == before {
        return Err(format!("no such remote: {name}"));
    }
    let body = serde_json::to_vec(&remotes).map_err(|e| format!("remotes ser: {e}"))?;
    origin_common::atomic_write(&catalog_path(store_root), &body)
        .map_err(|e| format!("write remotes: {e}"))
}

pub fn get(store_root: &Path, name: &str) -> Result<Remote, String> {
    list(store_root)?
        .into_iter()
        .find(|r| r.name == name)
        .ok_or_else(|| format!("no such remote: {name}"))
}

// --------------------------------------------------------------------------
// push / fetch / pull
// --------------------------------------------------------------------------

pub fn read_manifest(remote_dir: &Path) -> Result<RemoteManifest, String> {
    let path = manifest_path(remote_dir);
    let bytes = std::fs::read(&path).map_err(|e| format!("read remote manifest: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("remote manifest parse: {e}"))
}

/// Export the reachable object set + branch/tag tips to the remote.
///
/// Local directory targets mirror a snapshot; `tcp://` targets use
/// origin-network direct transport; `quic://` targets use origin-network's
/// QUIC transport (self-signed TLS obfuscation, identical pack framing);
/// `session://` targets dial an authenticated endpoint; `relay://` targets
/// tunnel through an origin-network relay (where `net_seed` may override the
/// relay connection identity) and first attempt a NAT-punched direct UDP
/// path (STUN via `stun` when given), falling back to the relay tunnel.
pub fn push(
    store: &Store,
    ks: &KeySource,
    remote: &Remote,
    net_seed: Option<[u8; 32]>,
    stun: Option<&str>,
    force: bool,
) -> Result<RemoteManifest, String> {
    if is_tcp_target(&remote.target) {
        return net_push(store, remote, force);
    }
    if is_quic_target(&remote.target) {
        return quic_push(store, remote, force);
    }
    if is_session_target(&remote.target) {
        return session_push(store, ks, remote, net_seed, force);
    }
    if is_relay_target(&remote.target) {
        return relay_push(store, ks, remote, net_seed, stun, force);
    }
    let reachable = store.reachable_from_refs(&store.meta().branches, &store.meta().tags, &[])?;

    // Directory targets are mirrors of the same store format: enforce the
    // same fast-forward policy the network servers enforce (unless --force).
    check_dir_push_ff(store, &remote.target, &store.meta().branches, force)?;

    let objects_root = remote_objects_root(Path::new(&remote.target));
    for id in &reachable {
        store.export_object(id, &objects_root)?;
    }

    let manifest = RemoteManifest {
        branches: store.meta().branches.clone(),
        tags: store.meta().tags.clone(),
        object_ids: reachable.iter().map(hex::encode).collect(),
        force,
    };
    let body = serde_json::to_vec(&manifest).map_err(|e| format!("manifest ser: {e}"))?;
    origin_common::atomic_write(&manifest_path(Path::new(&remote.target)), &body)
        .map_err(|e| format!("write manifest: {e}"))?;
    Ok(manifest)
}

/// Reject a directory-target push whose branch tips would overwrite commits
/// the remote already has unless they fast-forward (or `force`). The remote
/// manifest lists its current tips; the pushed commit must descend from each
/// one (and be locally readable) for the overwrite to be safe.
fn check_dir_push_ff(
    store: &Store,
    target: &str,
    pushed: &BTreeMap<String, [u8; 32]>,
    force: bool,
) -> Result<(), String> {
    if force {
        return Ok(());
    }
    let remote_manifest = match read_manifest(Path::new(target)) {
        Ok(m) => m,
        Err(_) => return Ok(()), // first push to an empty target
    };
    for (b, pushed_tip) in pushed {
        if let Some(remote_tip) = remote_manifest.branches.get(b) {
            if remote_tip == pushed_tip {
                continue;
            }
            let ff = store.read_commit(remote_tip).is_ok()
                && is_ancestor(store, *remote_tip, *pushed_tip)?;
            if !ff {
                return Err(format!(
                    "push refused: remote branch '{b}' is not a fast-forward \
                     (remote has {}); use --force to overwrite",
                    short_id(remote_tip)
                ));
            }
        }
    }
    Ok(())
}

fn short_id(id: &[u8; 32]) -> String {
    hex::encode(&id[..8])
}

/// Import every object listed in the remote manifest (byte-for-byte) and, when
/// `track` is set, record `name/<branch>` tracking refs under `refs/remotes/`
/// signed by the local identity.
///
/// `shallow` requests a truncated fetch: only the tip commits' trees/blobs
/// (no ancestor history), and the store is marked shallow. Only network
/// transports can serve a shallow pack; directory/bundle targets fall back
/// to a full fetch with a warning.
pub fn fetch(
    store: &mut Store,
    ks: &KeySource,
    remote: &Remote,
    track: bool,
    net_seed: Option<[u8; 32]>,
    stun: Option<&str>,
    depth: Option<usize>,
) -> Result<RemoteManifest, String> {
    if is_tcp_target(&remote.target) {
        return net_fetch(store, ks, remote, track, depth);
    }
    if is_quic_target(&remote.target) {
        return quic_fetch(store, ks, remote, track, depth);
    }
    if is_session_target(&remote.target) {
        return session_fetch(store, ks, remote, track, net_seed, depth);
    }
    if is_relay_target(&remote.target) {
        return relay_fetch(store, ks, remote, track, net_seed, stun, depth);
    }
    if depth.is_some() {
        println!(
            "warning: shallow fetch is only supported over network remotes; fetching full history"
        );
    }
    let manifest = read_manifest(Path::new(&remote.target))?;
    if manifest.object_ids.is_empty() {
        return Err(format!(
            "remote '{}' has no objects (push to it first)",
            remote.name
        ));
    }
    let objects_root = remote_objects_root(Path::new(&remote.target));
    let mut imported = 0usize;
    for hexid in &manifest.object_ids {
        let id = id_from_hex(hexid)?;
        if store.import_object(&id, &objects_root)? {
            imported += 1;
        }
    }

    if track {
        let bundle = ks.signing_bundle()?;
        for (b, id) in &manifest.branches {
            let tracking = format!("{}/{}", remote.name, b);
            let sig = Signature::sign(&bundle, id);
            store.write_ref("remotes", &tracking, *id, &sig)?;
            store.update_mem_ref("remotes", &tracking, *id);
        }
    }
    let _ = imported;
    Ok(manifest)
}

/// pull = fetch + attach the fetched branch to the current working tree by
/// fast-forwarding the local branch onto the remote tip (refusing on diverge).
pub fn pull(
    store: &mut Store,
    ks: &KeySource,
    remote: &Remote,
    branch: &str,
    cwd: &Path,
    net_seed: Option<[u8; 32]>,
    stun: Option<&str>,
) -> Result<(), String> {
    fetch(store, ks, remote, true, net_seed, stun, None)?;
    let remote_ref = format!("{}/{}", remote.name, branch);
    if !store.ref_exists("remotes", &remote_ref) {
        return Err(format!("remote branch {branch} not found after fetch"));
    }
    let remote_tip = store.read_ref("remotes", &remote_ref)?;

    let local_tip = if store.ref_exists("heads", branch) {
        Some(store.read_ref("heads", branch)?)
    } else {
        None
    };

    match local_tip {
        Some(local) if local == remote_tip => {
            println!("already up to date with {remote_ref}");
        }
        Some(local) => {
            if !is_ancestor(store, local, remote_tip)? {
                return Err(format!(
                    "remote {remote_ref} is not a fast-forward of {branch} (diverged); merge manually"
                ));
            }
            let commit = store.read_commit(&remote_tip)?;
            let tree = store.read_tree(&commit.tree)?;
            let bundle = ks.signing_bundle()?;
            let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&commit));
            store.write_ref("heads", branch, remote_tip, &sig)?;
            store.update_mem_ref("heads", branch, remote_tip);
            store.save_index(&tree)?;
            crate::commands::ensure_tree_on_disk(store, &tree, cwd)?;
            store.append_commit_leaf(&remote_tip)?;
            println!(
                "fast-forwarded {branch} to {remote_ref} ({})",
                hex::encode(remote_tip)
            );
        }
        None => attach_branch(store, ks, branch, remote_tip, cwd, &remote_ref)?,
    }
    Ok(())
}

/// Create a local branch at `tip`, check it out (index + working tree), and
/// append it to the commit log. Used by `pull`/`clone` when the branch does
/// not exist locally yet.
pub fn attach_branch(
    store: &mut Store,
    ks: &KeySource,
    branch: &str,
    tip: [u8; 32],
    cwd: &Path,
    src: &str,
) -> Result<(), String> {
    let commit = store.read_commit(&tip)?;
    let tree = store.read_tree(&commit.tree)?;
    let bundle = ks.signing_bundle()?;
    let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&commit));
    store.write_ref("heads", branch, tip, &sig)?;
    store.update_mem_ref("heads", branch, tip);
    store.set_head(Some(branch.to_string()))?;
    store.save_index(&tree)?;
    crate::commands::ensure_tree_on_disk(store, &tree, cwd)?;
    store.append_commit_leaf(&tip)?;
    println!("created local branch {branch} from {src}");
    Ok(())
}

// --------------------------------------------------------------------------
// prune (stale tracking refs)
// --------------------------------------------------------------------------

/// Branch names currently tracked for a remote under `refs/remotes/<name>/`.
pub fn tracking_refs(store: &Store, remote: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let dir = store.root().join("refs").join("remotes").join(remote);
    if !dir.is_dir() {
        return Ok(out);
    }
    for e in std::fs::read_dir(&dir).map_err(|e| format!("refs remotes dir: {e}"))? {
        let e = e.map_err(|e| format!("refs remotes entry: {e}"))?;
        if e.path().is_file() {
            out.push(e.file_name().to_string_lossy().to_string());
        }
    }
    Ok(out)
}

/// Delete tracking refs for a remote whose branch the remote no longer
/// advertises (or whose advertised tip differs from the local ref). Returns
/// the number of refs pruned.
pub fn prune(
    store: &mut Store,
    ks: &KeySource,
    remote: &Remote,
    net_seed: Option<[u8; 32]>,
    stun: Option<&str>,
) -> Result<usize, String> {
    // Current view of the remote's branches (manifest only — no object
    // import). `tcp://`/`relay://` targets answer a lightweight `ls`.
    let manifest = if is_tcp_target(&remote.target) {
        net_ls(remote)?
    } else if is_quic_target(&remote.target) {
        quic_ls(remote)?
    } else if is_session_target(&remote.target) {
        session_ls(remote, net_seed_or_default(ks, net_seed))?
    } else if is_relay_target(&remote.target) {
        relay_ls(remote, net_seed_or_default(ks, net_seed), stun)?
    } else {
        read_manifest(Path::new(&remote.target))?
    };

    let mut pruned = 0usize;
    for b in tracking_refs(store, &remote.name)? {
        let name = format!("{}/{b}", remote.name);
        let stale = match manifest.branches.get(&b) {
            None => true,
            Some(tip) => store.read_ref("remotes", &name).ok() != Some(*tip),
        };
        if stale {
            store.delete_ref("remotes", &name)?;
            pruned += 1;
        }
    }
    Ok(pruned)
}

/// Whether `ancestor` is an ancestor (or equal) of `desc` in the parent DAG.
/// On a shallow clone a missing boundary parent means we cannot prove the
/// relationship, so it answers `false` (callers then refuse the fast-forward).
pub(crate) fn is_ancestor(
    store: &Store,
    ancestor: [u8; 32],
    desc: [u8; 32],
) -> Result<bool, String> {
    let mut cur = desc;
    loop {
        if cur == ancestor {
            return Ok(true);
        }
        let c = match store.read_commit(&cur) {
            Ok(c) => c,
            Err(_) if store.is_shallow() => return Ok(false),
            Err(e) => return Err(e),
        };
        match c.parents.first() {
            Some(p) => cur = *p,
            None => return Ok(false),
        }
    }
}

// --------------------------------------------------------------------------
// origin-network transport (Phase 10 follow-up)
//
// A remote whose target is `tcp://<host>:<port>` is served by an origin-network
// `TcpTransport`. The protocol is a tiny synchronous request/response over
// channel pass-through frames (type 0x10 DATA):
//
//   client → server: REQUEST {"cmd":"fetch"|"push"}
//   fetch:  server → client: MANIFEST(json), OBJECT*(envelope bytes), DONE
//   push:   client → server: MANIFEST(json), OBJECT*(envelope bytes), DONE
//
// Each message is chunked into ≤8 MB frames (the codec caps a frame at 16 MB)
// with a `[type][more]` prefix. Object envelopes travel verbatim (addresses are
// key-agnostic); the server needs the key only to compute reachability and to
// sign refs on push. The server verifies each pushed commit's embedded hybrid
// signature before accepting it.
// --------------------------------------------------------------------------

/// Channel pass-through frame type used for pack messages (DATA range).
const PACK_FRAME: u8 = 0x10;
const MSG_REQUEST: u8 = 0x01;
const MSG_MANIFEST: u8 = 0x02;
const MSG_OBJECT: u8 = 0x03;
const MSG_DONE: u8 = 0x04;
const MSG_ERROR: u8 = 0x05;
/// Per-frame chunk size (well under the 16 MB codec cap).
const CHUNK: usize = 8 * 1024 * 1024;
/// Datagram chunk size for the NAT-punched UDP transport. Stays well under
/// the UDP frame ceiling (`origin_network::udp::MAX_DATAGRAM_FRAME`) with
/// room for the codec + `[type][more]` prefixes.
const UDP_CHUNK: usize = 32 * 1024;

pub fn is_tcp_target(target: &str) -> bool {
    target.starts_with("tcp://")
}

fn tcp_addr(target: &str) -> Result<std::net::SocketAddr, String> {
    let host_port = target.strip_prefix("tcp://").unwrap_or(target);
    host_port
        .parse::<std::net::SocketAddr>()
        .map_err(|e| format!("invalid tcp target '{target}': {e}"))
}

async fn send_msg(
    conn: &mut dyn origin_network::transport::FrameConn,
    typ: u8,
    body: &[u8],
) -> Result<(), String> {
    // Always emit at least one frame — an empty body (e.g. the DONE marker)
    // must still produce a final frame so the peer's recv can return.
    let mut sent = false;
    for chunk in body.chunks(CHUNK) {
        let mut payload = Vec::with_capacity(2 + chunk.len());
        payload.push(typ);
        payload.push(0); // last chunk of this message
        payload.extend_from_slice(chunk);
        conn.send_frame(PACK_FRAME, &payload)
            .await
            .map_err(|e| format!("send pack frame: {e}"))?;
        sent = true;
    }
    if !sent {
        conn.send_frame(PACK_FRAME, &[typ, 0])
            .await
            .map_err(|e| format!("send pack frame: {e}"))?;
    }
    Ok(())
}

async fn recv_msg(
    conn: &mut dyn origin_network::transport::FrameConn,
) -> Result<(u8, Vec<u8>), String> {
    let mut typ = 0u8;
    let mut body = Vec::new();
    loop {
        let (tag, payload) = conn
            .recv_frame()
            .await
            .map_err(|e| format!("recv pack frame: {e}"))?;
        if tag != PACK_FRAME {
            return Err(format!("unexpected frame type 0x{tag:02x}"));
        }
        if payload.len() < 2 {
            return Err("short pack frame".to_string());
        }
        if typ == 0 {
            typ = payload[0];
        }
        let more = payload[1] & 1;
        body.extend_from_slice(&payload[2..]);
        if more == 0 {
            break;
        }
    }
    Ok((typ, body))
}

fn run<T>(f: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?
        .block_on(f)
}

async fn dial(
    addr: std::net::SocketAddr,
) -> Result<Box<dyn origin_network::transport::FrameConn>, String> {
    let transport = origin_network::transport::TcpTransport::connector();
    transport
        .connect(&origin_network::transport::TransportAddr::Tcp(addr))
        .await
        .map_err(|e| format!("dial {addr}: {e}"))
}

/// The one-way pack exchange over an established [FrameConn]: client side of
/// push (request → manifest → objects → DONE, then wait for the reply).
async fn push_exchange(
    store: &Store,
    conn: &mut dyn FrameConn,
    manifest: &RemoteManifest,
) -> Result<(), String> {
    let mbytes = serde_json::to_vec(manifest).map_err(|e| format!("manifest ser: {e}"))?;
    send_msg(conn, MSG_REQUEST, b"{\"cmd\":\"push\"}").await?;
    send_msg(conn, MSG_MANIFEST, &mbytes).await?;
    for hexid in &manifest.object_ids {
        let id = id_from_hex(hexid)?;
        let bytes = store.envelope_bytes(&id)?;
        send_msg(conn, MSG_OBJECT, &bytes).await?;
    }
    send_msg(conn, MSG_DONE, b"").await?;
    let (typ, body) = recv_msg(conn).await?;
    match typ {
        MSG_DONE => Ok(()),
        MSG_ERROR => Err(String::from_utf8_lossy(&body).to_string()),
        other => Err(format!("push: unexpected reply type 0x{other:02x}")),
    }
}

/// The one-way pack exchange over an established [FrameConn]: client side of
/// fetch (request → manifest → objects → DONE, import as they arrive).
/// When `depth` is Some(n), requests a truncated pack (at most n ancestor
/// generations from each ref tip) and records the boundary tips as the
/// store's shallow boundary.
async fn fetch_exchange(
    store: &mut Store,
    ks: &KeySource,
    name: &str,
    track: bool,
    depth: Option<usize>,
    conn: &mut dyn FrameConn,
) -> Result<RemoteManifest, String> {
    let req: Vec<u8> = match depth {
        None => b"{\"cmd\":\"fetch\"}".to_vec(),
        Some(1) => b"{\"cmd\":\"fetch\",\"shallow\":true}".to_vec(),
        Some(n) => format!(r#"{{"cmd":"fetch","shallow":true,"depth":{n}}}"#).into_bytes(),
    };
    send_msg(conn, MSG_REQUEST, &req).await?;
    let (typ, mbytes) = recv_msg(conn).await?;
    if typ == MSG_ERROR {
        return Err(String::from_utf8_lossy(&mbytes).to_string());
    }
    if typ != MSG_MANIFEST {
        return Err(format!("fetch: expected manifest, got 0x{typ:02x}"));
    }
    let manifest: RemoteManifest =
        serde_json::from_slice(&mbytes).map_err(|e| format!("manifest parse: {e}"))?;
    let mut imported = 0usize;
    loop {
        let (typ, body) = recv_msg(conn).await?;
        match typ {
            MSG_OBJECT => {
                let id = id_from_hex(
                    manifest
                        .object_ids
                        .get(imported)
                        .ok_or_else(|| "more objects than manifest".to_string())?,
                )?;
                store.put_envelope_bytes(&id, &body)?;
                imported += 1;
            }
            MSG_DONE => break,
            MSG_ERROR => return Err(String::from_utf8_lossy(&body).to_string()),
            other => return Err(format!("fetch: unexpected frame 0x{other:02x}")),
        }
    }
    // The server must have sent every object the manifest listed; anything
    // less means the transport dropped data (notably the UDP punch path,
    // which has no retransmission).
    if imported != manifest.object_ids.len() {
        return Err(format!(
            "fetch incomplete: imported {imported}/{} objects",
            manifest.object_ids.len()
        ));
    }
    if depth.is_some() {
        // The boundary tips are the deepest commits served (their parents
        // were not fetched); the manifest does not carry them, so derive
        // from the store's own refs — for a depth-N fetch the boundary is
        // every ref tip reachable within the truncated pack. Recording the
        // ref tips marks the clone shallow; the depth walk already ensured
        // the parents of the deepest commits are absent.
        let tips: Vec<[u8; 32]> = manifest.branches.values().copied().collect();
        store.mark_shallow(&tips)?;
    }
    if track {
        let bundle = ks.signing_bundle()?;
        for (b, id) in &manifest.branches {
            let tracking = format!("{name}/{b}");
            let sig = Signature::sign(&bundle, id);
            store.write_ref("remotes", &tracking, *id, &sig)?;
            store.update_mem_ref("remotes", &tracking, *id);
        }
    }
    Ok(manifest)
}

/// The one-way pack exchange over an established [FrameConn]: client side of
/// `ls` (manifest only, no objects — used by `remote prune`).
async fn ls_exchange(conn: &mut dyn FrameConn) -> Result<RemoteManifest, String> {
    send_msg(conn, MSG_REQUEST, b"{\"cmd\":\"ls\"}").await?;
    let (typ, mbytes) = recv_msg(conn).await?;
    if typ == MSG_ERROR {
        return Err(String::from_utf8_lossy(&mbytes).to_string());
    }
    if typ != MSG_MANIFEST {
        return Err(format!("ls: expected manifest, got 0x{typ:02x}"));
    }
    let manifest: RemoteManifest =
        serde_json::from_slice(&mbytes).map_err(|e| format!("manifest parse: {e}"))?;
    let (typ, _body) = recv_msg(conn).await?;
    if typ != MSG_DONE {
        return Err(format!("ls: expected DONE, got 0x{typ:02x}"));
    }
    Ok(manifest)
}

/// Push to a `tcp://` remote: send manifest + object envelopes, DONE.
pub fn net_push(store: &Store, remote: &Remote, force: bool) -> Result<RemoteManifest, String> {
    let addr = tcp_addr(&remote.target)?;
    let reachable = store.reachable_from_refs(&store.meta().branches, &store.meta().tags, &[])?;
    let manifest = RemoteManifest {
        branches: store.meta().branches.clone(),
        tags: store.meta().tags.clone(),
        object_ids: reachable.iter().map(hex::encode).collect(),
        force,
    };
    let m = manifest.clone();
    run(async move {
        let mut conn = dial(addr).await?;
        push_exchange(store, &mut *conn, &m).await
    })?;
    Ok(manifest)
}

/// Fetch from a `tcp://` remote: request manifest + objects, import them, and
/// (when `track`) set `refs/remotes/<name>/<branch>` refs signed locally.
pub fn net_fetch(
    store: &mut Store,
    ks: &KeySource,
    remote: &Remote,
    track: bool,
    depth: Option<usize>,
) -> Result<RemoteManifest, String> {
    let addr = tcp_addr(&remote.target)?;
    let name = remote.name.clone();
    run(async move {
        let mut conn = dial(addr).await?;
        fetch_exchange(store, ks, &name, track, depth, &mut *conn).await
    })
}

/// Serve one connection for the store: answer a fetch or accept a push.
/// Binds on `listen` (port 0 = ephemeral); `on_bound` is invoked with the
/// actual bound address as soon as the listener is up (before accepting), so
/// a caller can hand the address to a client. Returns the served address.
pub fn serve_once(
    store: &mut Store,
    ks: &KeySource,
    listen: std::net::SocketAddr,
    on_bound: impl FnOnce(std::net::SocketAddr) + Send + 'static,
) -> Result<std::net::SocketAddr, String> {
    run(async move {
        let transport = origin_network::transport::TcpTransport::listen(listen)
            .await
            .map_err(|e| format!("bind {listen}: {e}"))?;
        let bound = match transport.local_addr() {
            Some(origin_network::transport::TransportAddr::Tcp(a)) => a,
            _ => return Err("no bound tcp address".to_string()),
        };
        on_bound(bound);
        let mut conn = transport
            .accept()
            .await
            .map_err(|e| format!("accept: {e}"))?;
        dispatch_request(store, ks, &mut *conn).await?;
        Ok(bound)
    })
}

/// Read one REQUEST and serve it. Shared by every transport's serve path
/// (tcp, session, relay, punched-UDP) so the pack protocol stays identical
/// regardless of how the bytes moved.
async fn dispatch_request(
    store: &mut Store,
    ks: &KeySource,
    conn: &mut dyn FrameConn,
) -> Result<(), String> {
    let (typ, body) = recv_msg(conn).await?;
    serve_request(store, ks, conn, typ, body).await
}

/// Match an already-received REQUEST and serve it. Split out of
/// [dispatch_request] so the UDP serve path can hand over a REQUEST that
/// arrived whole in its first datagram.
async fn serve_request(
    store: &mut Store,
    ks: &KeySource,
    conn: &mut dyn FrameConn,
    typ: u8,
    body: Vec<u8>,
) -> Result<(), String> {
    if typ != MSG_REQUEST {
        send_msg(conn, MSG_ERROR, b"expected REQUEST").await?;
        return Err(format!("peer sent 0x{typ:02x}, expected REQUEST"));
    }
    let req = String::from_utf8_lossy(&body).to_string();
    // Fetch requests may carry `shallow: true` and an optional `depth`
    // (ancestor generations to serve; 1 = tips only). Parse loosely so a
    // truncated pack is served for any shallow request.
    let depth: Option<usize> = if req.contains("\"shallow\":true") {
        let d = req
            .split("\"depth\":")
            .nth(1)
            .and_then(|s| {
                s.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .ok()
            })
            .unwrap_or(1);
        Some(d)
    } else {
        None
    };
    match req.as_str() {
        "{\"cmd\":\"fetch\"}" => serve_fetch(store, conn, None).await,
        "{\"cmd\":\"push\"}" => serve_push(store, ks, conn).await,
        "{\"cmd\":\"ls\"}" => serve_ls(store, conn).await,
        other if other.contains("\"cmd\":\"fetch\"") => serve_fetch(store, conn, depth).await,
        other => {
            send_msg(
                conn,
                MSG_ERROR,
                format!("unknown request: {other}").as_bytes(),
            )
            .await?;
            Err(format!("unknown request: {other}"))
        }
    }
}

async fn serve_fetch(
    store: &Store,
    conn: &mut dyn FrameConn,
    depth: Option<usize>,
) -> Result<(), String> {
    // Serve the published snapshot if one was pushed, else the store's own
    // refs. A depth-limited request serves only the first `depth` ancestor
    // generations from each ref tip (1 = tips only, no ancestor history).
    let manifest = match depth {
        Some(n) => RemoteManifest {
            branches: store.meta().branches.clone(),
            tags: store.meta().tags.clone(),
            object_ids: store
                .depth_reachable(&store.meta().branches, &store.meta().tags, &[], n)?
                .0
                .iter()
                .map(hex::encode)
                .collect(),
            force: false,
        },
        None => published_manifest(store).unwrap_or(RemoteManifest {
            branches: store.meta().branches.clone(),
            tags: store.meta().tags.clone(),
            object_ids: store
                .reachable_from_refs(&store.meta().branches, &store.meta().tags, &[])?
                .iter()
                .map(hex::encode)
                .collect(),
            force: false,
        }),
    };
    let mbytes = serde_json::to_vec(&manifest).map_err(|e| format!("manifest ser: {e}"))?;
    send_msg(conn, MSG_MANIFEST, &mbytes).await?;
    for hexid in &manifest.object_ids {
        let id = id_from_hex(hexid)?;
        let bytes = store.envelope_bytes(&id)?;
        send_msg(conn, MSG_OBJECT, &bytes).await?;
    }
    send_msg(conn, MSG_DONE, b"").await?;
    Ok(())
}

/// Serve a `ls` request: manifest only, no objects. Used by `remote prune`.
async fn serve_ls(store: &Store, conn: &mut dyn FrameConn) -> Result<(), String> {
    let manifest = published_manifest(store).unwrap_or(RemoteManifest {
        branches: store.meta().branches.clone(),
        tags: store.meta().tags.clone(),
        object_ids: Vec::new(),
        force: false,
    });
    let mbytes = serde_json::to_vec(&manifest).map_err(|e| format!("manifest ser: {e}"))?;
    send_msg(conn, MSG_MANIFEST, &mbytes).await?;
    send_msg(conn, MSG_DONE, b"").await?;
    Ok(())
}

/// Fetch only the manifest (no objects) from a `tcp://` remote. Used by
/// `remote prune` to compare advertised branches against tracking refs.
pub fn net_ls(remote: &Remote) -> Result<RemoteManifest, String> {
    let addr = tcp_addr(&remote.target)?;
    run(async move {
        let mut conn = dial(addr).await?;
        ls_exchange(&mut *conn).await
    })
}

// --------------------------------------------------------------------------
// QUIC transport (`quic://host:port`)
//
// origin-network's `quic` feature exposes `QuicTransport`/`QuicFrameConn` —
// a QUIC (quinn) listener/connector pair that implements the SAME FrameConn
// trait the pack protocol already runs over. QUIC adds stream multiplexing,
// 0-RTT-capable migration support, and congestion control; identity is still
// authenticated above the transport (or not at all, matching tcp:// — the
// session:// target adds auth). Because the frame layer is identical, the
// whole pack exchange ([push_exchange]/[fetch_exchange]/[ls_exchange] and
// [dispatch_request]) runs over QUIC unchanged.
// --------------------------------------------------------------------------

pub fn is_quic_target(target: &str) -> bool {
    target.starts_with("quic://")
}

fn quic_addr(target: &str) -> Result<std::net::SocketAddr, String> {
    let host_port = target.strip_prefix("quic://").unwrap_or(target);
    host_port
        .parse::<std::net::SocketAddr>()
        .map_err(|e| format!("invalid quic target '{target}': {e}"))
}

async fn quic_dial(
    addr: std::net::SocketAddr,
) -> Result<Box<dyn origin_network::transport::FrameConn>, String> {
    let transport = origin_network::quic::QuicTransport::connector()
        .map_err(|e| format!("quic connector: {e}"))?;
    transport
        .connect(&origin_network::transport::TransportAddr::Quic(addr))
        .await
        .map_err(|e| format!("quic dial {addr}: {e}"))
}

/// Push to a `quic://` remote: the same pack exchange as [net_push] over the
/// QUIC transport.
pub fn quic_push(store: &Store, remote: &Remote, force: bool) -> Result<RemoteManifest, String> {
    let addr = quic_addr(&remote.target)?;
    let reachable = store.reachable_from_refs(&store.meta().branches, &store.meta().tags, &[])?;
    let manifest = RemoteManifest {
        branches: store.meta().branches.clone(),
        tags: store.meta().tags.clone(),
        object_ids: reachable.iter().map(hex::encode).collect(),
        force,
    };
    let m = manifest.clone();
    run(async move {
        let mut conn = quic_dial(addr).await?;
        let r = push_exchange(store, &mut *conn, &m).await;
        quic_close(&mut *conn).await;
        r
    })?;
    Ok(manifest)
}

/// Fetch from a `quic://` remote: request manifest + objects over QUIC,
/// import them, and (when `track`) set tracking refs.
pub fn quic_fetch(
    store: &mut Store,
    ks: &KeySource,
    remote: &Remote,
    track: bool,
    depth: Option<usize>,
) -> Result<RemoteManifest, String> {
    let addr = quic_addr(&remote.target)?;
    let name = remote.name.clone();
    run(async move {
        let mut conn = quic_dial(addr).await?;
        let r = fetch_exchange(store, ks, &name, track, depth, &mut *conn).await;
        quic_close(&mut *conn).await;
        r
    })
}

/// Manifest-only fetch from a `quic://` remote (used by `remote prune`).
pub fn quic_ls(remote: &Remote) -> Result<RemoteManifest, String> {
    let addr = quic_addr(&remote.target)?;
    run(async move {
        let mut conn = quic_dial(addr).await?;
        let r = ls_exchange(&mut *conn).await;
        quic_close(&mut *conn).await;
        r
    })
}

/// Gracefully tear down a QUIC pack connection. QUIC writes are buffered by
/// a driver task that lives on this runtime; returning from `run()` drops
/// the runtime and kills the driver before buffered frames (or our FIN)
/// reach the peer. `shutdown` sends a real CONNECTION_CLOSE and keeps the
/// runtime alive (via `Endpoint::wait_idle`) until the close handshake
/// finishes, so both peers exit promptly instead of hitting the idle
/// timeout.
async fn quic_close(conn: &mut dyn origin_network::transport::FrameConn) {
    let _ = conn.shutdown().await;
}

/// Serve one QUIC connection for the store (fetch or signature-verified
/// push). Binds on `listen` (port 0 = ephemeral); `on_bound` is invoked with
/// the actual bound address as soon as the listener is up, so a caller can
/// hand the address to a client. Returns the served address.
pub fn serve_quic_once(
    store: &mut Store,
    ks: &KeySource,
    listen: std::net::SocketAddr,
    on_bound: impl FnOnce(std::net::SocketAddr) + Send + 'static,
) -> Result<std::net::SocketAddr, String> {
    run(async move {
        let transport = origin_network::quic::QuicTransport::listen(listen)
            .await
            .map_err(|e| format!("quic bind {listen}: {e}"))?;
        let bound = match transport.local_addr() {
            Some(origin_network::transport::TransportAddr::Quic(a)) => a,
            _ => return Err("no bound quic address".to_string()),
        };
        on_bound(bound);
        let mut conn = transport
            .accept()
            .await
            .map_err(|e| format!("quic accept: {e}"))?;
        let r = dispatch_request(store, ks, &mut *conn).await;
        if r.is_ok() {
            // Finish our send stream (so the client's recv returns promptly),
            // then wait for the peer to close the connection (its exchange
            // finished reading our DONE). This keeps our runtime — and the
            // transport's driver task — alive until the client's teardown, so
            // every response frame is flushed before we return.
            let _ = conn.close().await;
            let rr = conn.recv_frame().await;
            if rr.is_ok() {
                return Err("quic: unexpected frame after dispatch".to_string());
            }
        }
        r?;
        Ok(bound)
    })
}

async fn serve_push(
    store: &mut Store,
    ks: &KeySource,
    conn: &mut dyn origin_network::transport::FrameConn,
) -> Result<(), String> {
    let (typ, mbytes) = recv_msg(conn).await?;
    if typ != MSG_MANIFEST {
        send_msg(conn, MSG_ERROR, b"expected MANIFEST").await?;
        return Err("push: expected MANIFEST".to_string());
    }
    let manifest: RemoteManifest =
        serde_json::from_slice(&mbytes).map_err(|e| format!("manifest parse: {e}"))?;

    let mut imported = 0usize;
    loop {
        let (typ, body) = recv_msg(conn).await?;
        match typ {
            MSG_OBJECT => {
                let id = id_from_hex(
                    manifest
                        .object_ids
                        .get(imported)
                        .ok_or_else(|| "more objects than manifest".to_string())?,
                )?;
                store.put_envelope_bytes(&id, &body)?;
                imported += 1;
            }
            MSG_DONE => break,
            MSG_ERROR => return Err(String::from_utf8_lossy(&body).to_string()),
            other => return Err(format!("push: unexpected frame 0x{other:02x}")),
        }
    }

    // Verify every pushed branch/tag tip's embedded signature before adopting,
    // and enforce the fast-forward policy: a push may not overwrite a branch
    // tip unless the pushed tip descends from the current one (or --force).
    // Rejections are reported to the client as an MSG_ERROR frame (so the
    // pusher sees the real reason) before the connection closes.
    let bundle = ks.signing_bundle()?;
    for (b, id) in &manifest.branches {
        let record = store.read_commit_record(id)?;
        if let Err(e) = record
            .signature
            .verify(&crate::object::canonical_commit(&record.commit))
        {
            let msg = format!(
                "push rejected: branch '{b}' commit {} bad signature: {e}",
                hex::encode(id)
            );
            let _ = send_msg(conn, MSG_ERROR, msg.as_bytes()).await;
            return Ok(());
        }
        if let Ok(cur) = store.read_ref("heads", b) {
            if cur != *id && !manifest.force && !is_ancestor(store, cur, *id)? {
                let msg = format!(
                    "push rejected: branch '{b}' is not a fast-forward (server has {}); \
                     push --force to overwrite",
                    short_id(&cur)
                );
                let _ = send_msg(conn, MSG_ERROR, msg.as_bytes()).await;
                return Ok(());
            }
        }
        let sig = Signature::sign(&bundle, &crate::object::canonical_commit(&record.commit));
        store.write_ref("heads", b, *id, &sig)?;
        store.update_mem_ref("heads", b, *id);
    }

    // Persist the pushed snapshot so later fetches serve it.
    let body = serde_json::to_vec(&manifest).map_err(|e| format!("manifest ser: {e}"))?;
    origin_common::atomic_write(&store.root().join("published-manifest.json"), &body)
        .map_err(|e| format!("write published manifest: {e}"))?;
    send_msg(conn, MSG_DONE, b"").await?;
    Ok(())
}

fn published_manifest(store: &Store) -> Result<RemoteManifest, String> {
    let path = store.root().join("published-manifest.json");
    let bytes = std::fs::read(&path).map_err(|e| format!("read published manifest: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("published manifest parse: {e}"))
}

// --------------------------------------------------------------------------
// origin-network relay transport (follow-up phase)
//
// A remote whose target is `relay://host:port/<relay-fp>/<relay-pk>/<peer-fp>`
// tunnels the SAME pack protocol through an origin-network relay: both
// endpoints hold authenticated connections to the relay, the client opens a
// live forwarding pair (`session_open`), and every RelayData frame is a
// `[type][more]`-prefixed pack chunk forwarded verbatim by the relay.
//
// The relay identifies endpoints by fingerprint and keys its forwarder by
// that fingerprint, so the two ends of a pair must use DISTINCT identities.
// Because identity-mode storage keys are derived from the repo seed, a
// client cloning a repo it shares a storage key with should pass `--net-seed
// <other>` to authenticate to the relay as a different identity.
//
// The relay operator must have registered both endpoint keys (the relay's
// allowlist resolver); unregistered peers are rejected at AUTH.
// --------------------------------------------------------------------------

/// `relay://host:port/<relay-fp>/<relay-pk>/<peer-fp>`
pub fn is_relay_target(target: &str) -> bool {
    target.starts_with("relay://")
}

/// Parsed relay target (client side: knows the peer it wants to reach).
struct RelaySpec {
    addr: std::net::SocketAddr,
    relay_keys: PeerKeys,
    peer_fp: Fingerprint,
}

/// Parse the three relay components both sides share:
/// `relay://host:port/<relay-fp-hex>/<relay-pk-hex>`. The optional fourth
/// component is the peer fingerprint (client targets only; `serve` computes
/// its own).
fn relay_parts(
    target: &str,
) -> Result<
    (
        std::net::SocketAddr,
        Fingerprint,
        [u8; 32],
        Option<Fingerprint>,
    ),
    String,
> {
    let rest = target.strip_prefix("relay://").unwrap_or(target);
    let mut parts = rest.split('/');
    let host_port = parts.next().ok_or("relay target missing host:port")?;
    let relay_fp_hex = parts
        .next()
        .ok_or("relay target missing relay fingerprint")?;
    let relay_pk_hex = parts
        .next()
        .ok_or("relay target missing relay transport key")?;
    let addr: std::net::SocketAddr = host_port
        .parse()
        .map_err(|e| format!("invalid relay target '{target}': {e}"))?;
    let relay_fp =
        Fingerprint::from_hex(relay_fp_hex).map_err(|e| format!("bad relay fingerprint: {e}"))?;
    let pk = hex::decode(relay_pk_hex).map_err(|e| format!("bad relay transport key: {e}"))?;
    if pk.len() != 32 {
        return Err(format!(
            "relay transport key must be 32 bytes, got {}",
            pk.len()
        ));
    }
    let mut relay_pk = [0u8; 32];
    relay_pk.copy_from_slice(&pk);
    let peer_fp = match parts.next() {
        Some(h) => {
            Some(Fingerprint::from_hex(h).map_err(|e| format!("bad peer fingerprint: {e}"))?)
        }
        None => None,
    };
    Ok((addr, relay_fp, relay_pk, peer_fp))
}

fn relay_spec(target: &str) -> Result<RelaySpec, String> {
    let (addr, relay_fp, relay_pk, peer_fp) = relay_parts(target)?;
    let peer_fp = peer_fp.ok_or("relay target missing peer fingerprint")?;
    Ok(RelaySpec {
        addr,
        relay_keys: PeerKeys {
            fingerprint: relay_fp.0,
            device_index: 0,
            ed25519_pk: Vec::new(),
            falcon_pk: Vec::new(),
            transport_pk: relay_pk.to_vec(),
        },
        peer_fp,
    })
}

/// The relay connection identity: an explicit `--net-seed` overrides the
/// repo seed so the two ends of a relay pair can use distinct identities
/// while sharing one storage key (see module docs).
pub(crate) fn net_seed_or_default(ks: &KeySource, net_seed: Option<[u8; 32]>) -> [u8; 32] {
    net_seed.unwrap_or(*ks.seed())
}

async fn relay_connect(
    spec: &RelaySpec,
    identity_seed: [u8; 32],
) -> Result<origin_network::client::RelayClient, String> {
    let transport: std::sync::Arc<dyn Transport> =
        std::sync::Arc::new(origin_network::transport::TcpTransport::connector());
    origin_network::client::RelayClient::connect(
        identity_seed,
        0,
        &transport,
        &TransportAddr::Tcp(spec.addr),
        &spec.relay_keys,
    )
    .await
    .map_err(|e| format!("relay connect: {e}"))
}

/// Poll the peer's presence until it is registered/online at the relay
/// (bounded ~2 s), so `session_open` never races the peer's connect.
async fn wait_online(
    client: &origin_network::client::RelayClient,
    peer: &Fingerprint,
) -> Result<(), String> {
    for _ in 0..40 {
        if client
            .probe(peer)
            .await
            .map_err(|e| format!("relay probe: {e}"))?
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err(format!("relay peer {peer} not online"))
}

/// A live relay pair presented as a [FrameConn], so the pack protocol
/// ([send_msg]/[recv_msg], `serve_fetch`/`serve_push`) runs over the relay
/// unchanged. Every RelayData frame carries one `[type][more]` pack chunk;
/// the transport tag byte is omitted on the wire and replaced on recv.
struct RelayFrameConn<'a> {
    client: &'a origin_network::client::RelayClient,
    pair: u64,
    seq: u64,
    addr: std::net::SocketAddr,
    /// A frame the serve select already received (the peer's REQUEST),
    /// pre-fed so [FrameConn::recv_frame] returns it without another recv.
    pending: Option<Vec<u8>>,
}

impl<'a> RelayFrameConn<'a> {
    fn new(
        client: &'a origin_network::client::RelayClient,
        pair: u64,
        addr: std::net::SocketAddr,
    ) -> Self {
        RelayFrameConn {
            client,
            pair,
            seq: 0,
            addr,
            pending: None,
        }
    }
}

#[async_trait::async_trait]
impl<'a> origin_network::transport::FrameConn for RelayFrameConn<'a> {
    async fn send_frame(
        &mut self,
        _typ: u8,
        payload: &[u8],
    ) -> Result<(), origin_network::error::NetworkError> {
        self.client
            .relay_send(self.pair, self.seq, payload.to_vec())
            .await
            .map_err(|e| origin_network::error::NetworkError::Transport(e.to_string()))?;
        self.seq += 1;
        Ok(())
    }

    async fn recv_frame(&mut self) -> Result<(u8, Vec<u8>), origin_network::error::NetworkError> {
        if let Some(frame) = self.pending.take() {
            return Ok((PACK_FRAME, frame));
        }
        let data = self
            .client
            .relay_recv()
            .await
            .map_err(|e| origin_network::error::NetworkError::Transport(e.to_string()))?
            .ok_or_else(|| {
                origin_network::error::NetworkError::Transport("relay connection closed".into())
            })?;
        // Adopt the pair id from the inbound frame (server side learns it here).
        self.pair = data.pair_id;
        Ok((PACK_FRAME, data.frame))
    }

    fn peer_addr(&self) -> TransportAddr {
        TransportAddr::Tcp(self.addr)
    }

    async fn close(&mut self) -> Result<(), origin_network::error::NetworkError> {
        self.client
            .session_close(self.pair)
            .await
            .map_err(|e| origin_network::error::NetworkError::Transport(e.to_string()))
    }
}

/// Push to a `relay://` remote: same pack exchange as [net_push], tunneled
/// through a live relay pair. First attempts a NAT-punched direct UDP path
/// (`stun` server optional) and only falls back to the relay tunnel when the
/// punch fails or the peer published no advert.
pub fn relay_push(
    store: &Store,
    ks: &KeySource,
    remote: &Remote,
    net_seed: Option<[u8; 32]>,
    stun: Option<&str>,
    force: bool,
) -> Result<RemoteManifest, String> {
    let spec = relay_spec(&remote.target)?;
    let ident = net_seed_or_default(ks, net_seed);
    let reachable = store.reachable_from_refs(&store.meta().branches, &store.meta().tags, &[])?;
    let manifest = RemoteManifest {
        branches: store.meta().branches.clone(),
        tags: store.meta().tags.clone(),
        object_ids: reachable.iter().map(hex::encode).collect(),
        force,
    };
    let m = manifest.clone();

    run(async move {
        let client = relay_connect(&spec, ident).await?;
        wait_online(&client, &spec.peer_fp).await?;
        // Punch-first: if the peer advertised UDP candidates and a socket
        // comes up, exchange the pack directly and skip the relay tunnel.
        if let Some(mut conn) = try_punch(&client, &spec.peer_fp, stun).await? {
            push_exchange(store, &mut conn, &m).await?;
            let _ = conn.close().await;
            return Ok(manifest);
        }
        let pair = client
            .session_open(&spec.peer_fp)
            .await
            .map_err(|e| format!("relay session open: {e}"))?;
        let mut peer = RelayFrameConn::new(&client, pair, spec.addr);
        push_exchange(store, &mut peer, &m).await?;
        let _ = peer.close().await;
        Ok(manifest)
    })
}

/// Fetch from a `relay://` remote: tunnel the manifest + objects exchange
/// through a live relay pair and import (optionally tracking refs), after
/// trying a NAT-punched direct UDP path first.
pub fn relay_fetch(
    store: &mut Store,
    ks: &KeySource,
    remote: &Remote,
    track: bool,
    net_seed: Option<[u8; 32]>,
    stun: Option<&str>,
    depth: Option<usize>,
) -> Result<RemoteManifest, String> {
    let spec = relay_spec(&remote.target)?;
    let ident = net_seed_or_default(ks, net_seed);
    let name = remote.name.clone();

    run(async move {
        let client = relay_connect(&spec, ident).await?;
        wait_online(&client, &spec.peer_fp).await?;
        if let Some(mut conn) = try_punch(&client, &spec.peer_fp, stun).await? {
            let m = fetch_exchange(store, ks, &name, track, depth, &mut conn).await?;
            let _ = conn.close().await;
            return Ok(m);
        }
        let pair = client
            .session_open(&spec.peer_fp)
            .await
            .map_err(|e| format!("relay session open: {e}"))?;
        let mut peer = RelayFrameConn::new(&client, pair, spec.addr);
        let m = fetch_exchange(store, ks, &name, track, depth, &mut peer).await?;
        let _ = peer.close().await;
        Ok(m)
    })
}

/// Manifest-only fetch from a `relay://` remote (used by `remote prune`).
pub fn relay_ls(
    remote: &Remote,
    ident: [u8; 32],
    stun: Option<&str>,
) -> Result<RemoteManifest, String> {
    let spec = relay_spec(&remote.target)?;
    run(async move {
        let client = relay_connect(&spec, ident).await?;
        wait_online(&client, &spec.peer_fp).await?;
        if let Some(mut conn) = try_punch(&client, &spec.peer_fp, stun).await? {
            let m = ls_exchange(&mut conn).await?;
            let _ = conn.close().await;
            return Ok(m);
        }
        let pair = client
            .session_open(&spec.peer_fp)
            .await
            .map_err(|e| format!("relay session open: {e}"))?;
        let mut peer = RelayFrameConn::new(&client, pair, spec.addr);
        let m = ls_exchange(&mut peer).await?;
        let _ = peer.close().await;
        Ok(m)
    })
}

/// Serve ONE request/response exchange through a relay (the CLI wraps this
/// in a loop; tests call it once). The relay URL is the 3-component form
/// `relay://host:port/<relay-fp>/<relay-pk>`; our own fingerprint is the
/// peer identity clients dial.
///
/// The server also binds a fresh UDP punch socket, publishes its candidates
/// as a relay advert (`stun` optionally resolves the public address), and
/// serves whichever client arrives first: a NAT-punched UDP exchange or a
/// relay session. `on_udp_ready` (if any) is called with the bound UDP
/// address once the advert is published, so a caller can start punching.
pub fn serve_relay_once(
    store: &mut Store,
    ks: &KeySource,
    relay_url: &str,
    net_seed: Option<[u8; 32]>,
    stun: Option<&str>,
    on_udp_ready: Option<Box<dyn FnOnce(std::net::SocketAddr) + Send>>,
) -> Result<(), String> {
    let spec = serve_relay_spec(relay_url, ks, net_seed)?;
    let ident = net_seed_or_default(ks, net_seed);
    run(async move {
        let client = relay_connect(&spec, ident).await?;
        let udp = publish_advert(&client, stun).await?;
        let udp_addr = udp
            .local_addr()
            .map_err(|e| format!("udp local_addr: {e}"))?;
        if let Some(cb) = on_udp_ready {
            cb(udp_addr);
        }
        // Wait for traffic on either path; the store is only borrowed by the
        // branch that actually serves, so the two waits can coexist.
        tokio::select! {
            r = udp.readable() => {
                r.map_err(|e| format!("udp readable: {e}"))?;
                serve_udp_client(store, ks, udp).await?;
            }
            r = client.relay_recv() => {
                let data = r
                    .map_err(|e| format!("relay recv: {e}"))?
                    .ok_or_else(|| "relay connection closed".to_string())?;
                serve_relay_exchange(store, ks, &client, data, spec.addr).await?;
            }
        }
        Ok(())
    })
}

/// The CLI serve loop for a `relay://` target: reconnects, re-publishes the
/// UDP advert, and serves one exchange (relay session or punched UDP client)
/// per iteration until interrupted.
pub fn serve_relay_forever(
    store: &mut Store,
    ks: &KeySource,
    relay_url: &str,
    net_seed: Option<[u8; 32]>,
    stun: Option<&str>,
) -> Result<(), String> {
    loop {
        serve_relay_once(store, ks, relay_url, net_seed, stun, None)?;
        println!("served one relay/punch session");
    }
}

/// The shared 3-component relay parse for the serve side (rejects a peer
/// fingerprint component, which only client targets carry).
fn serve_relay_spec(
    relay_url: &str,
    ks: &KeySource,
    net_seed: Option<[u8; 32]>,
) -> Result<RelaySpec, String> {
    let (addr, relay_fp, relay_pk, peer) = relay_parts(relay_url)?;
    if peer.is_some() {
        return Err("serve relay URL must not include a peer fingerprint".into());
    }
    let ident = net_seed_or_default(ks, net_seed);
    let my_fp = Fingerprint::from_seed_bytes(&ident);
    Ok(RelaySpec {
        addr,
        relay_keys: PeerKeys {
            fingerprint: relay_fp.0,
            device_index: 0,
            ed25519_pk: Vec::new(),
            falcon_pk: Vec::new(),
            transport_pk: relay_pk.to_vec(),
        },
        peer_fp: my_fp,
    })
}

/// Serve one already-received relay frame (the peer's REQUEST) through the
/// server's existing relay connection.
async fn serve_relay_exchange(
    store: &mut Store,
    ks: &KeySource,
    client: &origin_network::client::RelayClient,
    first: origin_network::wire::RelayData,
    addr: std::net::SocketAddr,
) -> Result<(), String> {
    let mut peer = RelayFrameConn {
        client,
        pair: first.pair_id,
        seq: 0,
        addr,
        pending: Some(first.frame),
    };
    dispatch_request(store, ks, &mut peer).await?;
    let _ = peer.close().await;
    Ok(())
}

/// Publish our UDP punch candidates (public via STUN when configured, plus
/// the local address) as a relay advert, so clients can attempt a direct
/// NAT-punched exchange instead of the relay tunnel. Returns the punch
/// listener socket (kept alive for the serve session).
async fn publish_advert(
    client: &origin_network::client::RelayClient,
    stun: Option<&str>,
) -> Result<tokio::net::UdpSocket, String> {
    let sock = origin_network::fresh_punch_socket(false)
        .await
        .map_err(|e| format!("udp punch bind: {e}"))?;
    bump_udp_buffers(&sock)?;
    let local = sock
        .local_addr()
        .map_err(|e| format!("udp local_addr: {e}"))?;
    let public = match stun {
        Some(srv) => match origin_network::discover_public_address(&sock, srv).await {
            Ok(a) => a,
            Err(_) => local,
        },
        None => local,
    };
    client
        .advert_publish(origin_network::wire::Advert {
            protocol_version: 1,
            endpoints: vec![public.to_string(), local.to_string()],
            ttl_secs: 120,
            presence: 1,
        })
        .await
        .map_err(|e| format!("advert publish: {e}"))?;
    Ok(sock)
}

/// Accept one NAT-punched UDP client on the listener: skip punch probes
/// (replying to them so the client's punch loop connects), then serve the
/// pack exchange over the datagram transport. Takes ownership of the socket
/// (the select in [serve_relay_once] hands it over).
async fn serve_udp_client(
    store: &mut Store,
    ks: &KeySource,
    sock: tokio::net::UdpSocket,
) -> Result<(), String> {
    loop {
        sock.readable()
            .await
            .map_err(|e| format!("udp readable: {e}"))?;
        let mut buf = vec![0u8; 64 * 1024];
        match sock.try_recv_from(&mut buf) {
            Ok((n, from)) => {
                let d = &buf[..n];
                if d.is_empty() || d.starts_with(origin_network::PUNCH_PROBE) {
                    if d.starts_with(origin_network::PUNCH_PROBE) {
                        let _ = sock.send_to(origin_network::PUNCH_PROBE, from).await;
                    }
                    continue;
                }
                let mut conn = UdpPackFrameConn::new_listener(sock, from);
                match conn.seed_datagram(d)? {
                    // The first datagram carried the whole REQUEST: strip the
                    // pack prefix and dispatch on the message type.
                    Some((_tag, payload)) => {
                        if payload.len() < 2 {
                            return Err("short pack datagram".into());
                        }
                        let msg_typ = payload[0];
                        let body = payload[2..].to_vec();
                        serve_request(store, ks, &mut conn, msg_typ, body).await?;
                    }
                    // Fragmented: let dispatch_request reassemble the rest.
                    None => dispatch_request(store, ks, &mut conn).await?,
                }
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(format!("udp recv: {e}")),
        }
    }
}

/// Client side of the punch: fetch the peer's advertised UDP candidates,
/// punch/dial a direct socket (bounded), and wrap it as a pack FrameConn.
/// `Ok(None)` means "no advert or punch failed" — the caller falls back to
/// the relay tunnel.
async fn try_punch(
    client: &origin_network::client::RelayClient,
    peer: &Fingerprint,
    stun: Option<&str>,
) -> Result<Option<UdpPackFrameConn>, String> {
    // The server publishes its advert right after connecting; retry briefly
    // so a fast client doesn't miss it.
    let mut advert = None;
    for _ in 0..40 {
        match client.advert_fetch(peer).await {
            Ok(Some(a)) => {
                advert = Some(a);
                break;
            }
            _ => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
        }
    }
    let Some(a) = advert else { return Ok(None) };
    let Some(peer_addrs) = parse_peer_addrs(&a.endpoints) else {
        return Ok(None);
    };
    match tokio::time::timeout(
        std::time::Duration::from_secs(12),
        origin_network::connect_p2p(&peer_addrs, stun),
    )
    .await
    {
        Ok(Ok(Some(socket))) => Ok(Some(UdpPackFrameConn::new_connected(socket)?)),
        _ => Ok(None),
    }
}

/// Parse an advert's endpoints into punch candidates: first = public
/// (NAT-mapped), second (if present) = private (LAN).
fn parse_peer_addrs(endpoints: &[String]) -> Option<origin_network::nat::PeerAddrs> {
    let public = endpoints.first()?.parse::<std::net::SocketAddr>().ok()?;
    let private = endpoints
        .get(1)
        .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
        .unwrap_or(public);
    Some(origin_network::nat::PeerAddrs { public, private })
}

// --------------------------------------------------------------------------
// authenticated sessions (`session://host:port/<peer-fp>/<peer-tpk>`)
//
// The raw `tcp://` transport is convenient but unauthenticated: anyone who
// can reach the port can fetch ciphertext. `session://` targets dial an
// origin-network Endpoint instead, so the peer's identity is verified by the
// Noise IK handshake + AUTH claim before a single pack byte moves, and the
// pack protocol rides inside a ratcheted SecurePipe. The server side
// (`serve --session`) accepts only identities on its allowlist.
// --------------------------------------------------------------------------

pub fn is_session_target(target: &str) -> bool {
    target.starts_with("session://")
}

/// Parse `session://host:port/<peer-fp-hex>/<peer-tpk-hex>`.
fn session_parts(target: &str) -> Result<(std::net::SocketAddr, Fingerprint, [u8; 32]), String> {
    let rest = target.strip_prefix("session://").unwrap_or(target);
    let mut parts = rest.split('/');
    let host_port = parts.next().ok_or("session target missing host:port")?;
    let fp_hex = parts
        .next()
        .ok_or("session target missing peer fingerprint")?;
    let tpk_hex = parts
        .next()
        .ok_or("session target missing peer transport key")?;
    let addr: std::net::SocketAddr = host_port
        .parse()
        .map_err(|e| format!("invalid session target '{target}': {e}"))?;
    let fp = Fingerprint::from_hex(fp_hex).map_err(|e| format!("bad session fingerprint: {e}"))?;
    let tpk = hex::decode(tpk_hex).map_err(|e| format!("bad session transport key: {e}"))?;
    if tpk.len() != 32 {
        return Err(format!(
            "session transport key must be 32 bytes, got {}",
            tpk.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&tpk);
    Ok((addr, fp, key))
}

/// Dial an authenticated session to `addr` as `identity_seed`, verifying the
/// peer against `fp`/`tpk` via the Noise IK + AUTH handshake.
async fn session_connect(
    addr: std::net::SocketAddr,
    fp: Fingerprint,
    tpk: [u8; 32],
    identity_seed: [u8; 32],
) -> Result<SecurePipe, String> {
    let peer = PeerKeys {
        fingerprint: fp.0,
        device_index: 0,
        ed25519_pk: Vec::new(),
        falcon_pk: Vec::new(),
        transport_pk: tpk.to_vec(),
    };
    let mut resolver = origin_network::session::StaticResolver::new();
    resolver.add(peer.clone());
    let transport: std::sync::Arc<dyn Transport> =
        std::sync::Arc::new(origin_network::transport::TcpTransport::connector());
    let ep = origin_network::session::Endpoint::new(
        identity_seed,
        0,
        transport,
        std::sync::Arc::new(resolver),
    )
    .map_err(|e| format!("session endpoint: {e}"))?;
    ep.connect_at(&peer, &TransportAddr::Tcp(addr))
        .await
        .map_err(|e| format!("session connect: {e}"))
}

/// [FrameConn] adapter over an authenticated [SecurePipe]: the pack protocol
/// runs unchanged inside the ratcheted session.
struct PipeConn<'a> {
    pipe: &'a mut SecurePipe,
    addr: std::net::SocketAddr,
}

#[async_trait::async_trait]
impl<'a> FrameConn for PipeConn<'a> {
    async fn send_frame(
        &mut self,
        typ: u8,
        payload: &[u8],
    ) -> Result<(), origin_network::error::NetworkError> {
        let frame = origin_channel::codec::encode_typed(typ, payload)
            .map_err(|e| origin_network::error::NetworkError::Codec(e.to_string()))?;
        self.pipe.send(&frame).await
    }

    async fn recv_frame(&mut self) -> Result<(u8, Vec<u8>), origin_network::error::NetworkError> {
        let bytes = self.pipe.recv().await?;
        match origin_network::wire::decode_wire(&bytes)? {
            Some((tag, payload, _consumed)) => Ok((tag, payload)),
            None => Err(origin_network::error::NetworkError::Codec(
                "incomplete frame over session".into(),
            )),
        }
    }

    fn peer_addr(&self) -> TransportAddr {
        TransportAddr::Tcp(self.addr)
    }

    async fn close(&mut self) -> Result<(), origin_network::error::NetworkError> {
        Ok(())
    }
}

/// Push to a `session://` remote over an authenticated SecurePipe.
pub fn session_push(
    store: &Store,
    ks: &KeySource,
    remote: &Remote,
    net_seed: Option<[u8; 32]>,
    force: bool,
) -> Result<RemoteManifest, String> {
    let (addr, fp, tpk) = session_parts(&remote.target)?;
    let ident = net_seed_or_default(ks, net_seed);
    let reachable = store.reachable_from_refs(&store.meta().branches, &store.meta().tags, &[])?;
    let manifest = RemoteManifest {
        branches: store.meta().branches.clone(),
        tags: store.meta().tags.clone(),
        object_ids: reachable.iter().map(hex::encode).collect(),
        force,
    };
    let m = manifest.clone();
    run(async move {
        let mut pipe = session_connect(addr, fp, tpk, ident).await?;
        let mut conn = PipeConn {
            pipe: &mut pipe,
            addr,
        };
        push_exchange(store, &mut conn, &m).await
    })?;
    Ok(manifest)
}

/// Fetch from a `session://` remote over an authenticated SecurePipe.
pub fn session_fetch(
    store: &mut Store,
    ks: &KeySource,
    remote: &Remote,
    track: bool,
    net_seed: Option<[u8; 32]>,
    depth: Option<usize>,
) -> Result<RemoteManifest, String> {
    let (addr, fp, tpk) = session_parts(&remote.target)?;
    let ident = net_seed_or_default(ks, net_seed);
    let name = remote.name.clone();
    run(async move {
        let mut pipe = session_connect(addr, fp, tpk, ident).await?;
        let mut conn = PipeConn {
            pipe: &mut pipe,
            addr,
        };
        fetch_exchange(store, ks, &name, track, depth, &mut conn).await
    })
}

/// Manifest-only fetch from a `session://` remote (used by `remote prune`).
pub fn session_ls(remote: &Remote, ident: [u8; 32]) -> Result<RemoteManifest, String> {
    let (addr, fp, tpk) = session_parts(&remote.target)?;
    run(async move {
        let mut pipe = session_connect(addr, fp, tpk, ident).await?;
        let mut conn = PipeConn {
            pipe: &mut pipe,
            addr,
        };
        ls_exchange(&mut conn).await
    })
}

/// Serve the store over authenticated sessions forever. Only identities in
/// `allow` (or the `--allow-file` PeerKeys records) pass the AUTH claim;
/// unknown peers are rejected by the endpoint before any pack bytes move.
/// `on_bound` (if any) reports the actual bound address once the listener is
/// up (port 0 = ephemeral), so callers can construct client targets.
pub fn serve_session(
    store: &mut Store,
    ks: &KeySource,
    listen: std::net::SocketAddr,
    allow: &[[u8; 32]],
    net_seed: Option<[u8; 32]>,
    on_bound: Option<Box<dyn FnOnce(std::net::SocketAddr) + Send>>,
) -> Result<(), String> {
    let ident = net_seed_or_default(ks, net_seed);
    run(async move {
        let mut resolver = origin_network::session::StaticResolver::new();
        for s in allow {
            resolver.add(PeerKeys::from_seed(s, 0).map_err(|e| format!("allow seed: {e}"))?);
        }
        let transport: std::sync::Arc<dyn Transport> = std::sync::Arc::new(
            origin_network::transport::TcpTransport::listen(listen)
                .await
                .map_err(|e| format!("bind {listen}: {e}"))?,
        );
        let bound = match transport.local_addr() {
            Some(TransportAddr::Tcp(a)) => a,
            _ => return Err("no bound session address".to_string()),
        };
        if let Some(cb) = on_bound {
            cb(bound);
        }
        let ep = origin_network::session::Endpoint::new(
            ident,
            0,
            transport,
            std::sync::Arc::new(resolver),
        )
        .map_err(|e| format!("session endpoint: {e}"))?;
        println!(
            "serving {} via authenticated sessions on {bound} (ctrl-c to stop)",
            store.root().display()
        );
        loop {
            match ep.accept_one().await {
                Ok(mut pipe) => {
                    let peer = pipe.peer();
                    let mut conn = PipeConn {
                        pipe: &mut pipe,
                        addr: bound,
                    };
                    if let Err(e) = dispatch_request(store, ks, &mut conn).await {
                        eprintln!("session {peer}: {e}");
                    }
                }
                Err(e) => eprintln!("accept session: {e}"),
            }
        }
    })
}

/// Serve ONE pack exchange over a dialed/punched UDP socket (no relay).
/// Binds an ephemeral UDP listener and reports it via `on_bound` so a client
/// can dial it; used by the transport tests and as the building block for
/// relay-adjacent punch serving.
pub fn serve_udp_once(
    store: &mut Store,
    ks: &KeySource,
    on_bound: impl FnOnce(std::net::SocketAddr) + Send + 'static,
) -> Result<(), String> {
    run(async move {
        let sock = origin_network::fresh_punch_socket(false)
            .await
            .map_err(|e| format!("udp bind: {e}"))?;
        bump_udp_buffers(&sock)?;
        let addr = sock
            .local_addr()
            .map_err(|e| format!("udp local_addr: {e}"))?;
        on_bound(addr);
        serve_udp_client(store, ks, sock).await
    })
}

/// Manifest-only pack exchange with a store served on a known UDP socket
/// (dial + `ls`). Proves the datagram transport carries the pack protocol.
pub fn udp_ls(addr: std::net::SocketAddr) -> Result<RemoteManifest, String> {
    run(async move {
        let sock = origin_network::dial_direct(&addr)
            .await
            .map_err(|e| format!("udp dial {addr}: {e}"))?;
        let mut conn = UdpPackFrameConn::new_connected(sock)?;
        let m = ls_exchange(&mut conn).await?;
        let _ = conn.close().await;
        Ok(m)
    })
}

/// Full fetch over a dialed UDP socket (imports every manifest object).
pub fn udp_fetch(
    store: &mut Store,
    ks: &KeySource,
    name: &str,
    track: bool,
    addr: std::net::SocketAddr,
) -> Result<RemoteManifest, String> {
    run(async move {
        let sock = origin_network::dial_direct(&addr)
            .await
            .map_err(|e| format!("udp dial {addr}: {e}"))?;
        let mut conn = UdpPackFrameConn::new_connected(sock)?;
        let m = fetch_exchange(store, ks, name, track, None, &mut conn).await?;
        let _ = conn.close().await;
        Ok(m)
    })
}

// --------------------------------------------------------------------------
// NAT-punched UDP transport
//
// `UdpPackFrameConn` is a [FrameConn] over an UNCONNECTED UDP socket with a
// fixed peer, so one listener can serve sequential punched clients (the peer
// is learned from the first inbound datagram). Large pack messages are
// transparently fragmented into `[type][more]`-prefixed datagrams (≤ UDP_CHUNK)
// and reassembled on recv — the pack layer above sees whole frames exactly
// as it would over TCP, so every serve/exchange helper works unchanged.
// Punch probes and datagrams from other senders are skipped (probes are
// answered so the client's punch loop connects).
// --------------------------------------------------------------------------

/// Reassembly state for a single inbound message stream (split from the
/// socket struct so a datagram slice can be passed in without aliasing).
struct UdpReasm {
    buf: Vec<u8>,
    frag_typ: Option<u8>,
}

impl UdpReasm {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            frag_typ: None,
        }
    }

    /// Feed one datagram; returns the completed `[msg_type][0][body]` payload
    /// when this datagram finished a message.
    fn process(
        &mut self,
        d: &[u8],
    ) -> Result<Option<(u8, Vec<u8>)>, origin_network::error::NetworkError> {
        if d.is_empty() || d.starts_with(origin_network::PUNCH_PROBE) {
            return Ok(None);
        }
        let (_tag, payload, _consumed) =
            origin_network::wire::decode_wire(d)?.ok_or_else(|| {
                origin_network::error::NetworkError::Codec("incomplete UDP frame".into())
            })?;
        // Datagram payload = [msg_type][more][piece]; reassemble pieces by
        // message type and re-emit the full `[msg_type][0][body]` payload the
        // pack layer expects from [FrameConn::recv_frame].
        if payload.len() < 2 {
            return Err(origin_network::error::NetworkError::Codec(
                "short pack datagram".into(),
            ));
        }
        let typ = payload[0];
        let more = payload[1] & 1;
        if self.buf.is_empty() {
            self.frag_typ = Some(typ);
        } else if self.frag_typ != Some(typ) {
            self.buf.clear();
            self.frag_typ = Some(typ);
        }
        self.buf.extend_from_slice(&payload[2..]);
        if more == 0 {
            let data = std::mem::take(&mut self.buf);
            self.frag_typ = None;
            let mut out = Vec::with_capacity(2 + data.len());
            out.push(typ);
            out.push(0); // reassembly complete
            out.extend_from_slice(&data);
            return Ok(Some((PACK_FRAME, out)));
        }
        Ok(None)
    }
}

struct UdpPackFrameConn {
    socket: tokio::net::UdpSocket,
    peer: std::net::SocketAddr,
    /// Reassembly state (disjoint from `recv_buf` so a datagram slice can be
    /// processed while the socket/state stay mutable).
    reasm: UdpReasm,
    /// Reused datagram buffer (avoid a fresh 64KB allocation per recv, which
    /// slows the reassembly loop enough to overflow the kernel buffer under a
    /// multi-datagram burst).
    recv_buf: Vec<u8>,
}

impl UdpPackFrameConn {
    /// Client side: the socket came from [origin_network::connect_p2p] and is
    /// already connected; `peer` is its connected peer.
    fn new_connected(socket: tokio::net::UdpSocket) -> Result<Self, String> {
        let peer = socket
            .peer_addr()
            .map_err(|e| format!("udp socket not connected: {e}"))?;
        bump_udp_buffers(&socket)?;
        Ok(Self {
            socket,
            peer,
            reasm: UdpReasm::new(),
            recv_buf: vec![0u8; 64 * 1024],
        })
    }

    /// Server side: an unconnected listener; `peer` is the client learned
    /// from the first real datagram.
    fn new_listener(socket: tokio::net::UdpSocket, peer: std::net::SocketAddr) -> Self {
        Self {
            socket,
            peer,
            reasm: UdpReasm::new(),
            recv_buf: vec![0u8; 64 * 1024],
        }
    }

    /// Feed one datagram through the reassembler (used by the serve path for
    /// the first datagram the select consumed). Returns the completed message
    /// if this datagram finished it, else `None` (caller falls through to
    /// [dispatch_request], which reads the remaining fragments).
    fn seed_datagram(&mut self, d: &[u8]) -> Result<Option<(u8, Vec<u8>)>, String> {
        self.reasm.process(d).map_err(|e| e.to_string())
    }
}

#[async_trait::async_trait]
impl FrameConn for UdpPackFrameConn {
    async fn send_frame(
        &mut self,
        _typ: u8,
        payload: &[u8],
    ) -> Result<(), origin_network::error::NetworkError> {
        // Payload = [msg_type][more][data...]; re-chunk the data into UDP
        // datagrams, each carrying its own [msg_type][more] prefix so the
        // peer can reassemble by message type.
        if payload.len() < 2 {
            return Err(origin_network::error::NetworkError::Codec(
                "pack frame without type prefix".into(),
            ));
        }
        let msg_typ = payload[0];
        let data = &payload[2..];
        let mut chunks = data.chunks(UDP_CHUNK).peekable();
        if chunks.peek().is_none() {
            // Zero-length data (e.g. the DONE marker): one bare datagram.
            return udp_send_piece(&self.socket, self.peer, msg_typ, &[], 0).await;
        }
        while let Some(chunk) = chunks.next() {
            let more: u8 = if chunks.peek().is_some() { 1 } else { 0 };
            udp_send_piece(&self.socket, self.peer, msg_typ, chunk, more).await?;
        }
        Ok(())
    }

    async fn recv_frame(&mut self) -> Result<(u8, Vec<u8>), origin_network::error::NetworkError> {
        loop {
            let (n, from) = self
                .socket
                .recv_from(&mut self.recv_buf)
                .await
                .map_err(|e| origin_network::error::NetworkError::Transport(e.to_string()))?;
            if from != self.peer {
                continue;
            }
            let d = &self.recv_buf[..n];
            if d.is_empty() || d.starts_with(origin_network::PUNCH_PROBE) {
                continue;
            }
            if let Some((tag, body)) = self.reasm.process(d)? {
                return Ok((tag, body));
            }
        }
    }

    fn peer_addr(&self) -> TransportAddr {
        TransportAddr::Udp(self.peer)
    }

    async fn close(&mut self) -> Result<(), origin_network::error::NetworkError> {
        Ok(())
    }
}

/// Enlarge the kernel send+receive buffers for a pack UDP socket. A burst of
/// datagrams (a multi-chunk object) can otherwise overflow the default rmem
/// and silently drop middle datagrams; the pack protocol has no
/// retransmission, so the buffer must absorb the burst. Best-effort:
/// failures to set the size are ignored (the socket still works, just with
/// a smaller buffer).
fn bump_udp_buffers(sock: &tokio::net::UdpSocket) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();
    const SIZE: libc::c_int = 4 * 1024 * 1024;
    unsafe {
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &SIZE as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &SIZE as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    Ok(())
}

/// Send one `[msg_type][more][piece]` datagram to `peer`.
async fn udp_send_piece(
    sock: &tokio::net::UdpSocket,
    peer: std::net::SocketAddr,
    msg_typ: u8,
    piece: &[u8],
    more: u8,
) -> Result<(), origin_network::error::NetworkError> {
    let mut inner = Vec::with_capacity(2 + piece.len());
    inner.push(msg_typ);
    inner.push(more);
    inner.extend_from_slice(piece);
    let frame = origin_channel::codec::encode_typed(PACK_FRAME, &inner)
        .map_err(|e| origin_network::error::NetworkError::Codec(e.to_string()))?;
    sock.send_to(&frame, peer)
        .await
        .map(|_| ())
        .map_err(|e| origin_network::error::NetworkError::Transport(e.to_string()))
}
