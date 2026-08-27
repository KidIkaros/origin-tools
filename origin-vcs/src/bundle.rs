// SPDX-License-Identifier: Apache-2.0

//! Single-file bundle exchange (git-bundle style).
//!
//! A bundle packs the reachable object set + branch/tag tips into one portable
//! file, so a repository can be moved without a network or a directory remote:
//!
//! ```text
//! magic "OVCSBND1" (8) ‖ [u32 len ‖ manifest.json] ‖ [u32 len ‖ envelope]* ‖ [u32 0]
//! ```
//!
//! Envelopes are verbatim encrypted bytes (key-agnostic addresses), so any
//! repo under the same key-source can import them. `bundle verify` checks every
//! listed envelope is present and decryptable without importing.

use std::io::{Read, Write};
use std::path::Path;

use crate::remote::RemoteManifest;
use crate::store::Store;

pub const BUNDLE_MAGIC: &[u8; 8] = b"OVCSBND1";

/// Parsed bundle payload: (hex object id, envelope bytes), ordered per the
/// manifest's `object_ids`.
type BundleObjects = Vec<(String, Vec<u8>)>;

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), String> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => return Err("unexpected end of bundle".to_string()),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    Ok(())
}

/// Write a bundle of the store's reachable objects + refs to `path`.
pub fn create(store: &Store, path: &Path) -> Result<RemoteManifest, String> {
    let reachable = store.reachable_from_refs(&store.meta().branches, &store.meta().tags, &[])?;
    let manifest = RemoteManifest {
        branches: store.meta().branches.clone(),
        tags: store.meta().tags.clone(),
        object_ids: reachable.iter().map(hex::encode).collect(),
        force: false,
    };

    let tmp = path.with_extension("tmp");
    let mut w = std::io::BufWriter::new(
        std::fs::File::create(&tmp).map_err(|e| format!("create {:?}: {e}", tmp.display()))?,
    );
    w.write_all(BUNDLE_MAGIC)
        .map_err(|e| format!("write magic: {e}"))?;

    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|e| format!("manifest ser: {e}"))?;
    w.write_all(&(manifest_bytes.len() as u32).to_be_bytes())
        .map_err(|e| format!("write manifest len: {e}"))?;
    w.write_all(&manifest_bytes)
        .map_err(|e| format!("write manifest: {e}"))?;

    for id in &reachable {
        let bytes = store.envelope_bytes(id)?;
        w.write_all(&(bytes.len() as u32).to_be_bytes())
            .map_err(|e| format!("write obj len: {e}"))?;
        w.write_all(&bytes).map_err(|e| format!("write obj: {e}"))?;
    }
    w.write_all(&0u32.to_be_bytes())
        .map_err(|e| format!("write terminator: {e}"))?;
    w.flush().map_err(|e| format!("flush: {e}"))?;
    drop(w);
    std::fs::rename(&tmp, path).map_err(|e| format!("finalize {:?}: {e}", path.display()))?;
    Ok(manifest)
}

/// Parse a bundle file into its manifest + object envelopes.
fn parse_bundle(path: &Path) -> Result<(RemoteManifest, BundleObjects), String> {
    let mut r = std::io::BufReader::new(
        std::fs::File::open(path).map_err(|e| format!("open {:?}: {e}", path.display()))?,
    );
    let mut magic = [0u8; 8];
    read_full(&mut r, &mut magic)?;
    if &magic != BUNDLE_MAGIC {
        return Err("not an origin-vcs bundle (bad magic)".to_string());
    }

    let mut len_buf = [0u8; 4];
    read_full(&mut r, &mut len_buf)?;
    let mlen = u32::from_be_bytes(len_buf) as usize;
    let mut mbytes = vec![0u8; mlen];
    read_full(&mut r, &mut mbytes)?;
    let manifest: RemoteManifest =
        serde_json::from_slice(&mbytes).map_err(|e| format!("manifest parse: {e}"))?;

    let mut envelopes: Vec<Vec<u8>> = Vec::new();
    loop {
        read_full(&mut r, &mut len_buf)?;
        let olen = u32::from_be_bytes(len_buf) as usize;
        if olen == 0 {
            break;
        }
        let mut bytes = vec![0u8; olen];
        read_full(&mut r, &mut bytes)?;
        envelopes.push(bytes);
    }
    // Envelopes are ordered per manifest.object_ids.
    let mut pairs = Vec::new();
    for (i, bytes) in envelopes.into_iter().enumerate() {
        let hexid = manifest
            .object_ids
            .get(i)
            .ok_or_else(|| format!("bundle has more objects than manifest ({i})"))?
            .clone();
        pairs.push((hexid, bytes));
    }
    Ok((manifest, pairs))
}

/// Import a bundle into the store: all object envelopes + tracking refs under
/// `refs/remotes/<bundle_name>/<branch>` (signed with the local identity).
pub fn import(
    store: &mut Store,
    ks: &crate::crypto::KeySource,
    path: &Path,
    bundle_name: &str,
) -> Result<RemoteManifest, String> {
    let (manifest, pairs) = parse_bundle(path)?;
    for (hexid, bytes) in &pairs {
        let id = hex_to_id(hexid)?;
        store.put_envelope_bytes(&id, bytes)?;
    }
    let bundle = ks.signing_bundle()?;
    for (b, id) in &manifest.branches {
        let tracking = format!("{bundle_name}/{b}");
        let sig = crate::crypto::Signature::sign(&bundle, id);
        store.write_ref("remotes", &tracking, *id, &sig)?;
        store.update_mem_ref("remotes", &tracking, *id);
    }
    Ok(manifest)
}

/// Verify a bundle's object set is present and decryptable in the store.
pub fn verify(store: &Store, path: &Path) -> Result<RemoteManifest, String> {
    let (manifest, pairs) = parse_bundle(path)?;
    let mut ok = 0usize;
    for (hexid, bytes) in &pairs {
        let id = hex_to_id(hexid)?;
        let stored = store.envelope_bytes(&id)?;
        if stored != *bytes {
            return Err(format!(
                "bundle object {} differs from store",
                short_id(&id)
            ));
        }
        // Decrypt to prove the key matches and the envelope is intact.
        store
            .read(&id)
            .map_err(|e| format!("bundle object {} not decryptable: {e}", short_id(&id)))?;
        ok += 1;
    }
    println!(
        "bundle OK: {} objects present and decryptable, branches: {}",
        ok,
        manifest.branches.len()
    );
    Ok(manifest)
}

fn hex_to_id(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("bad id hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("id must be 32 bytes, got {}", bytes.len()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn short_id(id: &[u8; 32]) -> String {
    hex::encode(&id[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_length() {
        assert_eq!(BUNDLE_MAGIC.len(), 8);
    }
}
