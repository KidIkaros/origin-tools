// SPDX-License-Identifier: Apache-2.0

//! Object store — encrypted-at-rest, content-addressed persistence.
//!
//! Every object (blob/tree/commit/tag) is wrapped in an origin-common
//! `Envelope` (XChaCha20-Poly1305 with an AAD-authenticated header) under a
//! single domain-derived key, and stored under its SHA3-256 plaintext address.
//! Refs, the index, and the MMR checkpoint are likewise encrypted; only
//! non-secret config stays clear.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use origin_common::{atomic_write, MemoryTier};

use crate::mmr::MmrState;
use crate::object::{
    commit_address, tag_address, tree_address, Blob, Commit, ObjectKind, Tag, Tree,
};

/// The per-tool domain used to derive the object-encryption key from the suite
/// identity (HKDF-BLAKE3 domain separation). Changing it invalidates the store.
pub const KEY_DOMAIN: &str = "origin-vcs::objects";

/// A signed entity on disk (ref, tag) — holds the target id + signature.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignedRef {
    pub target: [u8; 32],
    pub signature: crate::crypto::Signature,
}

/// In-memory view of the repository metadata.
#[derive(Debug, Clone, Default)]
pub struct RepoMeta {
    pub head: Option<String>, // branch name
    pub branches: BTreeMap<String, [u8; 32]>,
    pub tags: BTreeMap<String, [u8; 32]>,
    pub mmr: MmrState,
}

/// Per-repository non-secret configuration (stored as `config.toml`).
///
/// `encrypt` records how the object-encryption key is derived:
///  - `"identity"` (default): HKDF-BLAKE3 over the suite identity seed
///    (domain-separated), so any repo you open under the same identity can
///    reproduce the key deterministically without extra input.
///  - `"passphrase"`: Argon2id over a user passphrase + a per-repo random
///    salt (stored here, non-secret). The salt is required to re-derive the
///    key on open.
///
/// Signing/verification is unaffected: commit/tag/ref signatures still use the
/// suite identity (`--identity`) or `--seed`; this only governs at-rest
/// object encryption.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RepoConfig {
    pub encrypt: String,
    pub salt: Option<String>,
    pub default_branch: Option<String>,
    /// Argon2id memory tier used for passphrase-mode key derivation
    /// ("nano" | "standard" | "sovereign"). Ignored in identity mode.
    #[serde(default = "default_tier")]
    pub tier: String,
}

fn default_tier() -> String {
    "nano".into()
}

impl Default for RepoConfig {
    fn default() -> Self {
        RepoConfig {
            encrypt: "identity".into(),
            salt: None,
            default_branch: None,
            tier: "nano".into(),
        }
    }
}

/// Read `config.json` for a store rooted at `root`; defaults to identity mode.
pub fn read_repo_config(root: &Path) -> Result<RepoConfig, String> {
    match std::fs::read(root.join("config.json")) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("config parse: {e}")),
        Err(_) => Ok(RepoConfig::default()),
    }
}

/// Write `config.json` for a store rooted at `root`.
pub fn write_repo_config(root: &Path, cfg: &RepoConfig) -> Result<(), String> {
    let body = serde_json::to_vec(cfg).map_err(|e| format!("config ser: {e}"))?;
    atomic_write(&root.join("config.json"), &body).map_err(|e| format!("write config: {e}"))
}

/// Compute the object-encryption key for a repo, honouring its recorded
/// encrypt mode. `ks` supplies the identity/seed path; a `"passphrase"`-mode
/// repo derives the key from Argon2id over the configured salt + the supplied
/// passphrase (read from `passphrase_file` or frrompted).
pub fn repo_storage_key(root: &Path, ks: &crate::crypto::KeySource) -> Result<[u8; 32], String> {
    let cfg = read_repo_config(root)?;
    match cfg.encrypt.as_str() {
        "identity" => ks.storage_key(),
        "passphrase" => {
            let slug = cfg
                .salt
                .ok_or_else(|| "repo config missing salt for passphrase mode".to_string())?;
            let salt_bytes = hex::decode(&slug).map_err(|e| format!("config salt hex: {e}"))?;
            if salt_bytes.len() != 16 {
                return Err(format!(
                    "config salt must be 16 bytes, got {}",
                    salt_bytes.len()
                ));
            }
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&salt_bytes);
            let passphrase = ks
                .passphrase()
                .ok_or_else(|| {
                    "passphrase-mode store needs a passphrase (--passphrase-file)".to_string()
                })
                .map(|s| s.to_string())?;
            let tier = origin_common::tier_from_str(&cfg.tier)
                .map_err(|e| format!("config tier '{}': {e}", cfg.tier))?;
            let params = tier.argon2_params(32);
            let builder = origin_crypto_sdk::kdf::Argon2idBuilder::new()
                .memory_kib(params.m_cost())
                .iterations(params.t_cost())
                .parallelism(params.p_cost());
            let key = builder
                .derive(passphrase.as_bytes(), &salt)
                .map_err(|e| format!("Argon2id failed: {e:?}"))?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key[..32]);
            Ok(arr)
        }
        other => Err(format!("unknown config.encrypt mode: {other}")),
    }
}

pub struct Store {
    root: PathBuf,
    objects: PathBuf,
    refs: PathBuf,
    index_path: PathBuf,
    meta: RepoMeta,
    key: [u8; 32],
    /// Optional exclusive advisory lock held for the lifetime of this store
    /// handle. When present, concurrent writers/readers that also lock block
    /// until it is dropped, preventing index/refs/MMR races.
    _lock: Option<std::fs::File>,
}

/// Parse a 64-char hex string into a 32-byte object id.
fn id_from_hex_str(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("bad id hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("id must be 32 bytes, got {}", bytes.len()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// Intermediate bucket while bucketing a flat tree's paths into nested
/// subtrees (write path of [Store::write_tree]).
#[derive(Default)]
struct Bucket {
    /// Entries whose path terminates here (leaf name → entry).
    leaves: Vec<(String, crate::object::TreeEntry)>,
    /// Sub-buckets by the next path segment.
    subs: std::collections::BTreeMap<String, Bucket>,
}

/// Split a flat path map into nested buckets by '/'. Empty directory
/// entries are unrepresentable (same as the flat model).
fn bucketize(entries: &BTreeMap<String, crate::object::TreeEntry>) -> Bucket {
    let mut root = Bucket::default();
    for (rel, entry) in entries {
        let mut cur = &mut root;
        let parts: Vec<&str> = rel.split('/').collect();
        for (i, part) in parts.iter().enumerate() {
            if i + 1 == parts.len() {
                cur.leaves.push((part.to_string(), entry.clone()));
            } else {
                cur = cur.subs.entry(part.to_string()).or_default();
            }
        }
    }
    root
}

impl Store {
    /// Open (or initialize) a repository store rooted at `root`.
    /// `key` is the 32-byte object-encryption key (derived from the suite
    /// identity by the caller, or from a passphrase).
    pub fn open(root: &Path, key: [u8; 32]) -> Result<Self, String> {
        let objects = root.join("objects");
        let refs = root.join("refs");
        std::fs::create_dir_all(&objects).map_err(|e| format!("store dir: {e}"))?;
        std::fs::create_dir_all(&refs).map_err(|e| format!("refs dir: {e}"))?;
        Ok(Store {
            root: root.to_path_buf(),
            objects,
            refs,
            index_path: root.join("index.env"),
            meta: RepoMeta::default(),
            key,
            _lock: None,
        })
    }

    /// Acquire an exclusive advisory lock on this store as a `File` handle
    /// (held in the returned `Store`). Blocks until any concurrent holder
    /// releases their lock, then returns a store that owns the lock. Drop the
    /// store (or the lock handle) to release.
    ///
    /// Uses an flock on `root/lock`; on non-Unix platforms it falls back to an
    /// empty lock file with no enforcement (still safe, but not exclusive).
    pub fn open_locked(root: &Path, key: [u8; 32]) -> Result<Store, String> {
        let mut store = Self::open(root, key)?;
        let lock_path = root.join("lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| format!("open lock file {:?}: {e}", lock_path))?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(format!(
                    "could not lock store {:?} (another process active?): {}",
                    root.display(),
                    std::io::Error::last_os_error()
                ));
            }
        }
        store._lock = Some(file);
        Ok(store)
    }

    /// Whether this handle holds an exclusive store lock.
    pub fn is_locked(&self) -> bool {
        self._lock.is_some()
    }

    /// Root of the store directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    // ------------------------------------------------------------------
    // repository config (encrypt mode, salt, default branch)
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // repository config (encrypt mode, salt, default branch)
    // ------------------------------------------------------------------

    /// Read `config.json` atomically.
    pub fn read_config(&self) -> Result<RepoConfig, String> {
        read_repo_config(&self.root)
    }

    /// Write `config.json` atomically.
    pub fn write_config(&self, cfg: &RepoConfig) -> Result<(), String> {
        write_repo_config(&self.root, cfg)
    }

    /// Compute the object-encryption key for this repo, honouring its recorded
    /// encrypt mode (see [repo_storage_key]). Passphrase-mode repos read the
    /// passphrase from [KeySource::passphrase].
    pub fn storage_key_for(&self, ks: &crate::crypto::KeySource) -> Result<[u8; 32], String> {
        repo_storage_key(&self.root, ks)
    }

    // ------------------------------------------------------------------
    // key derivation (suite-identity path)
    // ------------------------------------------------------------------

    /// Derive the object-encryption key from the master identity seed using
    /// HKDF-BLAKE3 domain separation (mirrors `origin-seal key_from_identity`).
    pub fn derive_key_from_seed(seed: &[u8; 32]) -> Result<[u8; 32], String> {
        let mut okm = [0u8; 32];
        origin_crypto_sdk::hkdf_blake3(seed, None, KEY_DOMAIN.as_bytes(), &mut okm)
            .map_err(|e| format!("HKDF key derivation failed: {e}"))?;
        Ok(okm)
    }

    // ------------------------------------------------------------------
    // object addressing / persistence
    // ------------------------------------------------------------------

    fn fanout(id: &[u8; 32]) -> (String, String) {
        let h = hex::encode(id);
        (h[..2].to_string(), h[2..].to_string())
    }

    fn object_path(&self, id: &[u8; 32]) -> PathBuf {
        let (dir, rest) = Self::fanout(id);
        self.objects.join(dir).join(format!("{rest}.env"))
    }

    /// Store an object's canonical plaintext, encrypted, returning its address.
    pub fn put(&self, kind: ObjectKind, plaintext: &[u8]) -> Result<[u8; 32], String> {
        let id = match kind {
            ObjectKind::Blob => crate::object::blob_address(&Blob::new(plaintext.to_vec())),
            ObjectKind::Tree => {
                let tree: Tree =
                    serde_json::from_slice(plaintext).map_err(|e| format!("tree: {e}"))?;
                tree_address(&tree)
            }
            ObjectKind::Commit => {
                let c: Commit =
                    serde_json::from_slice(plaintext).map_err(|e| format!("commit:{e}"))?;
                commit_address(&c)
            }
            ObjectKind::Tag => {
                let t: Tag = serde_json::from_slice(plaintext).map_err(|e| format!("tag:{e}"))?;
                tag_address(&t)
            }
        };
        self.put_raw(&id, plaintext)?;
        Ok(id)
    }

    /// Store envelope bytes keyed by an already-computed plaintext address.
    pub fn put_raw(&self, id: &[u8; 32], plaintext: &[u8]) -> Result<(), String> {
        let (dir, rest) = Self::fanout(id);
        let dirp = self.objects.join(&dir);
        std::fs::create_dir_all(&dirp).map_err(|e| format!("obj dir: {e}"))?;
        let bytes = self.encrypt(plaintext)?;
        let path = dirp.join(format!("{rest}.env"));
        atomic_write(&path, &bytes).map_err(|e| format!("write obj: {e}"))
    }

    /// Read an envelope file verbatim (no decrypt) by address.
    pub fn envelope_bytes(&self, id: &[u8; 32]) -> Result<Vec<u8>, String> {
        let path = self.object_path(id);
        std::fs::read(&path).map_err(|e| format!("read {}: {e}", hex::encode(id)))
    }

    /// Read an envelope by address and decrypt.
    pub fn read(&self, id: &[u8; 32]) -> Result<Vec<u8>, String> {
        let path = self.object_path(id);
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", hex::encode(id)))?;
        self.decrypt(&bytes)
    }

    /// Encrypt canonical plaintext into an envelope.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let env = origin_common::Envelope::encrypt(
            plaintext,
            &self.key,
            MemoryTier::Nano,
            origin_common::PayloadType::File,
            false, // do not compress, keep addresses stable to plaintext
        )
        .map_err(|e| format!("env encrypt: {e}"))?;
        Ok(env.to_bytes())
    }

    /// Decrypt an envelope, authenticating its header.
    fn decrypt(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let env =
            origin_common::Envelope::from_bytes(bytes).map_err(|e| format!("env parse: {e}"))?;
        env.decrypt(&self.key)
            .map_err(|e| format!("env auth/decrypt failed: {e}"))
    }

    // ------------------------------------------------------------------
    // high-level object accessors
    // ------------------------------------------------------------------

    pub fn write_blob(&self, data: &[u8]) -> Result<[u8; 32], String> {
        let blob = Blob::new(data.to_vec());
        let id = crate::object::blob_address(&blob);
        // The envelope stores the raw bytes directly; addressing already binds
        // the type+length header. Keeping them opaque is fine since `read`
        // authenticates the envelope.
        self.put_raw(&id, data)?;
        Ok(id)
    }

    pub fn read_blob(&self, id: &[u8; 32]) -> Result<Blob, String> {
        let path = self.object_path(id);
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", hex::encode(id)))?;
        if crate::stream::is_streamed(&bytes) {
            let data = crate::stream::stream_decrypt_to_vec(&self.key, &path)?;
            Ok(Blob::new(data))
        } else {
            Ok(Blob::new(self.decrypt(&bytes)?))
        }
    }

    /// Stream a blob to `dest` with bounded memory (Phase 12). Auto-detects
    /// streamed (`OVCS`) vs regular (`ORGN`) envelopes.
    pub fn read_blob_to_path(&self, id: &[u8; 32], dest: &Path) -> Result<(), String> {
        let path = self.object_path(id);
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", hex::encode(id)))?;
        if crate::stream::is_streamed(&bytes) {
            crate::stream::stream_decrypt_to_file(&self.key, &path, dest)
                .map(|_| ())
                .map_err(|e| format!("stream blob {}: {e}", hex::encode(id)))
        } else {
            let plain = self.decrypt(&bytes)?;
            atomic_write(dest, &plain).map_err(|e| format!("write {:?}: {e}", dest.display()))
        }
    }

    /// Store a blob by streaming the file into a chunked (`OVCS`) envelope,
    /// returning its content address (Phase 12). Bounded memory.
    pub fn write_blob_stream(&self, path: &Path, chunk_size: usize) -> Result<[u8; 32], String> {
        let id = crate::stream::stream_blob_id(path)?;
        let dest = self.object_path(&id);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("obj dir: {e}"))?;
        }
        crate::stream::stream_encrypt_file(&self.key, path, &dest, chunk_size)?;
        Ok(id)
    }

    /// Write a tree as **nested** tree objects (git-style subtrees): paths
    /// are bucketed by their first path segment and each subtree becomes
    /// its own content-addressed object. In-memory trees stay flat — this
    /// only changes the on-disk object graph (large trees don't become one
    /// giant object; identical subtrees dedupe by id).
    pub fn write_tree(&self, tree: &Tree) -> Result<[u8; 32], String> {
        self.write_tree_bucket(&bucketize(&tree.entries))
    }

    /// Recursively write a bucket (one subtree) and return its address.
    fn write_tree_bucket(&self, b: &Bucket) -> Result<[u8; 32], String> {
        let mut rows: Vec<(String, String, String)> =
            Vec::with_capacity(b.leaves.len() + b.subs.len());
        for (name, sub) in &b.subs {
            let id = self.write_tree_bucket(sub)?;
            rows.push((format!("{name}/"), "tree".into(), hex::encode(id)));
        }
        for (name, entry) in &b.leaves {
            rows.push((
                name.clone(),
                entry.mode.as_str().to_string(),
                hex::encode(entry.id),
            ));
        }
        rows.sort();
        let obj = crate::object::TreeObject {
            v: 2,
            entries: rows,
        };
        let body = serde_json::to_vec(&obj).map_err(|e| format!("tree ser: {e}"))?;
        // Address binds type + length so it can be recomputed without
        // deserializing (same wire form as the other object kinds).
        let mut wire = Vec::with_capacity(5 + body.len());
        wire.extend_from_slice(b"tree");
        wire.push(0);
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(&body);
        let id = origin_crypto_sdk::sha3_256(&wire);
        self.put_raw(&id, &body)?;
        Ok(id)
    }

    /// Read a tree back into the flat in-memory form. Accepts both the
    /// current nested (v2) objects — recursively flattened — and the
    /// legacy flat `Tree` JSON written by earlier versions.
    pub fn read_tree(&self, id: &[u8; 32]) -> Result<Tree, String> {
        let bytes = self.read(id)?;
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("decoded tree: {e}"))?;
        if v.get("v").and_then(|x| x.as_u64()) == Some(2) {
            let obj: crate::object::TreeObject =
                serde_json::from_value(v).map_err(|e| format!("decoded tree: {e}"))?;
            let mut out = Tree::new();
            self.flatten_rows(&obj.entries, "", &mut out.entries)?;
            Ok(out)
        } else {
            serde_json::from_value(v).map_err(|e| format!("decoded tree: {e}"))
        }
    }

    /// Flatten nested tree rows into the flat path map, recursing into
    /// subtree objects on demand.
    fn flatten_rows(
        &self,
        rows: &[(String, String, String)],
        prefix: &str,
        out: &mut BTreeMap<String, crate::object::TreeEntry>,
    ) -> Result<(), String> {
        for (name, kind, hexid) in rows {
            let id = id_from_hex_str(hexid)?;
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if kind == "tree" {
                // Subtree row: recurse into the subtree object.
                let rel = rel.trim_end_matches('/');
                let bytes = self.read(&id)?;
                let v: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|e| format!("subtree: {e}"))?;
                let sub: crate::object::TreeObject =
                    serde_json::from_value(v).map_err(|e| format!("subtree: {e}"))?;
                self.flatten_rows(&sub.entries, rel, out)?;
            } else {
                let mode = crate::object::FileMode::from_name(kind)?;
                out.insert(rel, crate::object::TreeEntry { mode, id });
            }
        }
        Ok(())
    }

    /// Direct child object ids of a tree object: blob ids for the legacy
    /// flat form, and blob + subtree-object ids for the nested v2 form.
    /// Reachability walks (`gc`, `push`) use this so intermediate subtree
    /// objects are never pruned as "unreachable".
    pub fn tree_object_children(&self, id: &[u8; 32]) -> Result<Vec<[u8; 32]>, String> {
        let bytes = self.read(id)?;
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("tree: {e}"))?;
        let mut out = Vec::new();
        if v.get("v").and_then(|x| x.as_u64()) == Some(2) {
            let obj: crate::object::TreeObject =
                serde_json::from_value(v).map_err(|e| format!("tree: {e}"))?;
            for (_, _, hexid) in &obj.entries {
                out.push(id_from_hex_str(hexid)?);
            }
        } else {
            let t: Tree = serde_json::from_value(v).map_err(|e| format!("tree: {e}"))?;
            out.extend(t.entries.values().map(|e| e.id));
        }
        Ok(out)
    }

    /// Store a commit plus its signature (self-describing). The content address
    /// is the bare [Commit], so embedding the signature never changes dedupe.
    pub fn write_commit(
        &self,
        commit: &Commit,
        sig: &crate::crypto::Signature,
    ) -> Result<[u8; 32], String> {
        let id = commit_address(commit);
        let record = crate::object::CommitRecord {
            commit: commit.clone(),
            signature: sig.clone(),
        };
        let body = serde_json::to_vec(&record).map_err(|e| format!("commit ser: {e}"))?;
        self.put_raw(&id, &body)?;
        Ok(id)
    }

    /// Read a commit and its embedded signature.
    pub fn read_commit_record(&self, id: &[u8; 32]) -> Result<crate::object::CommitRecord, String> {
        let bytes = self.read(id)?;
        serde_json::from_slice(&bytes).map_err(|e| format!("decoded commit: {e}"))
    }

    pub fn read_commit(&self, id: &[u8; 32]) -> Result<Commit, String> {
        Ok(self.read_commit_record(id)?.commit)
    }

    pub fn write_tag(&self, tag: &Tag) -> Result<[u8; 32], String> {
        let id = tag_address(tag);
        let body = serde_json::to_vec(tag).map_err(|e| format!("tag ser: {e}"))?;
        self.put_raw(&id, &body)?;
        Ok(id)
    }
    pub fn read_tag(&self, id: &[u8; 32]) -> Result<Tag, String> {
        let bytes = self.read(id)?;
        serde_json::from_slice(&bytes).map_err(|e| format!("decoded tag: {e}"))
    }

    pub fn object_exists(&self, id: &[u8; 32]) -> bool {
        self.object_path(id).exists()
    }

    /// All object addresses currently present in the store (parsed from the
    /// fan-out filenames). Used by `gc` to know which envelopes exist.
    pub fn all_object_ids(&self) -> Result<Vec<[u8; 32]>, String> {
        let mut out = Vec::new();
        if !self.objects.is_dir() {
            return Ok(out);
        }
        for entry in std::fs::read_dir(&self.objects).map_err(|e| format!("objects dir: {e}"))? {
            let entry = entry.map_err(|e| format!("objects entry: {e}"))?;
            if !entry.path().is_dir() {
                continue;
            }
            let dir_name = entry.file_name().to_string_lossy().to_string();
            if dir_name.len() != 2 {
                continue;
            }
            for f in std::fs::read_dir(entry.path()).map_err(|e| format!("fanout dir: {e}"))? {
                let f = f.map_err(|e| format!("fanout entry: {e}"))?;
                let name = f.file_name().to_string_lossy().to_string();
                let rest = name.strip_suffix(".env").unwrap_or(&name);
                if rest.len() != 62 {
                    continue;
                }
                let hexs = format!("{dir_name}{rest}");
                if let Ok(bytes) = hex::decode(&hexs) {
                    if bytes.len() == 32 {
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&bytes);
                        out.push(id);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Delete a single object envelope from the store (used by `gc`).
    pub fn delete_object(&self, id: &[u8; 32]) -> Result<bool, String> {
        let path = self.object_path(id);
        if !path.exists() {
            return Ok(false);
        }
        std::fs::remove_file(&path)
            .map_err(|e| format!("delete object {}: {e}", hex::encode(id)))?;
        Ok(true)
    }

    /// Import an encrypted object envelope (bytes verbatim) from a remote's
    /// object store rooted at `src_objects`. Content addressing means the id
    /// and path are key-agnostic; a remote clone owned by the same key-source
    /// can be mirrored byte-for-byte. Returns false if the envelope was
    /// already present or missing.
    pub fn import_object(&self, id: &[u8; 32], src_objects: &Path) -> Result<bool, String> {
        if self.object_exists(id) {
            return Ok(false);
        }
        let (dir, rest) = Self::fanout(id);
        let src = src_objects.join(dir).join(format!("{rest}.env"));
        let bytes = std::fs::read(&src).map_err(|e| format!("read remote obj: {e}"))?;
        self.put_envelope_bytes(id, &bytes)
    }

    /// Write an object envelope file directly from bytes (used by remote
    /// import and bundle import). Returns false if already present.
    pub fn put_envelope_bytes(&self, id: &[u8; 32], bytes: &[u8]) -> Result<bool, String> {
        if self.object_exists(id) {
            return Ok(false);
        }
        let (dir, rest) = Self::fanout(id);
        let dirp = self.objects.join(dir);
        std::fs::create_dir_all(&dirp).map_err(|e| format!("obj dir: {e}"))?;
        atomic_write(&dirp.join(format!("{rest}.env")), bytes)
            .map_err(|e| format!("write obj: {e}"))?;
        Ok(true)
    }

    /// Copy an object's encrypted envelope to the destination path (used by
    /// remotes). The envelope bytes are copied verbatim so the address is
    /// preserved across machines without the storage key.
    pub fn export_object(&self, id: &[u8; 32], dest: &Path) -> Result<(), String> {
        let src = self.object_path(id);
        let bytes = std::fs::read(&src).map_err(|e| format!("read {}: {e}", hex::encode(id)))?;
        std::fs::create_dir_all(dest).map_err(|e| format!("mkdir {:?}: {e}", dest.display()))?;
        let (dir, rest) = Self::fanout(id);
        let dirp = dest.join(dir);
        std::fs::create_dir_all(&dirp).map_err(|e| format!("obj dir: {e}"))?;
        atomic_write(&dirp.join(format!("{rest}.env")), &bytes)
            .map_err(|e| format!("write obj: {e}"))
    }

    // ------------------------------------------------------------------
    // refs / index / metadata (encrypted)
    // ------------------------------------------------------------------

    pub fn meta(&self) -> &RepoMeta {
        &self.meta
    }
    pub fn meta_mut(&mut self) -> &mut RepoMeta {
        &mut self.meta
    }

    pub fn write_ref(
        &mut self,
        category: &str,
        name: &str,
        target: [u8; 32],
        signature: &crate::crypto::Signature,
    ) -> Result<(), String> {
        let dir = self.refs.join(category);
        std::fs::create_dir_all(&dir).map_err(|e| format!("refs dir: {e}"))?;
        let signed = SignedRef {
            target,
            signature: signature.clone(),
        };
        let plaintext = serde_json::to_vec(&signed).map_err(|e| format!("signed ref ser: {e}"))?;
        let bytes = self.encrypt(&plaintext)?;
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| format!("refs parent: {e}"))?;
            }
        }
        atomic_write(&path, &bytes).map_err(|e| format!("write ref {name}: {e}"))
    }

    pub fn update_mem_ref(&mut self, category: &str, name: &str, id: [u8; 32]) {
        match category {
            "heads" => {
                self.meta.branches.insert(name.to_string(), id);
            }
            "tags" => {
                self.meta.tags.insert(name.to_string(), id);
            }
            _ => {}
        }
    }

    pub fn read_ref(&self, category: &str, name: &str) -> Result<[u8; 32], String> {
        Ok(self.read_ref_signed(category, name)?.target)
    }

    /// Read a ref envelope back with its signature (used by `verify` to
    /// re-check the signed target).
    pub fn read_ref_signed(&self, category: &str, name: &str) -> Result<SignedRef, String> {
        let path = self.refs.join(category).join(name);
        let bytes = std::fs::read(&path).map_err(|e| format!("read ref {name}: {e}"))?;
        let signed: SignedRef = serde_json::from_slice(&self.decrypt(&bytes)?)
            .map_err(|e| format!("ref parse: {e}"))?;
        Ok(signed)
    }

    /// Sign and write HEAD as a HEAD-sentinel plus branch pointer (we store the
    /// branch name in clear config; the branch itself is the signed ref).
    pub fn set_head(&mut self, branch: Option<String>) -> Result<(), String> {
        self.meta.head = branch.clone();
        match branch {
            Some(b) => atomic_write(&self.root.join("HEAD"), b.as_bytes())
                .map_err(|e| format!("HEAD: {e}")),
            None => atomic_write(&self.root.join("HEAD"), b"-").map_err(|e| format!("HEAD: {e}")),
        }
    }

    pub fn head_branch(&self) -> Result<Option<String>, String> {
        let raw = std::fs::read(self.root.join("HEAD")).map_err(|e| format!("read HEAD: {e}"))?;
        let s = String::from_utf8_lossy(&raw).trim().to_string();
        if s == "-" {
            Ok(None)
        } else {
            Ok(Some(s))
        }
    }

    /// Load metadata back from disk (refs + HEAD) into `meta`.
    pub fn load_meta(&mut self) -> Result<(), String> {
        self.meta.head = self.head_branch()?;
        self.meta.branches.clear();
        self.meta.tags.clear();
        let heads = self.refs.join("heads");
        if heads.is_dir() {
            for e in std::fs::read_dir(&heads).map_err(|e| format!("refs heads: {e}"))? {
                let e = e.map_err(|e| format!("refs entry: {e}"))?;
                let name = e.file_name().to_string_lossy().to_string();
                let id = self.read_ref("heads", &name)?;
                self.meta.branches.insert(name, id);
            }
        }
        let tags = self.refs.join("tags");
        if tags.is_dir() {
            for e in std::fs::read_dir(&tags).map_err(|e| format!("refs tags: {e}"))? {
                let e = e.map_err(|e| format!("refs entry: {e}"))?;
                let name = e.file_name().to_string_lossy().to_string();
                let id = self.read_ref("tags", &name)?;
                self.meta.tags.insert(name, id);
            }
        }
        self.load_mmr();
        Ok(())
    }

    // ------------------------------------------------------------------
    // MMR persistence
    // ------------------------------------------------------------------

    fn mmr_path(&self) -> PathBuf {
        self.root.join("mmr.json")
    }
    fn load_mmr(&mut self) {
        let path = self.mmr_path();
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(json) = std::str::from_utf8(&bytes) {
                if let Ok(m) = serde_json::from_str::<MmrState>(json) {
                    self.meta.mmr = m;
                }
            }
        }
    }
    fn save_mmr(&self) -> Result<(), String> {
        let json = serde_json::to_string(&self.meta.mmr).map_err(|e| format!("mmr ser: {e}"))?;
        atomic_write(&self.mmr_path(), json.as_bytes()).map_err(|e| format!("mmr: {e}"))
    }

    /// Append a commit id to both the append-only commit log and the MMR, then
    /// persist. Returns the leaf index (append order).
    pub fn append_commit_leaf(&mut self, id: &[u8; 32]) -> Result<u64, String> {
        let idx = self.meta.mmr.append(id);
        self.save_mmr()?;
        // Keep the explicit order so we can replay and verify membership.
        let mut log = self.commit_log()?;
        log.push(*id);
        let json = serde_json::to_string(&log).map_err(|e| format!("log ser: {e}"))?;
        atomic_write(&self.root.join("commit-log.json"), json.as_bytes())
            .map_err(|e| format!("commit log: {e}"))?;
        Ok(idx)
    }

    /// Ordered ids of every commit appended so far.
    pub fn commit_log(&self) -> Result<Vec<[u8; 32]>, String> {
        let path = self.root.join("commit-log.json");
        match std::fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| format!("commit log parse: {e}"))
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Rebuild the MMR root from the explicit commit order and compare to the
    /// persisted root. Returns the recomputed root for callers to check.
    pub fn recompute_mmr_root_from_log(&self) -> Result<[u8; 32], String> {
        let mut acc = MmrState::new();
        for id in self.commit_log()? {
            acc.append(&id);
        }
        Ok(acc.root())
    }

    pub fn mmr_root(&self) -> [u8; 32] {
        self.meta.mmr.root()
    }
    pub fn mmr(&self) -> &MmrState {
        &self.meta.mmr
    }

    /// Compute the set of all object addresses reachable from the given branch
    /// and tag refs (plus an optional extra seed like HEAD). Walks
    /// commits → trees → blobs and tag targets. Reused by `gc` (prune the
    /// complement) and `push` (select which objects to export).
    ///
    /// Missing parents (a shallow clone's boundary) are treated as leaves, so
    /// the walk is safe on truncated history: gc keeps whatever is present
    /// and push exports exactly the objects that exist.
    pub fn reachable_from_refs(
        &self,
        branches: &BTreeMap<String, [u8; 32]>,
        tags: &BTreeMap<String, [u8; 32]>,
        extra: &[[u8; 32]],
    ) -> Result<BTreeSet<[u8; 32]>, String> {
        self.walk_reachable(branches, tags, extra, true)
    }

    /// Like [Self::reachable_from_refs], but commits do NOT enqueue their
    /// parents: the result is each tip commit + its tree closure, with no
    /// ancestor history. Served by `fetch` when the client asks for a
    /// shallow clone (`clone --shallow`).
    pub fn shallow_reachable(
        &self,
        branches: &BTreeMap<String, [u8; 32]>,
        tags: &BTreeMap<String, [u8; 32]>,
        extra: &[[u8; 32]],
    ) -> Result<BTreeSet<[u8; 32]>, String> {
        self.walk_reachable(branches, tags, extra, false)
    }

    /// Reachability walk limited to `depth` ancestor generations from the
    /// ref tips (depth 1 = tips only, like a shallow fetch). Returns the
    /// object set and the boundary tips — the commits at the deepest level
    /// whose parents were NOT followed (their parents are absent from the
    /// store, which is what marks a clone shallow).
    #[allow(clippy::type_complexity)]
    pub fn depth_reachable(
        &self,
        branches: &BTreeMap<String, [u8; 32]>,
        tags: &BTreeMap<String, [u8; 32]>,
        extra: &[[u8; 32]],
        depth: usize,
    ) -> Result<(BTreeSet<[u8; 32]>, Vec<[u8; 32]>), String> {
        let depth = depth.max(1);
        let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut objects: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut boundary: Vec<[u8; 32]> = Vec::new();
        let mut queue: Vec<([u8; 32], usize)> = Vec::new();
        queue.extend(branches.values().copied().map(|id| (id, 1)));
        queue.extend(tags.values().copied().map(|id| (id, 1)));
        queue.extend(extra.iter().copied().map(|id| (id, 1)));
        if let Ok(stashes) = self.list_stashes() {
            queue.extend(stashes.into_iter().map(|id| (id, 1)));
        }

        while let Some((id, level)) = queue.pop() {
            if !seen.insert(id) {
                continue;
            }
            objects.insert(id);
            if let Ok(record) = self.read_commit_record(&id) {
                let c = &record.commit;
                objects.insert(c.tree);
                queue.push((c.tree, level));
                if level >= depth {
                    // Deepest served generation: parents are not fetched.
                    boundary.push(id);
                } else {
                    for p in &c.parents {
                        queue.push((*p, level + 1));
                    }
                }
                continue;
            }
            if let Ok(tag) = self.read_tag(&id) {
                queue.push((tag.target, level + 1));
                continue;
            }
            // Tree object: keep every child — blobs for legacy flat trees,
            // blobs AND intermediate subtree objects for the nested v2 format.
            if let Ok(children) = self.tree_object_children(&id) {
                for child in children {
                    queue.push((child, level));
                }
                continue;
            }
        }
        Ok((objects, boundary))
    }

    fn walk_reachable(
        &self,
        branches: &BTreeMap<String, [u8; 32]>,
        tags: &BTreeMap<String, [u8; 32]>,
        extra: &[[u8; 32]],
        follow_parents: bool,
    ) -> Result<BTreeSet<[u8; 32]>, String> {
        let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut queue: Vec<[u8; 32]> = Vec::new();
        queue.extend(branches.values().copied());
        queue.extend(tags.values().copied());
        queue.extend(extra.iter().copied());
        // Stash snapshots are kept reachable so gc never prunes shelved work.
        if let Ok(stashes) = self.list_stashes() {
            queue.extend(stashes);
        }

        while let Some(id) = queue.pop() {
            if !seen.insert(id) {
                continue;
            }
            // Is it a commit?
            if let Ok(record) = self.read_commit_record(&id) {
                let c = &record.commit;
                queue.push(c.tree);
                if follow_parents {
                    for p in &c.parents {
                        queue.push(*p);
                    }
                }
                continue;
            }
            // Is it a tag pointing at something?
            if let Ok(tag) = self.read_tag(&id) {
                queue.push(tag.target);
                continue;
            }
            // Is it a tree object? Keep every child — blobs for legacy
            // flat trees, blobs AND intermediate subtree objects for the
            // nested v2 format (so gc/push never prune a subtree object).
            if let Ok(children) = self.tree_object_children(&id) {
                queue.extend(children);
            }
            // Otherwise it's a blob (leaf) — nothing further to crawl.
        }
        Ok(seen)
    }

    // ------------------------------------------------------------------
    // shallow marker (truncated history, set by `clone --shallow`)
    // ------------------------------------------------------------------

    /// Whether this repo is a shallow clone: the branch tips in `SHALLOW`
    /// have no parent objects present. Commands that walk parent chains
    /// (`log`, `verify`, `merge`) stop at the boundary instead of failing.
    pub fn is_shallow(&self) -> bool {
        self.root.join("SHALLOW").exists()
    }

    // ------------------------------------------------------------------
    // stash index (working-tree snapshots kept reachable from gc)
    // ------------------------------------------------------------------

    /// The current stash stack (newest first): each entry is a stash commit
    /// whose tree is the working-tree snapshot and parent the original HEAD.
    /// Stored unencrypted (ids are content addresses, non-secret).
    pub fn list_stashes(&self) -> Result<Vec<[u8; 32]>, String> {
        let path = self.root.join("stash.json");
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("stash parse: {e}")),
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Replace the stash stack. `stashes` newest first.
    pub fn save_stashes(&self, stashes: &[[u8; 32]]) -> Result<(), String> {
        let body = serde_json::to_vec(stashes).map_err(|e| format!("stash ser: {e}"))?;
        atomic_write(&self.root.join("stash.json"), &body).map_err(|e| format!("stash: {e}"))
    }

    /// The active sparse-checkout paths (empty = full checkout). Read from the
    /// `SPARSE` marker; a missing or empty marker means every tree entry is
    /// materialized.
    pub fn sparse_paths(&self) -> Result<Vec<String>, String> {
        let path = self.root.join("SPARSE");
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("sparse parse: {e}")),
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Set (or clear, with an empty slice) the sparse-checkout path set.
    pub fn set_sparse(&self, paths: &[String]) -> Result<(), String> {
        let body = serde_json::to_vec(paths).map_err(|e| format!("sparse ser: {e}"))?;
        atomic_write(&self.root.join("SPARSE"), &body).map_err(|e| format!("sparse: {e}"))
    }

    /// Record the boundary commit ids (the fetched branch tips) as a shallow
    /// clone. The file lists the tips whose parents were NOT fetched.
    pub fn mark_shallow(&self, tips: &[[u8; 32]]) -> Result<(), String> {
        let ids: Vec<String> = tips.iter().map(hex::encode).collect();
        let body = serde_json::to_vec(&ids).map_err(|e| format!("shallow ser: {e}"))?;
        atomic_write(&self.root.join("SHALLOW"), &body).map_err(|e| format!("write SHALLOW: {e}"))
    }

    /// The recorded shallow boundary tips.
    pub fn shallow_tips(&self) -> Result<Vec<[u8; 32]>, String> {
        let path = self.root.join("SHALLOW");
        match std::fs::read(&path) {
            Ok(bytes) => {
                let hexes: Vec<String> =
                    serde_json::from_slice(&bytes).map_err(|e| format!("shallow parse: {e}"))?;
                hexes.iter().map(|h| id_from_hex_str(h)).collect()
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Delete all object envelopes whose id is *not* in the reachable set.
    /// Returns the number of objects pruned.
    pub fn prune_unreachable(
        &self,
        reachable: &std::collections::BTreeSet<[u8; 32]>,
    ) -> Result<usize, String> {
        let mut pruned = 0usize;
        for id in self.all_object_ids()? {
            if !reachable.contains(&id) && self.delete_object(&id)? {
                pruned += 1;
            }
        }
        Ok(pruned)
    }

    /// Remove a branch or tag ref.
    pub fn delete_ref(&self, category: &str, name: &str) -> Result<(), String> {
        let path = self.refs.join(category).join(name);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| format!("delete ref {name}: {e}"))?;
        }
        Ok(())
    }

    /// Whether a branch ref exists.
    pub fn ref_exists(&self, category: &str, name: &str) -> bool {
        self.refs.join(category).join(name).exists()
    }

    /// All tracking-ref tips under `refs/remotes/<remote>/<branch>` (set by
    /// remote fetch / bundle import). Used so `verify` walks imported history
    /// even when no local branch exists yet. Recurses the one-level
    /// `<remote>/<branch>` layout.
    pub fn remote_refs(&self) -> Result<Vec<[u8; 32]>, String> {
        let mut out = Vec::new();
        let remotes = self.refs.join("remotes");
        if !remotes.is_dir() {
            return Ok(out);
        }
        for e in std::fs::read_dir(&remotes).map_err(|e| format!("refs remotes: {e}"))? {
            let e = e.map_err(|e| format!("refs remotes entry: {e}"))?;
            let path = e.path();
            if path.is_dir() {
                // <remote>/<branch> files
                for f in std::fs::read_dir(&path).map_err(|e| format!("refs remote dir: {e}"))? {
                    let f = f.map_err(|e| format!("refs remote entry: {e}"))?;
                    let remote = e.file_name().to_string_lossy().to_string();
                    let branch = f.file_name().to_string_lossy().to_string();
                    out.push(self.read_ref("remotes", &format!("{remote}/{branch}"))?);
                }
            } else {
                let name = e.file_name().to_string_lossy().to_string();
                out.push(self.read_ref("remotes", &name)?);
            }
        }
        Ok(out)
    }

    // ------------------------------------------------------------------
    // index (staging area)
    // ------------------------------------------------------------------

    /// The staged index is a serialized Tree (paths → entry refs). Stored
    /// encrypted. Return a default (empty) tree if none exists.
    pub fn load_index(&self) -> Result<Tree, String> {
        // The index file is the same format as a tree, but we want an empty
        // default. Envelope-encrypt an empty tree on first use.
        let path = &self.index_path;
        match std::fs::read(path) {
            Ok(bytes) => {
                let plain = self.decrypt(&bytes)?;
                serde_json::from_slice(&plain).map_err(|e| format!("index parse: {e}"))
            }
            Err(_) => Ok(Tree::new()),
        }
    }

    pub fn save_index(&self, tree: &Tree) -> Result<(), String> {
        let body = serde_json::to_vec(tree).map_err(|e| format!("index ser: {e}"))?;
        let bytes = self.encrypt(&body)?;
        atomic_write(&self.index_path, &bytes).map_err(|e| format!("index: {e}"))
    }
}
