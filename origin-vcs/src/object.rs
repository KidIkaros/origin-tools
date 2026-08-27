// SPDX-License-Identifier: Apache-2.0

//! Object model for origin-vcs.
//!
//! Mirrors git's blob/tree/commit/tag decomposition, but every object is
//! content-addressed by the SHA3-256 of its **canonical plaintext** and stored
//! encrypted at rest. Identical plaintext dedupes to one address; tampering
//! changes the address so lookups fail loudly.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Object kind discriminator, prefixed into the address hash so that a tree
/// whose serialized bytes coincide with some other kind's bytes can never
/// collide with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ObjectKind {
    Blob = 0x01,
    Tree = 0x02,
    Commit = 0x03,
    Tag = 0x04,
}

impl ObjectKind {
    /// Human-readable tag used inside the canonical bytes (never on disk alone).
    pub fn tag(self) -> &'static str {
        match self {
            ObjectKind::Blob => "blob",
            ObjectKind::Tree => "tree",
            ObjectKind::Commit => "commit",
            ObjectKind::Tag => "tag",
        }
    }
}

/// Unix-ish file mode recorded in a tree entry. Simplified: regular file,
/// executable, or symlink (content = the link target path, git-style).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum FileMode {
    File = 0o100644,
    Executable = 0o100755,
    Symlink = 0o120000,
}

impl FileMode {
    pub fn from_permissions(mode: u32) -> Self {
        if mode & 0o111 != 0 {
            FileMode::Executable
        } else {
            FileMode::File
        }
    }
    pub fn bits(self) -> u32 {
        self as u32
    }

    /// Whether the entry is a symlink.
    pub fn is_symlink(self) -> bool {
        matches!(self, FileMode::Symlink)
    }

    /// Stable name used inside nested tree objects (v2 rows).
    pub fn as_str(self) -> &'static str {
        match self {
            FileMode::File => "File",
            FileMode::Executable => "Executable",
            FileMode::Symlink => "Symlink",
        }
    }

    /// Parse the name form written by [FileMode::as_str].
    pub fn from_name(s: &str) -> Result<Self, String> {
        match s {
            "File" => Ok(FileMode::File),
            "Executable" => Ok(FileMode::Executable),
            "Symlink" => Ok(FileMode::Symlink),
            other => Err(format!("unknown file mode '{other}'")),
        }
    }
}

/// One row of a tree: relative path → descendant object id (+ mode).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    pub mode: FileMode,
    pub id: [u8; 32],
}

/// An immutable directory node. Maps a path segment to its child id.
///
/// In memory this is always a **flat** map of full relative paths (the
/// index, diff, merge and status code all work on flat trees). On disk,
/// `Store::write_tree` buckets the paths into git-style nested tree
/// objects (see [TreeObject]) so large directories never produce one
/// giant object and shared subtrees dedupe by content address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tree {
    pub kind: String,
    pub entries: BTreeMap<String, TreeEntry>,
}

/// A `v:2` nested tree object — the on-disk (git-style subtree) form.
///
/// Rows are sorted `(name, kind, hex-id)` triples. Subtree rows have a
/// trailing `/` in the name and kind `"tree"`; blob rows carry a
/// [FileMode] name. The object's address is SHA3-256 of
/// `tree:<len>\n<json>` (same wire shape as the other object kinds), so a
/// subtree shared by two parents stores once and dedupes by id.
///
/// Legacy flat trees (the pre-v2 `Tree` JSON, `v` absent) are still
/// readable: `Store::read_tree` and `tree_object_children` detect the
/// marker and fall back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeObject {
    pub v: u32,
    pub entries: Vec<(String, String, String)>,
}

impl TreeObject {
    pub fn new() -> Self {
        TreeObject {
            v: 2,
            entries: Vec::new(),
        }
    }
}

impl Default for TreeObject {
    fn default() -> Self {
        Self::new()
    }
}

/// A file's plaintext bytes (kept out of serde only by separation, never
/// written to disk unencrypted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub data: Vec<u8>,
}

/// A commit — the signed unit of history. `tree` roots the whole snapshot;
/// `parents` link the DAG. The hybrid signature covers the canonical serialized
/// form (the same bytes that produce the address), so a tampered tree or parent
/// breaks this commit's own signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    pub kind: String,
    pub tree: [u8; 32],
    pub parents: Vec<[u8; 32]>,
    pub message: String,
    pub author: String,
    pub committer: String,
    pub ts: u64,
}

/// A signed tag pointing at any object (typically a commit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    pub kind: String,
    pub name: String,
    pub target: [u8; 32],
    pub message: String,
    pub ts: u64,
}

/// The on-disk record for a commit: the commit itself plus its hybrid
/// signature, serialized together and stored inside the (encrypted) envelope.
/// Addressing still uses the bare [Commit], so the signature never affects the
/// content address and identical commits dedupe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitRecord {
    pub commit: Commit,
    pub signature: crate::crypto::Signature,
}

impl Blob {
    pub fn new(data: Vec<u8>) -> Self {
        Blob { data }
    }
}

impl Tree {
    pub fn new() -> Self {
        Tree {
            kind: "tree".into(),
            entries: BTreeMap::new(),
        }
    }
}

impl Default for Commit {
    fn default() -> Self {
        Self::new()
    }
}

impl Commit {
    pub fn new() -> Self {
        Commit {
            kind: "commit".into(),
            tree: [0u8; 32],
            parents: Vec::new(),
            message: String::new(),
            author: String::new(),
            committer: String::new(),
            ts: 0,
        }
    }
}

impl Tag {
    pub fn new(name: &str) -> Self {
        Tag {
            kind: "tag".into(),
            name: name.into(),
            target: [0u8; 32],
            message: String::new(),
            ts: 0,
        }
    }
}

/// Canonical serialization is what both content addressing and signing run
/// over. We use the type-tagged length-prefixed wire form so the bytes are
/// deterministic regardless of serialization-library drift.
pub fn canonical_blob(blob: &Blob) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + 4 + blob.data.len());
    out.extend_from_slice(ObjectKind::Blob.tag().as_bytes());
    out.push(0);
    out.extend_from_slice(&(blob.data.len() as u32).to_be_bytes());
    out.extend_from_slice(&blob.data);
    out
}

pub fn canonical_tree(tree: &Tree) -> Vec<u8> {
    let body = serde_json::to_vec(tree).expect("tree serializes");
    let mut out = Vec::with_capacity(5 + body.len());
    out.extend_from_slice(ObjectKind::Tree.tag().as_bytes());
    out.push(0);
    out.extend_from_slice(&body);
    out
}

pub fn canonical_commit(commit: &Commit) -> Vec<u8> {
    let body = serde_json::to_vec(commit).expect("commit serializes");
    let mut out = Vec::with_capacity(5 + body.len());
    out.extend_from_slice(ObjectKind::Commit.tag().as_bytes());
    out.push(0);
    out.extend_from_slice(&body);
    out
}

pub fn canonical_tag(tag: &Tag) -> Vec<u8> {
    let body = serde_json::to_vec(tag).expect("tag serializes");
    let mut out = Vec::with_capacity(5 + body.len());
    out.extend_from_slice(ObjectKind::Tag.tag().as_bytes());
    out.push(0);
    out.extend_from_slice(&body);
    out
}

/// Object id = SHA3-256 over `<kind>` marker + canonical bytes.
/// The marker line is the CRLF-free header `<kind>:<len>\n` so we can
/// reconstruct/decode without deserializing blindly.
fn address_of(header: &str, body: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(header.len() + body.len());
    buf.extend_from_slice(header.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(body);
    origin_crypto_sdk::sha3_256(&buf)
}

pub fn blob_address(blob: &Blob) -> [u8; 32] {
    let hdr = format!("{}:{}", ObjectKind::Blob.tag(), blob.data.len());
    address_of(&hdr, &blob.data)
}

pub fn tree_address(tree: &Tree) -> [u8; 32] {
    let body = canonical_tree(tree);
    let hdr = format!("{}:{}", ObjectKind::Tree.tag(), body.len());
    address_of(&hdr, &body)
}

pub fn commit_address(commit: &Commit) -> [u8; 32] {
    let body = canonical_commit(commit);
    let hdr = format!("{}:{}", ObjectKind::Commit.tag(), body.len());
    address_of(&hdr, &body)
}

pub fn tag_address(tag: &Tag) -> [u8; 32] {
    let body = canonical_tag(tag);
    let hdr = format!("{}:{}", ObjectKind::Tag.tag(), body.len());
    address_of(&hdr, &body)
}

pub fn hex(id: &[u8; 32]) -> String {
    hex::encode(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_address_is_content_addressed() {
        let a = Blob::new(b"hello world".to_vec());
        let b = Blob::new(b"hello world".to_vec());
        let c = Blob::new(b"hello worlD".to_vec());
        assert_eq!(blob_address(&a), blob_address(&b));
        assert_ne!(blob_address(&a), blob_address(&c));
    }

    #[test]
    fn tree_address_detects_child_change() {
        let mut t1 = Tree::new();
        t1.entries.insert(
            "a".into(),
            TreeEntry {
                mode: FileMode::File,
                id: [1u8; 32],
            },
        );
        let mut t2 = Tree::new();
        t2.entries.insert(
            "a".into(),
            TreeEntry {
                mode: FileMode::File,
                id: [2u8; 32],
            },
        );
        assert_ne!(tree_address(&t1), tree_address(&t2));
    }

    #[test]
    fn canonical_is_deterministic() {
        let mut c = Commit::new();
        c.message = "hi".into();
        c.ts = 1234;
        assert_eq!(canonical_commit(&c), canonical_commit(&c));
    }

    #[test]
    fn kinds_do_not_collide() {
        // Same length body for blob vs tree must yield different addresses
        // thanks to the type tag.
        let blob = Blob::new(vec![0u8; 8]);
        let mut tree = Tree::new();
        tree.entries.insert(
            "\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}\u{0}".into(),
            TreeEntry {
                mode: FileMode::File,
                id: [0u8; 32],
            },
        );
        assert_ne!(blob_address(&blob), tree_address(&tree));
    }

    #[test]
    fn file_mode_from_permissions() {
        assert_eq!(FileMode::from_permissions(0o644), FileMode::File);
        assert_eq!(FileMode::from_permissions(0o755), FileMode::Executable);
        assert_eq!(FileMode::from_permissions(0o600), FileMode::File);
    }
}
