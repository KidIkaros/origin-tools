// SPDX-License-Identifier: Apache-2.0

//! persist — disk-backed memory store (rusqlite).
//!
//! Design (agreed step 1):
//! - **Markdown files are the canonical cold store.** Each node is written to
//!   `<root>/<id>.md` in Obsidian format. Human-readable, git-friendly, and the
//!   authoritative source if the index ever disagrees.
//! - **SQLite (rusqlite) is the survival index.** It holds parsed node fields +
//!   signatures so the store reloads instantly after restart without re-parsing
//!   every file, and gives temporal-zoom queries for free via SQL.
//! - **Coarse summary nodes are just nodes.** A summary node has
//!   `evidence: summary` and `topics: [<wing>]` and links to its leaf children.
//!   This is the star-chart zoom pointer from the thesis: descend only where the
//!   question points.

use crate::endorse::EndorsementStore;
use crate::node::MemoryNode;
use crate::revoke::RevocationStore;
use crate::sign::{sign_node, NodeSignature};
use chrono::NaiveDate;
use origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle;
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct MemoryStore {
    root: PathBuf,
    conn: Connection,
    revocations: RevocationStore,
    endorsements: EndorsementStore,
}

/// Current SQLite schema version (stamped in `PRAGMA user_version`).
/// Bump this and add a migration step in `migrate()` whenever the schema changes.
pub const SCHEMA_VERSION: i32 = 1;

/// Columns the canonical `nodes` table must have at `SCHEMA_VERSION`, in
/// order of the migration steps that introduced them. Used both to detect
/// what a legacy database is missing and to document history.
const NODES_COLUMNS: &[(&str, &str)] = &[
    ("id", "TEXT PRIMARY KEY"),
    ("title", "TEXT NOT NULL"),
    ("time", "TEXT NOT NULL"),
    ("time_end", "TEXT"),
    ("topics", "TEXT NOT NULL"),
    ("evidence", "TEXT NOT NULL"),
    ("tier", "TEXT NOT NULL"),
    ("content_hash", "TEXT NOT NULL"),
    ("body", "TEXT NOT NULL"),
    ("ed25519_sig", "TEXT NOT NULL"),
    ("falcon_sig", "TEXT NOT NULL"),
    ("signer", "TEXT NOT NULL"),
    ("layer_root", "TEXT"),
    ("body_encrypted", "TEXT"),
];

/// Migrate a database from `from_version` to `SCHEMA_VERSION`.
///
/// Version 0 means "un-versioned": any database created before R4 introduced
/// the stamp. Legacy data is never dropped — missing columns are added with
/// NULL-friendly defaults (`layer_root`, `body_encrypted` are both nullable).
///
/// Refuses to open a database stamped *newer* than this build: downgrading a
/// database with older code would silently lose future columns.
fn migrate(conn: &Connection, from_version: i32) -> rusqlite::Result<i32> {
    if from_version > SCHEMA_VERSION {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Null,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "database schema version {from_version} is newer than supported \
                     {SCHEMA_VERSION}; upgrade origin-memory"
                ),
            )),
        ));
    }

    let mut version = from_version;

    if version == 0 {
        // v0 -> v1: the un-versioned table predates the encrypted-body column
        // (P4). Add whatever is missing rather than assuming one exact shape —
        // a table can sit at any intermediate point. On a fresh database the
        // table doesn't exist yet; the caller's CREATE TABLE builds the full
        // shape, so nothing to add here.
        let nodes_exists: i32 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'nodes'",
            [],
            |r| r.get(0),
        )?;
        if nodes_exists > 0 {
            ensure_columns(conn, "nodes", NODES_COLUMNS)?;
        }
        version = 1;
    }

    // Future steps go here: `if version == 1 { ...; version = 2; }`

    conn.execute_batch(&format!("PRAGMA user_version = {version};"))?;
    Ok(version)
}

/// Add any of `columns` that the table doesn't have yet (SQLite has no
/// `ADD COLUMN IF NOT EXISTS`, so existence is checked via `table_info`).
fn ensure_columns(
    conn: &Connection,
    table: &str,
    columns: &[(&str, &str)],
) -> rusqlite::Result<()> {
    let mut existing = std::collections::HashSet::new();
    {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            existing.insert(row.get::<_, String>(1)?);
        }
    }
    for (name, ty) in columns {
        if !existing.contains(*name) {
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {name} {ty};"))?;
        }
    }
    Ok(())
}

impl MemoryStore {
    /// Open (or create) a store rooted at `root`. Markdown lives in `root/`,
    /// the index in `root/memory.sqlite`, the revocation journal in
    /// `root/revocations.json`, the endorsement journal in
    /// `root/endorsements.json`.
    ///
    /// The SQLite schema is version-stamped (`PRAGMA user_version`, R4):
    /// legacy databases migrate forward automatically, and a database stamped
    /// *newer* than this build refuses to open rather than degrade silently.
    pub fn open(root: &Path) -> rusqlite::Result<Self> {
        std::fs::create_dir_all(root).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?;
        let db_path = root.join("memory.sqlite");
        let conn = Connection::open(&db_path)?;

        // Schema versioning (R4): read the stamp, migrate forward.
        let from_version: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        migrate(&conn, from_version)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS nodes (
                id          TEXT PRIMARY KEY,
                title       TEXT NOT NULL,
                time        TEXT NOT NULL,
                time_end    TEXT,
                topics      TEXT NOT NULL,
                evidence    TEXT NOT NULL,
                tier        TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                body        TEXT NOT NULL,
                ed25519_sig TEXT NOT NULL,
                falcon_sig  TEXT NOT NULL,
                signer      TEXT NOT NULL,
                layer_root  TEXT,
                body_encrypted TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_time ON nodes(time);
            CREATE INDEX IF NOT EXISTS idx_nodes_evidence ON nodes(evidence);
            CREATE INDEX IF NOT EXISTS idx_nodes_tier ON nodes(tier);",
        )?;
        Ok(Self {
            root: root.to_path_buf(),
            conn,
            revocations: RevocationStore::open(root),
            endorsements: EndorsementStore::open(root),
        })
    }

    /// The SQLite schema version of the open database (post-migration).
    pub fn schema_version(&self) -> rusqlite::Result<i32> {
        self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))
    }

    /// Persist a node: write the canonical `.md` file AND upsert into the index.
    /// `sig` is the hybrid signature produced by the caller (so crypto stays in
    /// the sign module, not here).
    pub fn save(&self, node: &MemoryNode, sig: &NodeSignature) -> rusqlite::Result<()> {
        // Canonical markdown on disk (cold, authoritative) — atomic so a crash
        // mid-write never leaves a half-written .md (SQLite covers its own index).
        let md_path = self.root.join(format!("{}.md", node.id));
        origin_common::io::atomic_write(&md_path, node.to_markdown().as_bytes()).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e)),
            )
        })?;
        let stamp = node.stamp();

        // Upsert into the survival index.
        self.conn.execute(
            "INSERT INTO nodes (id, title, time, time_end, topics, evidence, tier, content_hash, body, ed25519_sig, falcon_sig, signer)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(id) DO UPDATE SET
                title=?2, time=?3, time_end=?4, topics=?5, evidence=?6, tier=?7,
                content_hash=?8, body=?9, ed25519_sig=?10, falcon_sig=?11, signer=?12",
            params![
                node.id,
                node.title,
                node.time.format("%Y-%m-%d").to_string(),
                node.time_end.map(|d| d.format("%Y-%m-%d").to_string()),
                node.topics.join(", "),
                node.evidence.as_str(),
                node.tier.label(),
                stamp.content_hash,
                node.body,
                sig.ed25519_hex,
                sig.falcon_hex,
                sig.signer_fingerprint,
            ],
        )?;
        Ok(())
    }

    /// Persist a secret node: body is encrypted (hex), stored in
    /// `body_encrypted`. The plaintext `body` column is set to `[encrypted]`
    /// so it's not readable on disk.
    pub fn save_encrypted(
        &self,
        node: &MemoryNode,
        sig: &NodeSignature,
        sealed_hex: &str,
    ) -> rusqlite::Result<()> {
        let md_path = self.root.join(format!("{}.md", node.id));
        let md = node.to_markdown();
        let _ = origin_common::io::atomic_write(&md_path, md.as_bytes());

        let stamp = node.stamp();
        self.conn.execute(
            "INSERT INTO nodes (id, title, time, time_end, topics, evidence, tier, content_hash, body, ed25519_sig, falcon_sig, signer, body_encrypted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(id) DO UPDATE SET
                title=?2, time=?3, time_end=?4, topics=?5, evidence=?6, tier=?7,
                content_hash=?8, body=?9, ed25519_sig=?10, falcon_sig=?11, signer=?12,
                body_encrypted=?13",
            params![
                node.id,
                node.title,
                node.time.format("%Y-%m-%d").to_string(),
                node.time_end.map(|d| d.format("%Y-%m-%d").to_string()),
                node.topics.join(", "),
                node.evidence.as_str(),
                node.tier.label(),
                stamp.content_hash,
                "[encrypted]",
                sig.ed25519_hex,
                sig.falcon_hex,
                sig.signer_fingerprint,
                sealed_hex,
            ],
        )?;
        Ok(())
    }

    /// Read the encrypted body (hex) for a secret node, if any.
    pub fn encrypted_body(&self, id: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT body_encrypted FROM nodes WHERE id = ?1",
                params![id],
                |row| row.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten()
    }

    /// Load every node from the SQLite index (fast path after restart).
    pub fn load_all(&self) -> rusqlite::Result<Vec<(MemoryNode, NodeSignature)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, title, time, time_end, topics, evidence, tier, body, ed25519_sig, falcon_sig, signer FROM nodes",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let time: String = row.get(2)?;
            let _time_end: Option<String> = row.get(3)?;
            let topics: String = row.get(4)?;
            let evidence: String = row.get(5)?;
            let tier: String = row.get(6)?;
            let body: String = row.get(7)?;
            // Reconstruct via the canonical markdown parser so links + tier round-trip.
            let md = format!(
                "---\ntitle: {}\ntime: {}\ntopic: [{}]\nevidence: {}\ntier: {}\n---\n{}",
                row.get::<_, String>(1)?,
                time,
                topics,
                evidence,
                tier,
                body,
            );
            let node = crate::node::MemoryNode::from_markdown(&id, &md).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
                )
            })?;
            let sig = NodeSignature {
                signer_fingerprint: row.get(10)?,
                ed25519_hex: row.get(8)?,
                falcon_hex: row.get(9)?,
            };
            Ok((node, sig))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Temporal zoom: node ids whose `time` falls in [center - window, center + window].
    /// One SQL query — the "walk the star chart" operation, cheap at the top.
    pub fn zoom_time(&self, center: NaiveDate, window_days: i64) -> rusqlite::Result<Vec<String>> {
        let lo = (center - chrono::Duration::days(window_days))
            .format("%Y-%m-%d")
            .to_string();
        let hi = (center + chrono::Duration::days(window_days))
            .format("%Y-%m-%d")
            .to_string();
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM nodes WHERE time BETWEEN ?1 AND ?2")?;
        let rows = stmt.query_map(params![lo, hi], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Coarse summary: build a summary node over a set of leaf nodes and persist
    /// it. The summary node carries `evidence: summary` and links to each leaf,
    /// so a zoom query can surface the summary first and descend only on
    /// interest. Crucially, the leaves are committed to a `LayerMmr` and its
    /// root is stored on the summary row — so membership of any leaf in this
    /// coarse layer is *provable* (not just signed) after reload.
    pub fn save_summary(
        &self,
        summary_id: &str,
        wing: &str,
        center: NaiveDate,
        leaves: &[MemoryNode],
        bundle: &Arc<HybridSigningKeyBundle>,
    ) -> rusqlite::Result<MemoryNode> {
        let leaf_ids: Vec<String> = leaves.iter().map(|l| l.id.clone()).collect();

        // Commit the leaves to a layer MMR; its root is the layer's fingerprint.
        let mut layer = crate::layer::LayerMmr::new(summary_id);
        for leaf in leaves {
            layer.append(leaf);
        }
        let layer_root = hex::encode(layer.root());

        let mut body = format!(
            "Summary wing `{}` around {} ({} leaves). Layer root: {}.\n",
            wing,
            center.format("%Y-%m-%d"),
            leaf_ids.len(),
            layer_root
        );
        for lid in &leaf_ids {
            body.push_str(&format!("\n- [[{}]]", lid));
        }
        let evidence = crate::node::Evidence::from_label("summary");
        let tier = evidence.tier();
        let node = MemoryNode {
            id: summary_id.to_string(),
            title: format!("Summary: {}", wing),
            time: center,
            time_end: None,
            topics: vec![wing.to_string()],
            evidence,
            tier,
            body,
            links: leaf_ids.iter().cloned().collect(),
        };
        let sig = sign_node(&node, bundle);
        self.save_with_layer(&node, &sig, &layer_root)?;
        Ok(node)
    }

    /// Persist a node plus an optional layer root (summary nodes only).
    fn save_with_layer(
        &self,
        node: &MemoryNode,
        sig: &NodeSignature,
        layer_root: &str,
    ) -> rusqlite::Result<()> {
        let md_path = self.root.join(format!("{}.md", node.id));
        origin_common::io::atomic_write(&md_path, node.to_markdown().as_bytes()).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e)),
            )
        })?;
        let stamp = node.stamp();
        self.conn.execute(
            "INSERT INTO nodes (id, title, time, time_end, topics, evidence, tier, content_hash, body, ed25519_sig, falcon_sig, signer, layer_root)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(id) DO UPDATE SET
                title=?2, time=?3, time_end=?4, topics=?5, evidence=?6, tier=?7,
                content_hash=?8, body=?9, ed25519_sig=?10, falcon_sig=?11, signer=?12, layer_root=?13",
            params![
                node.id,
                node.title,
                node.time.format("%Y-%m-%d").to_string(),
                node.time_end.map(|d| d.format("%Y-%m-%d").to_string()),
                node.topics.join(", "),
                node.evidence.as_str(),
                node.tier.label(),
                stamp.content_hash,
                node.body,
                sig.ed25519_hex,
                sig.falcon_hex,
                sig.signer_fingerprint,
                layer_root,
            ],
        )?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The stored layer root for a summary node (None for non-summary nodes).
    pub fn layer_root(&self, id: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT layer_root FROM nodes WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .ok()
            .flatten()
    }

    /// Access the append-only revocation journal (tamper-evident retraction).
    pub fn revocations(&self) -> &RevocationStore {
        &self.revocations
    }

    /// Access the append-only endorsement journal (multi-agent attribution).
    pub fn endorsements(&self) -> &EndorsementStore {
        &self.endorsements
    }

    /// Mutable access to the endorsement journal (for append during endorse).
    pub fn endorsements_mut(&mut self) -> &mut EndorsementStore {
        &mut self.endorsements
    }

    /// Raw SQLite connection (for tests/diagnostics).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Revoke a node by content hash (delegates to the internal journal, which
    /// signs with the bundle's Falcon-1024 component and persists to disk).
    pub fn revoke_node(
        &mut self,
        content_hash: [u8; 32],
        revoked_by: &str,
        reason: &str,
        bundle: &Arc<HybridSigningKeyBundle>,
    ) {
        self.revocations
            .revoke(content_hash, revoked_by, reason, bundle);
    }
}
