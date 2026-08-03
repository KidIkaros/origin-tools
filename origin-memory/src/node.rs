// SPDX-License-Identifier: Apache-2.0

//! MemoryNode — an Obsidian-shaped markdown node.
//!
//! Format (reused from Obsidian/Logseq/Foam, NOT invented):
//! ```markdown
//! ---
//! title: Event Name
//! time: 2004-03-11
//! topic: [geopolitics, finance]
//! evidence: documented   # documented | assertion | fiction
//! ---
//! Body text with [[wikilinks]] to other nodes.
//! ```

use chrono::{DateTime, NaiveDate, Utc};
use origin_crypto_sdk::tier::MemoryTier;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Evidence {
    Documented,
    Assertion,
    Fiction,
    /// Coarse summary node that points down into leaf nodes (star-chart zoom).
    Summary,
}

impl Evidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Evidence::Documented => "documented",
            Evidence::Assertion => "assertion",
            Evidence::Fiction => "fiction",
            Evidence::Summary => "summary",
        }
    }
    pub fn from_label(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "documented" => Evidence::Documented,
            "fiction" => Evidence::Fiction,
            "summary" => Evidence::Summary,
            _ => Evidence::Assertion,
        }
    }
    /// All valid evidence labels (for diagnostics).
    pub fn variants() -> &'static [&'static str] {
        &["documented", "assertion", "fiction", "summary"]
    }
    /// Map the evidentiary axis onto the shared Origin memory tier. This lets
    /// `origin-memory` reuse the same storage-tier vocabulary as origin-secrets
    /// / origin-pass (one concept, one enum, across the toolkit).
    pub fn tier(&self) -> MemoryTier {
        match self {
            Evidence::Documented => MemoryTier::Sovereign, // signed, canonical, durable
            Evidence::Assertion => MemoryTier::Standard,   // indexed, mutable
            Evidence::Fiction => MemoryTier::Nano,         // ephemeral / low-trust
            Evidence::Summary => MemoryTier::Standard,     // coarse pointer, indexed
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryNode {
    /// Stable id, derived from the filename stem (e.g. "event-2004-03-11").
    pub id: String,
    pub title: String,
    /// Temporal axis. Supports a single date or a range (start..end).
    pub time: NaiveDate,
    pub time_end: Option<NaiveDate>,
    /// Topical axis — orthogonal to time and evidence.
    pub topics: Vec<String>,
    /// Evidentiary axis — the trust signal missing from every flat graph.
    pub evidence: Evidence,
    /// Storage tier (mapped from `evidence`), shared with the rest of the toolkit.
    /// Skipped in serde (de)serialization: it is always derived from `evidence`,
    /// and `MemoryTier` does not implement `serde::Deserialize`.
    #[serde(skip, default)]
    pub tier: MemoryTier,
    /// Markdown body, with [[wikilinks]] preserved.
    pub body: String,
    /// Outgoing links resolved from [[wikilinks]].
    pub links: BTreeSet<String>,
}

impl MemoryNode {
    /// Parse an Obsidian-style markdown file (frontmatter + body).
    pub fn from_markdown(id: &str, md: &str) -> Result<Self, String> {
        let (fm, body) = split_frontmatter(md)?;
        let value: serde_json::Value = serde_yaml_or_json(fm)?;
        let get = |k: &str| value.get(k).and_then(|v| v.as_str());

        let time_str = get("time").ok_or("missing required frontmatter: time")?;
        let time = NaiveDate::parse_from_str(time_str, "%Y-%m-%d")
            .map_err(|e| format!("bad time {time_str}: {e}"))?;

        let time_end = value
            .get("time_end")
            .and_then(|v| v.as_str())
            .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok());

        let topics = value
            .get("topic")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let evidence = value
            .get("evidence")
            .and_then(|v| v.as_str())
            .map(Evidence::from_label)
            .ok_or_else(|| {
                format!(
                    "node '{}' missing or invalid 'evidence' field (must be one of: {})",
                    id,
                    Evidence::variants().join(", ")
                )
            })?;

        let tier = value
            .get("tier")
            .and_then(|v| v.as_str())
            .and_then(|s| origin_common::tier_from_str(s).ok())
            .unwrap_or_else(|| evidence.tier());

        let links = extract_wikilinks(body);
        let title = get("title").unwrap_or(id).to_string();

        Ok(Self {
            id: id.to_string(),
            title,
            time,
            time_end,
            topics,
            evidence,
            tier,
            body: body.to_string(),
            links,
        })
    }

    /// Canonical bytes that get signed: id ‖ time ‖ evidence ‖ body hash.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(self.id.as_bytes());
        p.push(0);
        p.extend_from_slice(self.time.format("%Y-%m-%d").to_string().as_bytes());
        p.push(0);
        p.extend_from_slice(self.evidence.as_str().as_bytes());
        p.push(0);
        p.extend_from_slice(origin_crypto_sdk::sha3_256(self.body.as_bytes()).as_ref());
        p
    }

    /// A `origin-provenance::Stamp` over the canonical markdown bytes — a
    /// timestamped content hash. Reuses the toolkit's provenance primitive
    /// instead of re-implementing a content fingerprint here.
    pub fn stamp(&self) -> origin_provenance::stamp::Stamp {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        origin_provenance::stamp::Stamp::new(self.to_markdown().as_bytes(), ts)
    }
}

fn split_frontmatter(md: &str) -> Result<(&str, &str), String> {
    let trimmed = md.trim_start();
    if !trimmed.starts_with("---\n") && !trimmed.starts_with("---\r\n") {
        return Err("no frontmatter delimiter".into());
    }
    let rest = &trimmed[4..];
    // The closing fence is "\n---\n" (preceded by a newline, followed by one).
    // Skip all 5 chars so the body starts exactly where the content begins.
    let fence = rest.find("\n---\n").ok_or("unterminated frontmatter")?;
    Ok((&rest[..fence], &rest[fence + 5..]))
}

fn serde_yaml_or_json(fm: &str) -> Result<serde_json::Value, String> {
    // Try YAML first (Obsidian default), fall back to JSON-ish.
    serde_yaml_unsafe(fm).ok_or_else(|| "could not parse frontmatter".into())
}

fn serde_yaml_unsafe(fm: &str) -> Option<serde_json::Value> {
    // Minimal hand-rolled parser for our flat schema to avoid a yaml dep.
    let mut map = serde_json::Map::new();
    for line in fm.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if let Some(stripped) = v.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                let arr: Vec<serde_json::Value> = stripped
                    .split(',')
                    .map(|s| serde_json::Value::String(s.trim().to_string()))
                    .collect();
                map.insert(k.to_string(), serde_json::Value::Array(arr));
            } else {
                map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
            }
        }
    }
    Some(serde_json::Value::Object(map))
}

fn extract_wikilinks(body: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if &bytes[i..i + 2] == b"[[" {
            if let Some(close) = body[i + 2..].find("]]") {
                let inner = &body[i + 2..i + 2 + close];
                let target = inner.split('#').next().unwrap_or(inner).trim().to_string();
                if !target.is_empty() {
                    set.insert(target);
                }
                i += 2 + close + 2;
                continue;
            }
        }
        i += 1;
    }
    set
}

#[allow(dead_code)]
fn now() -> DateTime<Utc> {
    Utc::now()
}

impl MemoryNode {
    /// Serialize to canonical Obsidian-shaped markdown (frontmatter + body).
    /// This is the human-readable, cold-storage representation on disk.
    pub fn to_markdown(&self) -> String {
        let mut fm = String::new();
        fm.push_str("---\n");
        fm.push_str(&format!("title: {}\n", self.title));
        fm.push_str(&format!("time: {}\n", self.time.format("%Y-%m-%d")));
        if let Some(end) = self.time_end {
            fm.push_str(&format!("time_end: {}\n", end.format("%Y-%m-%d")));
        }
        fm.push_str(&format!("topic: [{}]\n", self.topics.join(", ")));
        fm.push_str(&format!("evidence: {}\n", self.evidence.as_str()));
        fm.push_str(&format!("tier: {}\n", self.tier.label()));
        fm.push_str("---\n");
        fm.push_str(&self.body);
        fm
    }

    /// Load a node from a markdown file (filename stem becomes the id).
    pub fn from_markdown_file(path: &std::path::Path) -> Result<Self, String> {
        let md =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("invalid filename")?
            .to_string();
        MemoryNode::from_markdown(&id, &md)
    }
}
