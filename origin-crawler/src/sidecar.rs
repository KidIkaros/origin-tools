// SPDX-License-Identifier: Apache-2.0

//! Per-body metadata sidecars.
//!
//! Every stored body `<hash>` gets a sibling `<hash>.json` recording all
//! source URLs observed for that exact content. Because de-duplication maps
//! many URLs onto one body, the sidecar *accumulates*: the first storer
//! writes it, and every later duplicate encounter — including on subsequent
//! `--resume` runs — appends its provenance instead of re-storing content.
//!
//! Writes are read-modify-write, so callers must serialize them; the
//! orchestrator holds a dedicated lock around sidecar updates.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Unix epoch seconds.
fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One observed origin of a stored body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRef {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// BFS depth at which this URL was encountered.
    pub depth: usize,
    /// Epoch seconds of the first encounter of this URL for this body.
    pub first_seen: u64,
    /// Epoch seconds of the most recent encounter; refreshed whenever the
    /// same URL maps onto this body again (e.g. on later `--resume` runs).
    pub last_seen: u64,
    /// HTTP validator from the response that produced this observation —
    /// raw `ETag`, used for conditional revalidation on resume runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Raw `Last-Modified` from the same response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

impl SourceRef {
    /// A fresh observation stamped with the current time, no validators.
    pub fn new(url: String, title: Option<String>, depth: usize) -> Self {
        let now = now_epoch_secs();
        Self {
            url,
            title,
            depth,
            first_seen: now,
            last_seen: now,
            etag: None,
            last_modified: None,
        }
    }

    /// Attach the fetch's HTTP validators (builder-style).
    pub fn with_validators(mut self, etag: Option<String>, last_modified: Option<String>) -> Self {
        self.etag = etag;
        self.last_modified = last_modified;
        self
    }
}

/// Sidecar document stored as `<hash>.json` next to the body.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Sidecar {
    pub content_hash: String,
    pub sources: Vec<SourceRef>,
}

/// Path of the sidecar for a given hex content hash.
pub fn path_for(dir: &Path, hash_hex: &str) -> PathBuf {
    dir.join(format!("{hash_hex}.json"))
}

/// Append `source` to the sidecar for `hash_hex`, creating the file when
/// missing. Returns `true` if the URL was newly recorded; if it was already
/// listed, its `last_seen` is refreshed instead and `false` is returned.
///
/// Callers must ensure no concurrent `record_source` runs for the same
/// directory (see `SharedState::sidecar_lock`).
pub async fn record_source(dir: &Path, hash_hex: &str, source: SourceRef) -> Result<bool, String> {
    let path = path_for(dir, hash_hex);
    let mut doc = match tokio::fs::read(&path).await {
        Ok(bytes) => serde_json::from_slice::<Sidecar>(&bytes)
            .map_err(|e| format!("parse {}: {e}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Sidecar {
            content_hash: hash_hex.to_string(),
            sources: Vec::new(),
        },
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };

    if let Some(existing) = doc.sources.iter_mut().find(|s| s.url == source.url) {
        existing.last_seen = now_epoch_secs();
        let json =
            serde_json::to_vec_pretty(&doc).map_err(|e| format!("serialize sidecar: {e}"))?;
        tokio::fs::write(&path, json)
            .await
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        return Ok(false);
    }
    doc.sources.push(source);

    let json = serde_json::to_vec_pretty(&doc).map_err(|e| format!("serialize sidecar: {e}"))?;
    tokio::fs::write(&path, json)
        .await
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(true)
}

/// Per-URL HTTP validators harvested from a corpus's sidecars.
#[derive(Debug, Default, Clone)]
pub struct UrlValidators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl UrlValidators {
    pub fn is_usable(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }
}

/// Build a URL → validators map from every sidecar in `dir`.
///
/// Used by resume mode to send conditional requests instead of re-downloading
/// unchanged pages. Unparseable sidecars are skipped (they carry no usable
/// provenance anyway); entries without any validator are omitted.
pub async fn load_url_validators(
    dir: &Path,
) -> Result<std::collections::HashMap<String, UrlValidators>, String> {
    let mut rd = tokio::fs::read_dir(dir)
        .await
        .map_err(|e| format!("resume: read dir {}: {e}", dir.display()))?;
    let mut map = std::collections::HashMap::new();
    while let Some(entry) = rd
        .next_entry()
        .await
        .map_err(|e| format!("resume: scan {}: {e}", dir.display()))?
    {
        if !entry
            .file_type()
            .await
            .map_err(|e| format!("resume: {}: {e}", entry.path().display()))?
            .is_file()
        {
            continue;
        }
        let name = entry.file_name();
        if !name.to_string_lossy().ends_with(".json") {
            continue;
        }
        let bytes = match tokio::fs::read(entry.path()).await {
            Ok(b) => b,
            Err(_) => continue,
        };
        let Ok(doc) = serde_json::from_slice::<Sidecar>(&bytes) else {
            continue;
        };
        for s in doc.sources {
            if !s.url.is_empty() && (s.etag.is_some() || s.last_modified.is_some()) {
                map.insert(
                    s.url,
                    UrlValidators {
                        etag: s.etag,
                        last_modified: s.last_modified,
                    },
                );
            }
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sidecar-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn record_then_load_roundtrips_validators() {
        let dir = tmp_dir("validators");
        let src = SourceRef::new("https://e.com/p".into(), None, 0).with_validators(
            Some("\"v1\"".into()),
            Some("Tue, 01 Jan 2026 00:00:00 GMT".into()),
        );
        assert!(record_source(&dir, &"a".repeat(64), src).await.unwrap());
        // Re-record without validators must not erase them (merge keeps the
        // existing entry untouched apart from last_seen).
        assert!(!record_source(
            &dir,
            &"a".repeat(64),
            SourceRef::new("https://e.com/p".into(), None, 0)
        )
        .await
        .unwrap());

        let map = load_url_validators(&dir).await.unwrap();
        let v = map.get("https://e.com/p").expect("validator recorded");
        assert_eq!(v.etag.as_deref(), Some("\"v1\""));
        assert_eq!(
            v.last_modified.as_deref(),
            Some("Tue, 01 Jan 2026 00:00:00 GMT")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn sources_without_validators_are_omitted_and_bad_json_skipped() {
        let dir = tmp_dir("validators-skip");
        record_source(
            &dir,
            &"b".repeat(64),
            SourceRef::new("https://e.com/nov".into(), None, 1),
        )
        .await
        .unwrap();
        std::fs::write(dir.join("garbage.json"), b"{not json").unwrap();

        let map = load_url_validators(&dir).await.unwrap();
        assert!(map.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
