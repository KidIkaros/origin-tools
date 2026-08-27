// SPDX-License-Identifier: Apache-2.0

//! Corpus analysis — summarize a `--save-dir` from its sidecars.
//!
//! A corpus is a directory of BLAKE3-keyed bodies (`<hash>`) plus their
//! provenance sidecars (`<hash>.json`). This module reads both, pairs them
//! up, and produces a report covering:
//!
//! - inventory: body count/bytes, sidecar health (parse errors, orphans),
//! - sources: total counts grouped by host,
//! - staleness: source ages derived from each sidecar's `last_seen`.
//!
//! [`prune`] reuses the same scan to garbage-collect a corpus: orphaned
//! bodies/sidecars are deleted, stale sources are stripped from surviving
//! sidecars, and any entry whose last source was pruned is removed whole.
//!
//! Pure analysis over the filesystem — no network, no async.

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;

use crate::sidecar::{self, Sidecar};

/// Source counts for one host.
#[derive(Debug, Clone, Serialize)]
pub struct HostSummary {
    pub host: String,
    pub sources: usize,
}

/// Aggregate summary of a corpus directory.
#[derive(Debug, Clone, Serialize)]
pub struct CorpusReport {
    /// Directory that was analyzed.
    pub dir: String,
    // --- inventory ---
    pub bodies: usize,
    pub total_bytes: u64,
    pub sidecars: usize,
    /// Sidecar files that failed to parse.
    pub parse_errors: usize,
    /// Bodies with no matching sidecar (provenance lost).
    pub orphan_bodies: usize,
    /// Sidecars with no matching body (body deleted or never written).
    pub orphan_sidecars: usize,
    // --- sources ---
    pub total_sources: usize,
    pub distinct_hosts: usize,
    /// Per-host source counts, sorted by descending count then host name.
    pub hosts: Vec<HostSummary>,
    // --- staleness ---
    /// Threshold used to classify sources as stale.
    pub stale_days: u64,
    /// Sources whose `last_seen` is within `stale_days` of now.
    pub fresh_sources: usize,
    /// Sources not seen within `stale_days`.
    pub stale_sources: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_last_seen: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_last_seen: Option<u64>,
}

/// Filesystem inventory of a corpus directory: body stems with sizes, and
/// sidecar stems.
struct Scan {
    bodies: HashMap<String, u64>,
    sidecar_names: Vec<String>,
}

fn scan(dir: &Path) -> Result<Scan, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("read dir {}: {e}", dir.display()))?;
    let mut bodies: HashMap<String, u64> = HashMap::new();
    let mut sidecar_names: Vec<String> = Vec::new();

    for entry in rd {
        let entry = entry.map_err(|e| format!("scan {}: {e}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let is_sidecar = path.extension().is_some_and(|x| x == "json");
        if is_sidecar {
            sidecar_names.push(name.trim_end_matches(".json").to_string());
        } else {
            bodies.insert(name, size);
        }
    }
    Ok(Scan {
        bodies,
        sidecar_names,
    })
}

/// Outcome of a pruning pass.
#[derive(Debug, Clone, Serialize)]
pub struct PruneReport {
    pub dir: String,
    /// Threshold used to decide which sources count as stale.
    pub stale_days: u64,
    /// True when nothing was actually modified (plan only).
    pub dry_run: bool,
    /// Bodies deleted (orphans, plus entries emptied by stale pruning).
    pub removed_bodies: usize,
    /// Sidecars deleted (orphans, plus entries emptied by stale pruning).
    pub removed_sidecars: usize,
    /// Stale sources stripped from sidecars that still have fresh ones.
    pub pruned_stale_sources: usize,
    /// Body bytes reclaimed.
    pub freed_bytes: u64,
    /// Corpus contents after pruning.
    pub remaining_bodies: usize,
    pub remaining_sidecars: usize,
    pub remaining_sources: usize,
}

/// Garbage-collect the corpus in `dir`:
///
/// 1. delete orphaned bodies (no sidecar) and orphaned sidecars (no body),
/// 2. strip stale sources (`last_seen < cutoff`) from surviving sidecars,
/// 3. delete any body+sidecar pair left with zero sources.
///
/// With `dry_run` nothing is modified — the report describes exactly what
/// a real pass would do. Unparseable sidecars are always left untouched
/// rather than destroyed.
pub fn prune(dir: &Path, stale_days: u64, dry_run: bool) -> Result<PruneReport, String> {
    // Phase 1 — plan everything in memory so dry-run reports precisely
    // what a destructive pass would do, derived the same way.
    #[derive(Default)]
    struct Plan {
        remove_bodies: Vec<(String, u64)>,
        remove_sidecars: Vec<String>,
        rewrites: Vec<Sidecar>,
        pruned_stale_sources: usize,
        remaining_sources: usize,
    }

    let scan = scan(dir)?;
    let cutoff = now_epoch_secs().saturating_sub(stale_days.saturating_mul(86_400));
    let mut plan = Plan::default();

    // Orphaned bodies.
    for (name, size) in &scan.bodies {
        if !scan.sidecar_names.contains(name) {
            plan.remove_bodies.push((name.clone(), *size));
        }
    }

    for stem in &scan.sidecar_names {
        if !scan.bodies.contains_key(stem) {
            plan.remove_sidecars.push(stem.clone());
            continue;
        }

        let bytes = match std::fs::read(sidecar::path_for(dir, stem)) {
            Ok(b) => b,
            Err(_) => continue, // unreadable: leave untouched
        };
        let mut doc: Sidecar = match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(_) => continue, // unparseable: leave untouched
        };

        let before = doc.sources.len();
        doc.sources.retain(|s| s.last_seen >= cutoff);
        plan.pruned_stale_sources += before - doc.sources.len();

        if doc.sources.is_empty() {
            plan.remove_bodies.push((stem.clone(), scan.bodies[stem]));
            plan.remove_sidecars.push(stem.clone());
        } else {
            plan.remaining_sources += doc.sources.len();
            if before != doc.sources.len() {
                plan.rewrites.push(doc);
            }
        }
    }

    // Phase 2 — apply (or just report).
    let report = PruneReport {
        dir: dir.display().to_string(),
        stale_days,
        dry_run,
        removed_bodies: plan.remove_bodies.len(),
        removed_sidecars: plan.remove_sidecars.len(),
        pruned_stale_sources: plan.pruned_stale_sources,
        freed_bytes: plan.remove_bodies.iter().map(|(_, s)| s).sum(),
        remaining_bodies: scan.bodies.len() - plan.remove_bodies.len(),
        remaining_sidecars: scan.sidecar_names.len() - plan.remove_sidecars.len(),
        remaining_sources: plan.remaining_sources,
    };

    if !dry_run {
        for (name, _) in &plan.remove_bodies {
            std::fs::remove_file(dir.join(name)).map_err(|e| format!("remove {name}: {e}"))?;
        }
        for stem in &plan.remove_sidecars {
            std::fs::remove_file(sidecar::path_for(dir, stem))
                .map_err(|e| format!("remove {stem}.json: {e}"))?;
        }
        for doc in &plan.rewrites {
            let json = serde_json::to_vec_pretty(doc).map_err(|e| format!("serialize: {e}"))?;
            std::fs::write(sidecar::path_for(dir, &doc.content_hash), json)
                .map_err(|e| format!("write {}.json: {e}", doc.content_hash))?;
        }
    }

    Ok(report)
}

/// Analyze the corpus in `dir`. Returns an error only if the directory
/// itself is unreadable; per-file problems are reported as counters.
pub fn analyze(dir: &Path, stale_days: u64) -> Result<CorpusReport, String> {
    let Scan {
        bodies,
        sidecar_names,
    } = scan(dir)?;

    let now = now_epoch_secs();
    let cutoff = now.saturating_sub(stale_days.saturating_mul(86_400));

    let mut parse_errors = 0usize;
    let mut orphan_sidecars = 0usize;
    let mut hosts: HashMap<String, usize> = HashMap::new();
    let mut total_sources = 0usize;
    let mut fresh_sources = 0usize;
    let mut stale_sources = 0usize;
    let mut oldest_last_seen: Option<u64> = None;
    let mut newest_last_seen: Option<u64> = None;

    for stem in &sidecar_names {
        let path = sidecar::path_for(dir, stem);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                parse_errors += 1;
                continue;
            }
        };
        let doc: Sidecar = match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(_) => {
                parse_errors += 1;
                continue;
            }
        };

        if !bodies.contains_key(stem) {
            orphan_sidecars += 1;
        }

        for src in &doc.sources {
            total_sources += 1;
            if src.last_seen >= cutoff {
                fresh_sources += 1;
            } else {
                stale_sources += 1;
            }
            oldest_last_seen =
                Some(oldest_last_seen.map_or(src.last_seen, |o: u64| o.min(src.last_seen)));
            newest_last_seen =
                Some(newest_last_seen.map_or(src.last_seen, |o: u64| o.max(src.last_seen)));

            let host = url::Url::parse(&src.url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .unwrap_or_else(|| "<unknown>".to_string());
            *hosts.entry(host).or_default() += 1;
        }
    }

    let orphan_bodies = bodies
        .keys()
        .filter(|b| !sidecar_names.contains(*b))
        .count();
    let total_bytes = bodies.values().sum();
    let mut hosts: Vec<HostSummary> = hosts
        .into_iter()
        .map(|(host, sources)| HostSummary { host, sources })
        .collect();
    hosts.sort_by(|a, b| b.sources.cmp(&a.sources).then_with(|| a.host.cmp(&b.host)));

    Ok(CorpusReport {
        dir: dir.display().to_string(),
        bodies: bodies.len(),
        total_bytes,
        sidecars: sidecar_names.len(),
        parse_errors,
        orphan_bodies,
        orphan_sidecars,
        total_sources,
        distinct_hosts: hosts.len(),
        hosts,
        stale_days,
        fresh_sources,
        stale_sources,
        oldest_last_seen,
        newest_last_seen,
    })
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidecar::SourceRef;
    use std::path::PathBuf;

    /// Unique temp dir for one test.
    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "corpus-test-{tag}-{}-{:p}",
            std::process::id(),
            &tag
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const HASH_A: &str = "aa0000000000000000000000000000000000000000000000000000000000000a";
    const HASH_B: &str = "bb00000000000000000000000000000000000000000000000000000000000000bb";
    const HASH_C: &str = "cc00000000000000000000000000000000000000000000000000000000000000cc";

    fn write_sidecar(dir: &Path, hash: &str, sources: &[(&str, u64)]) {
        let doc = Sidecar {
            content_hash: hash.to_string(),
            sources: sources
                .iter()
                .map(|(url, seen)| SourceRef {
                    etag: None,
                    last_modified: None,
                    url: url.to_string(),
                    title: None,
                    depth: 0,
                    first_seen: *seen,
                    last_seen: *seen,
                })
                .collect(),
        };
        let json = serde_json::to_vec_pretty(&doc).unwrap();
        std::fs::write(sidecar::path_for(dir, hash), json).unwrap();
    }

    #[test]
    fn summarizes_inventory_hosts_and_staleness() {
        let dir = temp_dir("main");
        std::fs::write(dir.join(HASH_A), b"body-a").unwrap();
        std::fs::write(dir.join(HASH_B), b"body-b-bytes").unwrap();
        write_sidecar(
            &dir,
            HASH_A,
            &[
                ("https://example.com/", 1_700_000_000), // old -> stale at 30 days
                ("https://example.com/dup", now_epoch_secs()),
                ("https://other.org/x", now_epoch_secs()),
            ],
        );
        write_sidecar(&dir, HASH_B, &[("https://example.com/b", now_epoch_secs())]);
        // Orphans on both sides.
        std::fs::write(dir.join(HASH_C), b"no-sidecar").unwrap();
        write_sidecar(
            &dir,
            HASH_D_STEM,
            &[("https://ghost.net/", now_epoch_secs())],
        );

        let report = analyze(&dir, 30).unwrap();

        assert_eq!(report.bodies, 3);
        assert_eq!(report.total_bytes, 6 + 12 + 10);
        assert_eq!(report.sidecars, 3);
        assert_eq!(report.parse_errors, 0);
        assert_eq!(report.orphan_bodies, 1);
        assert_eq!(report.orphan_sidecars, 1);

        assert_eq!(report.total_sources, 5);
        assert_eq!(report.distinct_hosts, 3);
        // Sorted by descending count: example.com has 3 sources.
        assert_eq!(report.hosts[0].host, "example.com");
        assert_eq!(report.hosts[0].sources, 3);

        assert_eq!(report.fresh_sources, 4);
        assert_eq!(report.stale_sources, 1);
        assert_eq!(report.oldest_last_seen, Some(1_700_000_000));
        let newest = report.newest_last_seen.unwrap();
        let now = now_epoch_secs();
        assert!(newest <= now && now - newest <= 2, "newest is ~now");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn counts_unparseable_sidecars_as_errors() {
        let dir = temp_dir("bad");
        std::fs::write(sidecar::path_for(&dir, HASH_A), b"not json{{").unwrap();

        let report = analyze(&dir, 30).unwrap();
        assert_eq!(report.parse_errors, 1);
        assert_eq!(report.total_sources, 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_removes_orphans_stale_sources_and_emptied_entries() {
        let dir = temp_dir("prune");

        // A: mixed fresh/stale sources -> stale stripped, entry survives.
        std::fs::write(dir.join(HASH_A), b"body-a").unwrap();
        write_sidecar(
            &dir,
            HASH_A,
            &[
                ("https://example.com/old", 1_000),
                ("https://example.com/fresh", now_epoch_secs()),
            ],
        );

        // B: all sources stale -> body+sidecar removed entirely.
        std::fs::write(dir.join(HASH_B), b"body-b-bytes").unwrap();
        write_sidecar(&dir, HASH_B, &[("https://example.com/ancient", 1_000)]);

        // C: orphaned body (no sidecar) -> removed.
        std::fs::write(dir.join(HASH_C), b"no-sidecar").unwrap();

        // D: orphaned sidecar (no body) -> removed.
        write_sidecar(
            &dir,
            HASH_D_STEM,
            &[("https://ghost.net/", now_epoch_secs())],
        );

        let report = prune(&dir, 30, false).unwrap();

        assert_eq!(report.removed_bodies, 2); // C orphan + B emptied
        assert_eq!(report.removed_sidecars, 2); // D orphan + B emptied
        assert_eq!(report.pruned_stale_sources, 2); // A old + B ancient
        assert_eq!(report.freed_bytes, 10 + 12); // C + B bodies
        assert_eq!(report.remaining_bodies, 1);
        assert_eq!(report.remaining_sidecars, 1);
        assert_eq!(report.remaining_sources, 1);

        assert!(!dir.join(HASH_B).exists());
        assert!(!sidecar::path_for(&dir, HASH_B).exists());
        assert!(!dir.join(HASH_C).exists());
        assert!(!sidecar::path_for(&dir, HASH_D_STEM).exists());

        // A survived with only its fresh source.
        let bytes = std::fs::read(sidecar::path_for(&dir, HASH_A)).unwrap();
        let doc: Sidecar = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc.sources.len(), 1);
        assert_eq!(doc.sources[0].url, "https://example.com/fresh");

        // Post-prune analysis is clean.
        let after = analyze(&dir, 30).unwrap();
        assert_eq!(after.bodies, 1);
        assert_eq!(after.orphan_bodies, 0);
        assert_eq!(after.orphan_sidecars, 0);
        assert_eq!(after.stale_sources, 0);

        // Pruning again is idempotent.
        let second = prune(&dir, 30, false).unwrap();
        assert_eq!(second.removed_bodies, 0);
        assert_eq!(second.pruned_stale_sources, 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dry_run_reports_the_same_plan_without_modifying_files() {
        let build = |tag: &str| {
            let dir = temp_dir(tag);
            std::fs::write(dir.join(HASH_A), b"body-a").unwrap();
            std::fs::write(dir.join(HASH_B), b"body-b-bytes").unwrap();
            std::fs::write(dir.join(HASH_C), b"no-sidecar").unwrap();
            write_sidecar(
                &dir,
                HASH_A,
                &[
                    ("https://example.com/old", 1_000),
                    ("https://example.com/fresh", now_epoch_secs()),
                ],
            );
            write_sidecar(&dir, HASH_B, &[("https://example.com/ancient", 1_000)]);
            write_sidecar(
                &dir,
                HASH_D_STEM,
                &[("https://ghost.net/", now_epoch_secs())],
            );
            dir
        };

        // Dry run: same numbers as a destructive pass...
        let dir = build("dry");
        let dry = prune(&dir, 30, true).unwrap();
        assert!(dry.dry_run);
        assert_eq!(dry.removed_bodies, 2);
        assert_eq!(dry.removed_sidecars, 2);
        assert_eq!(dry.pruned_stale_sources, 2);
        assert_eq!(dry.freed_bytes, 10 + 12);
        assert_eq!(dry.remaining_bodies, 1);
        assert_eq!(dry.remaining_sources, 1);

        // ...but every file is still on disk.
        for stem in [HASH_A, HASH_B, HASH_C, HASH_D_STEM] {
            assert!(sidecar::path_for(&dir, stem).exists() || dir.join(stem).exists());
        }
        let after_dry = analyze(&dir, 30).unwrap();
        assert_eq!(after_dry.bodies, 3, "nothing deleted in dry run");
        assert_eq!(after_dry.total_sources, 4, "stale sources untouched");
        std::fs::remove_dir_all(&dir).ok();

        // Real pass on an identical corpus produces identical numbers.
        let dir = build("real");
        let real = prune(&dir, 30, false).unwrap();
        assert!(!real.dry_run);
        assert_eq!(real.removed_bodies, dry.removed_bodies);
        assert_eq!(real.removed_sidecars, dry.removed_sidecars);
        assert_eq!(real.pruned_stale_sources, dry.pruned_stale_sources);
        assert_eq!(real.freed_bytes, dry.freed_bytes);
        assert_eq!(real.remaining_sources, dry.remaining_sources);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_leaves_unparseable_sidecars_alone() {
        let dir = temp_dir("prune-bad");
        std::fs::write(dir.join(HASH_A), b"body").unwrap();
        std::fs::write(sidecar::path_for(&dir, HASH_A), b"not json{{").unwrap();

        let report = prune(&dir, 30, false).unwrap();
        assert_eq!(report.removed_bodies, 0);
        assert_eq!(report.removed_sidecars, 0);
        assert!(dir.join(HASH_A).exists(), "body untouched");
        assert!(
            sidecar::path_for(&dir, HASH_A).exists(),
            "bad sidecar untouched"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_directory_is_an_error() {
        assert!(analyze(Path::new("/nonexistent/corpus-dir-xyz"), 30).is_err());
        assert!(prune(Path::new("/nonexistent/corpus-dir-xyz"), 30, false).is_err());
    }

    const HASH_D_STEM: &str = "dd000000000000000000000000000000000000000000000000000000000000dd";
}
