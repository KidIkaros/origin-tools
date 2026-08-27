// SPDX-License-Identifier: Apache-2.0

//! Integration tests for origin-crawler.
//!
//! All tests run against a local HTTP server spawned inside the test
//! process — no external network access. The fixture site exercises every
//! crawler behavior: relative/absolute links, robots.txt disallow,
//! duplicate content, a spider trap, a 404, and non-HTML content types.

use std::collections::HashMap;

use origin_crawler::crawler::{self, CrawlConfig};

#[tokio::test]
async fn corpus_report_summarizes_crawled_save_dir() {
    let base = spawn_server().await;
    let dir = std::env::temp_dir().join(format!(
        "origin-crawler-corpus-{}-{:p}",
        std::process::id(),
        &base
    ));

    // Build a real corpus via a crawl.
    let mut cfg = test_config(format!("{base}/"));
    cfg.save_dir = Some(dir.clone());
    let crawl = crawler::run(cfg).await.unwrap();

    let report = origin_crawler::corpus::analyze(&dir, 30).unwrap();
    assert_eq!(
        report.bodies,
        crawl
            .pages
            .iter()
            .map(|p| p.content_hash.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len()
    );
    assert_eq!(report.sidecars, report.bodies);
    assert_eq!(report.parse_errors, 0);
    assert_eq!(report.orphan_bodies, 0);
    assert_eq!(report.orphan_sidecars, 0);
    assert_eq!(
        report.total_sources, report.fresh_sources,
        "freshly crawled corpus is fresh"
    );
    assert!(report.distinct_hosts >= 1);
    assert!(report.total_bytes > 0);
    assert_eq!(
        report.hosts.iter().map(|h| h.sources).sum::<usize>(),
        report.total_sources
    );

    // CLI surface: `corpus --save-dir` emits the same shape as JSON.
    let bin = env!("CARGO_BIN_EXE_origin-crawler");
    let out = std::process::Command::new(bin)
        .args(["corpus", "--save-dir"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "corpus cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("stdout is JSON");
    assert_eq!(parsed["bodies"].as_u64(), Some(report.bodies as u64));
    assert_eq!(
        parsed["total_sources"].as_u64(),
        Some(report.total_sources as u64)
    );

    // --prune on a fresh corpus removes nothing.
    let out = std::process::Command::new(bin)
        .args(["corpus", "--save-dir"])
        .arg(&dir)
        .args(["--stale-days", "30", "--prune"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "prune cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pruned: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(pruned["removed_bodies"].as_u64(), Some(0));
    assert_eq!(pruned["removed_sidecars"].as_u64(), Some(0));

    // Age one body's sources to the epoch, then prune the entry away.
    let victim_body = &body_files(&dir)[0];
    let mut aged = read_sidecar(victim_body);
    for s in &mut aged.sources {
        s.last_seen = 0;
        s.first_seen = 0;
    }
    let mut sidecar_os = victim_body.clone().into_os_string();
    sidecar_os.push(".json");
    let path = std::path::PathBuf::from(sidecar_os);
    std::fs::write(&path, serde_json::to_vec_pretty(&aged).unwrap()).unwrap();

    // Dry run reports the removal but leaves the files in place.
    let out = std::process::Command::new(bin)
        .args(["corpus", "--save-dir"])
        .arg(&dir)
        .args(["--stale-days", "30", "--prune", "--dry-run"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "dry-run cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dry: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(dry["dry_run"].as_bool(), Some(true));
    assert_eq!(dry["removed_bodies"].as_u64(), Some(1));
    assert!(path.exists(), "dry run modified nothing");

    // Real prune removes the aged entry.
    let out = std::process::Command::new(bin)
        .args(["corpus", "--save-dir"])
        .arg(&dir)
        .args(["--stale-days", "30", "--prune"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "prune cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pruned: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(pruned["removed_bodies"].as_u64(), Some(1));
    assert_eq!(pruned["removed_sidecars"].as_u64(), Some(1));
    assert!(!path.exists(), "emptied entry removed");

    std::fs::remove_dir_all(&dir).ok();
}

/// Minimal single-threaded-per-connection HTTP/1.1 fixture server.
async fn spawn_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(handle(sock));
        }
    });
    format!("http://{addr}")
}

fn page(title: &str, links: &[&str], body_extra: &str) -> String {
    let anchors: String = links
        .iter()
        .map(|l| format!("<a href=\"{l}\">{l}</a>"))
        .collect();
    format!("<html><head><title>{title}</title></head><body>{anchors}{body_extra}</body></html>")
}

async fn handle(mut sock: tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Base URL for fixtures that must emit absolute URLs (the sitemap).
    let self_addr = sock.local_addr().map(|a| a.to_string()).unwrap_or_default();
    let base = format!("http://{self_addr}");

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    // Read until the end of the request head.
    loop {
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
                    break;
                }
            }
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let has_if_none_match = head.to_ascii_lowercase().contains("if-none-match");
    let path = head
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();

    let (status, ctype, body): (u16, &str, Vec<u8>) = if path == "/robots.txt" {
        // Declares a sitemap at a NON-conventional path: seeding must
        // harvest it from here instead of probing /sitemap.xml.
        (
            200,
            "text/plain",
            format!("User-agent: *\nDisallow: /private/\nSitemap: {base}/site-map.xml\n")
                .into_bytes(),
        )
    } else if path == "/site-map.xml" || path == "/sitemap.xml" {
        // The conventional /sitemap.xml lists only sm1+sm2; the declared
        // site-map.xml additionally lists the served /sm3 — letting tests
        // distinguish robots-harvested seeding from fallback probing.
        (
            200,
            "application/xml",
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\
                 <url><loc>{base}/sm1</loc></url>\
                 <url><loc>/sm2</loc></url>{}\
                 </urlset>",
                if path == "/site-map.xml" {
                    format!("<url><loc>{base}/sm3</loc></url>")
                } else {
                    String::new()
                }
            )
            .into_bytes(),
        )
    } else if path == "/sm1" {
        // Reachable ONLY through the sitemap — no page links to it.
        (
            200,
            "text/html",
            page("Sm One", &[], "<p>sitemap-only content</p>").into_bytes(),
        )
    } else if path == "/sm3" {
        (
            200,
            "text/html",
            page("Sm Three", &[], "<p>declared-sitemap content</p>").into_bytes(),
        )
    } else if path == "/etag" {
        // Versioned resource: revalidation via If-None-Match yields a 304.
        if has_if_none_match {
            (304, "", vec![])
        } else {
            (
                200,
                "text/html",
                page("Etagged", &[], "<p>versioned content</p>").into_bytes(),
            )
        }
    } else if path == "/" {
        (
            200,
            "text/html",
            page(
                "Index",
                &[
                    "a",
                    "/b",
                    "/dup1",
                    "/dup2",
                    "/dup3",
                    "/private/secret",
                    "/trap/0",
                ],
                "",
            )
            .into_bytes(),
        )
    } else if path == "/a" {
        (
            200,
            "text/html",
            page("Page A", &["/"], "<p>unique content A</p>").into_bytes(),
        )
    } else if path == "/b" {
        (
            200,
            "text/html",
            page("Page B", &["/"], "<p>unique content B</p>").into_bytes(),
        )
    } else if path.starts_with("/dup") {
        // Identical bodies across distinct URLs -> content dedup.
        (
            200,
            "text/html",
            page("Dup", &[], "<p>DUPLICATE CONTENT</p>").into_bytes(),
        )
    } else if path == "/private/secret" {
        // Blocked by robots.txt; the crawler must never fetch it.
        panic!("crawler fetched a robots-disallowed URL");
    } else if let Some(n) = path
        .strip_prefix("/trap/")
        .and_then(|s| s.parse::<usize>().ok())
    {
        if n >= 500 {
            (200, "text/html", page("Trap End", &[], "").into_bytes())
        } else {
            (
                200,
                "text/html",
                page("Trap", &[&format!("/trap/{}", n + 1)], "").into_bytes(),
            )
        }
    } else if path == "/binary" {
        (200, "application/octet-stream", vec![0u8; 64])
    } else {
        (404, "text/plain", b"404".to_vec())
    };

    // Numeric status code is mandatory on the status line — hyper rejects
    // bare reason phrases. 304 responses carry no body or content-type;
    // /etag advertises its validator on 200s so crawls can record it.
    let reason = match status {
        200 => "OK",
        304 => "Not Modified",
        _ => "Not Found",
    };
    let mut resp = format!("HTTP/1.1 {status} {reason}\r\n");
    if status != 304 {
        resp.push_str(&format!("Content-Type: {ctype}\r\n"));
        if path == "/etag" {
            resp.push_str("ETag: \"e1\"\r\n");
        }
    }
    resp.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let _ = sock.write_all(resp.as_bytes()).await;
    let _ = sock.write_all(&body).await;
    let _ = sock.shutdown().await;
}

/// Config tuned for the local fixture: no politeness delay, stay on-site.
fn test_config(seed: String) -> CrawlConfig {
    CrawlConfig {
        seeds: vec![seed],
        max_pages: 20,
        max_depth: 6,
        delay_ms: 0,
        timeout_ms: 5_000,
        concurrency: 3,
        user_agent: "origin-crawler/test".to_string(),
        max_pages_per_host: 100,
        respect_robots: true,
        same_site_only: true,
        save_dir: None,
        resume: false,
        use_sitemaps: false,
    }
}

/// Save-dir entries that are stored *bodies* (i.e. not `.json` sidecars).
fn body_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_none_or(|x| x != "json"))
        .collect()
}

/// Parse the sidecar for a given body path.
fn read_sidecar(body: &std::path::Path) -> origin_crawler::sidecar::Sidecar {
    let mut path = body.as_os_str().to_owned();
    path.push(".json");
    let bytes = std::fs::read(&path).expect("sidecar exists");
    serde_json::from_slice(&bytes).expect("sidecar is valid JSON")
}

#[tokio::test]
async fn crawls_links_respects_robots_and_dedups() {
    let base = spawn_server().await;
    let report = crawler::run(test_config(format!("{base}/"))).await.unwrap();

    let urls: Vec<&str> = report.pages.iter().map(|p| p.url.as_str()).collect();

    // Index + unique pages discovered through relative and absolute hrefs.
    assert!(urls.iter().any(|u| u.ends_with('/')), "seed crawled");
    assert!(
        urls.iter().any(|u| u.ends_with("/a")),
        "relative link followed"
    );
    assert!(
        urls.iter().any(|u| u.ends_with("/b")),
        "absolute-path link followed"
    );

    // Only one of the three identical dup pages is stored.
    let dups = urls.iter().filter(|u| u.contains("/dup")).count();
    assert_eq!(dups, 1, "dedup keeps one copy of identical content");
    assert!(report.duplicates_skipped >= 2);

    // robots.txt blocked /private/secret.
    assert_eq!(report.blocked_by_robots, 1);
    assert!(report.pages.iter().all(|p| !p.url.contains("/private")));

    // Titles extracted.
    let index = report.pages.iter().find(|p| p.url.ends_with('/')).unwrap();
    assert_eq!(index.title.as_deref(), Some("Index"));
    assert!(index.content_hash.len() == 64, "BLAKE3 hex digest");

    // Bookkeeping is coherent.
    assert_eq!(report.pages_crawled, report.pages.len());
    assert!(report.pages_crawled <= 20);
    assert!(!report.hosts.is_empty());
}

#[tokio::test]
async fn spider_trap_is_bounded() {
    let base = spawn_server().await;
    let mut cfg = test_config(format!("{base}/trap/0"));
    // Depth must exceed the chain so the QUOTA is what stops the crawl,
    // not the depth limit.
    cfg.max_depth = 1_000;
    cfg.max_pages = 10;
    cfg.max_pages_per_host = 8;

    let report = crawler::run(cfg).await.unwrap();
    assert!(
        report.pages.len() <= 10,
        "page budget bounds trap crawling: {}",
        report.pages.len()
    );
    // The quota guard kicks in before the budget would.
    assert!(report.quota_skipped > 0);
}

#[tokio::test]
async fn depth_limit_stops_descending() {
    let base = spawn_server().await;
    let mut cfg = test_config(format!("{base}/trap/0"));
    cfg.max_depth = 2;
    cfg.max_pages = 100;

    let report = crawler::run(cfg).await.unwrap();
    assert!(report.pages.iter().all(|p| p.depth <= 2), "depth respected");
    // depth 0 + 1 + 2 of the chain only.
    assert_eq!(report.pages.len(), 3);
}

#[tokio::test]
async fn non_html_and_404_count_as_failures() {
    let base = spawn_server().await;
    let server = reqwest::get(format!("{base}/binary")).await.unwrap();
    // Sanity-check the fixture itself serves binary content.
    assert_eq!(server.status().as_u16(), 200);

    // The crawler never links to them in this fixture, so drive the
    // downloader directly instead.
    let dl = origin_crawler::downloader::Downloader::new(5_000, "test").unwrap();
    assert!(dl
        .fetch_text(&url::Url::parse(&format!("{base}/binary")).unwrap())
        .await
        .is_err());
    assert!(dl
        .fetch_text(&url::Url::parse(&format!("{base}/missing")).unwrap())
        .await
        .is_err());
    assert!(dl
        .fetch_text(&url::Url::parse(&format!("{base}/a")).unwrap())
        .await
        .is_ok());
}

#[tokio::test]
async fn save_dir_stores_bodies_keyed_by_content_hash() {
    let base = spawn_server().await;

    let dir = std::env::temp_dir().join(format!(
        "origin-crawler-test-{}-{:p}",
        std::process::id(),
        &base
    ));

    let mut cfg = test_config(format!("{base}/"));
    cfg.save_dir = Some(dir.clone());
    let report = crawler::run(cfg).await.unwrap();

    assert!(!report.pages.is_empty());
    for page in &report.pages {
        let path = page.saved_path.as_deref().expect("saved path recorded");
        // File is keyed by the BLAKE3 hex digest.
        let file_name = std::path::Path::new(path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(file_name, page.content_hash);

        // Body on disk matches the reported length.
        let body = std::fs::read(path).expect("body saved");
        assert_eq!(body.len(), page.body_len);
    } // One file per *unique* content — dedup pages share a hash, so the
      // number of files equals the distinct hashes in the report.
    let mut hashes: Vec<&str> = report
        .pages
        .iter()
        .map(|p| p.content_hash.as_str())
        .collect();
    hashes.sort_unstable();
    hashes.dedup();
    let stored = body_files(&dir);
    assert_eq!(stored.len(), hashes.len()); // Every body has a sidecar listing its storer's URL (plus any
                                            // duplicate URLs that mapped onto the same content during the run).
    for body in &stored {
        let sidecar = read_sidecar(body);
        assert_eq!(sidecar.content_hash.len(), 64);
        assert!(!sidecar.sources.is_empty());
        let hash = body.file_name().unwrap().to_str().unwrap();
        let storer = report
            .pages
            .iter()
            .find(|p| p.content_hash == hash)
            .unwrap();
        // The storer's own entry is never re-encountered within a run, so
        // its two timestamps coincide.
        assert!(
            sidecar
                .sources
                .iter()
                .any(|s| s.url == storer.url && s.first_seen == s.last_seen),
            "storer recorded with matching timestamps"
        );
        assert!(sidecar.sources.iter().all(|s| s.first_seen > 0));
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn resume_mode_skips_hashes_already_in_save_dir() {
    let base = spawn_server().await;

    let dir = std::env::temp_dir().join(format!(
        "origin-crawler-resume-{}-{:p}",
        std::process::id(),
        &base
    ));

    // First pass: crawl fresh into the save dir.
    let mut cfg = test_config(format!("{base}/"));
    cfg.save_dir = Some(dir.clone());
    let first = crawler::run(cfg.clone()).await.unwrap();
    assert!(!first.pages.is_empty());

    let stored_before = body_files(&dir).len();
    assert!(stored_before > 0);

    // Second pass over the same dir: every unique body is already on disk,
    // so nothing new may be stored.
    cfg.resume = true;
    let second = crawler::run(cfg).await.unwrap();

    assert_eq!(
        second.resumed_hashes, stored_before,
        "pre-loaded one hash per stored file"
    );
    assert_eq!(second.pages_crawled, 0, "no page re-stored in resume mode");
    assert!(
        second.duplicates_skipped > 0,
        "encountered bodies deduped against the corpus"
    );
    assert_eq!(body_files(&dir).len(), stored_before, "save dir unchanged");

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn resume_run_appends_sources_to_sidecars() {
    let base = spawn_server().await;
    let dir = std::env::temp_dir().join(format!(
        "origin-crawler-sidecar-{}-{:p}",
        std::process::id(),
        &base
    ));

    let mut cfg = test_config(format!("{base}/"));
    cfg.save_dir = Some(dir.clone());
    crawler::run(cfg.clone()).await.unwrap();

    let snapshot_before: Vec<Vec<(String, u64, u64)>> = body_files(&dir)
        .iter()
        .map(|b| {
            read_sidecar(b)
                .sources
                .into_iter()
                .map(|s| (s.url, s.first_seen, s.last_seen))
                .collect()
        })
        .collect();

    // Resume pass: already-recorded URLs must NOT be appended twice — only
    // their last_seen refreshed.
    cfg.resume = true;
    crawler::run(cfg).await.unwrap();

    let snapshot_after: Vec<Vec<(String, u64, u64)>> = body_files(&dir)
        .iter()
        .map(|b| {
            read_sidecar(b)
                .sources
                .into_iter()
                .map(|s| (s.url, s.first_seen, s.last_seen))
                .collect()
        })
        .collect();

    // Same URL sets, in the same order.
    let urls_before: Vec<Vec<&str>> = snapshot_before
        .iter()
        .map(|v| v.iter().map(|(u, _, _)| u.as_str()).collect())
        .collect();
    let urls_after: Vec<Vec<&str>> = snapshot_after
        .iter()
        .map(|v| v.iter().map(|(u, _, _)| u.as_str()).collect())
        .collect();
    assert_eq!(urls_after, urls_before, "resume adds no duplicate sources");

    // first_seen stable, last_seen never goes backwards.
    for (before_body, after_body) in snapshot_before.iter().zip(&snapshot_after) {
        for ((_, fs_b, ls_b), (_, fs_a, ls_a)) in before_body.iter().zip(after_body) {
            assert_eq!(fs_b, fs_a, "first_seen is immutable");
            assert!(ls_a >= ls_b, "last_seen refreshed on re-encounter");
        }
    }

    let total_sources: usize = snapshot_after.iter().map(Vec::len).sum();
    assert!(
        total_sources > body_files(&dir).len(),
        "resume accumulated extra sources onto sidecars"
    );
    let multi: Vec<_> = body_files(&dir)
        .iter()
        .map(|b| read_sidecar(b))
        .filter(|s| s.sources.len() >= 2)
        .collect();
    assert!(!multi.is_empty(), "some sidecar lists several source URLs");
    for s in multi {
        let urls: Vec<&str> = s.sources.iter().map(|r| r.url.as_str()).collect();
        assert!(urls.windows(2).all(|w| w[0] != w[1]), "no dup entries");
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn resume_without_save_dir_is_rejected() {
    let mut cfg = CrawlConfig {
        seeds: vec!["http://127.0.0.1:1/".to_string()],
        ..test_config("http://127.0.0.1:1/".to_string())
    };
    cfg.resume = true;
    let err = crawler::run(cfg).await.unwrap_err();
    assert!(err.contains("resume requires save_dir"));
}

#[tokio::test]
async fn sitemap_seeding_adds_unlinked_urls() {
    let base = spawn_server().await;

    // With seeding + robots compliance: robots.txt declares /site-map.xml,
    // whose three entries (sm1 absolute, sm2 relative-unserved, sm3 served)
    // must be harvested INSTEAD of probing /sitemap.xml (which only lists
    // two).
    let mut cfg = test_config(format!("{base}/"));
    cfg.use_sitemaps = true;
    let with = crawler::run(cfg).await.unwrap();
    assert_eq!(with.sitemap_urls, 3, "robots-declared document harvested");
    assert!(
        with.pages.iter().any(|p| p.url.ends_with("/sm1")),
        "sitemap-only page crawled"
    );
    assert!(
        with.pages.iter().any(|p| p.url.ends_with("/sm3")),
        "sm3 proves the DECLARED doc was used rather than a probe"
    );
    assert_eq!(with.pages_failed, 1, "/sm2 is deliberately unserved");

    // Without robots compliance there is no declaration to harvest, so the
    // conventional /sitemap.xml is probed instead. Seed /a with depth 0 so
    // the disallowed /private branch is never discovered.
    let mut cfg = test_config(format!("{base}/a"));
    cfg.use_sitemaps = true;
    cfg.respect_robots = false;
    cfg.max_depth = 0;
    let probed = crawler::run(cfg).await.unwrap();
    assert_eq!(probed.sitemap_urls, 2, "fallback probe used");
    assert!(probed.pages.iter().any(|p| p.url.ends_with("/sm1")));

    // Without seeding: no sitemap fetch happens at all.
    let without = crawler::run(test_config(format!("{base}/"))).await.unwrap();
    assert_eq!(without.sitemap_urls, 0);
    assert!(!without.pages.iter().any(|p| p.url.ends_with("/sm1")));
}

#[tokio::test]
async fn resume_revalidates_with_stored_etag() {
    let base = spawn_server().await;
    let dir = std::env::temp_dir().join(format!(
        "origin-crawler-revalidate-{}-{:p}",
        std::process::id(),
        &base
    ));

    // First pass stores the etagged page and its response validator.
    let mut cfg = test_config(format!("{base}/etag"));
    cfg.save_dir = Some(dir.clone());
    let first = crawler::run(cfg.clone()).await.unwrap();
    assert_eq!(first.pages_crawled, 1);
    assert_eq!(first.revalidated, 0);
    let sc = read_sidecar(&body_files(&dir)[0]);
    assert_eq!(sc.sources.len(), 1);
    assert_eq!(sc.sources[0].etag.as_deref(), Some("\"e1\""));

    // Resume pass: the conditional request is answered by a 304 — the URL
    // costs no download, no budget, and no store.
    cfg.resume = true;
    let second = crawler::run(cfg).await.unwrap();
    assert_eq!(second.revalidated, 1, "304 short-circuits the fetch");
    assert_eq!(second.pages_crawled, 0);
    assert_eq!(body_files(&dir).len(), 1, "save dir unchanged");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cli_prints_json_report() {
    // The fixture server must live on a dedicated thread whose runtime is
    // driven for the whole child-process lifetime — hence the pending()
    // after startup.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let base = spawn_server().await;
                tx.send(base).unwrap();
                std::future::pending::<()>().await;
            });
    });
    let base = rx.recv().unwrap();

    let bin = env!("CARGO_BIN_EXE_origin-crawler");
    let save_dir = std::env::temp_dir().join(format!("origin-crawler-cli-{}", std::process::id()));
    let out = std::process::Command::new(bin)
        .args([
            "crawl",
            &format!("{base}/"),
            "--max-pages",
            "10",
            "--max-depth",
            "3",
            "--delay-ms",
            "0",
            "--concurrency",
            "2",
            "--same-site-only",
            "--sitemaps",
            "--save-dir",
        ])
        .arg(&save_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "cli failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: HashMap<String, serde_json::Value> =
        serde_json::from_str(stdout.trim()).expect("stdout is JSON");
    assert_eq!(
        parsed["pages_crawled"].as_u64().unwrap() as usize,
        parsed["pages"].as_array().unwrap().len()
    );
    assert!(parsed["pages_crawled"].as_u64().unwrap() >= 4);
    assert_eq!(
        parsed["sitemap_urls"].as_u64(),
        Some(3),
        "--sitemaps injected the robots-declared document's three loc entries"
    );

    // --save-dir stored every unique body on disk.
    let stored = std::fs::read_dir(&save_dir)
        .expect("save dir populated")
        .count();
    assert!(stored > 0, "bodies written to --save-dir");
    std::fs::remove_dir_all(&save_dir).ok();
}
