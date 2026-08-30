// SPDX-License-Identifier: Apache-2.0

//! Dogfood: `origin-crawler` as a foundational dependency.
//!
//! The polite BFS crawler as a library: this example stands up a tiny
//! local fixture site (index → pages, robots.txt with a disallow, and
//! duplicate content), then drives `origin_crawler::crawler::run` —
//! the same public API a downstream project would call — and asserts
//! the crawl follows links, honors robots.txt, and content-dedups.
//! No external network access.
//!
//! Run with: `cargo run -p origin-crawler --example dogfood`

use std::sync::atomic::{AtomicU64, Ordering};

use origin_crawler::corpus;
use origin_crawler::crawler::{self, CrawlConfig};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch(label: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir().join("origin-dogfood-crawler");
    let dir = base.join(format!(
        "{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Minimal HTTP/1.1 fixture site: `/`, `/a`, `/b`, `/dup1` + `/dup2`
/// (identical bodies), `/private/secret` (robots-disallowed), robots.txt.
async fn spawn_fixture() -> String {
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

fn page(title: &str, links: &[&str]) -> String {
    let anchors: String = links
        .iter()
        .map(|l| format!("<a href=\"{l}\">{l}</a>"))
        .collect();
    format!("<html><head><title>{title}</title></head><body>{anchors}</body></html>")
}

async fn handle(mut sock: tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
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
    let path = head
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();

    let (status, ctype, body): (u16, &str, Vec<u8>) = match path.as_str() {
        "/robots.txt" => (
            200,
            "text/plain",
            b"User-agent: *\nDisallow: /private/\n".to_vec(),
        ),
        "/" => (
            200,
            "text/html",
            page("Index", &["/a", "/b", "/dup1", "/dup2", "/private/secret"]).into_bytes(),
        ),
        "/a" => (200, "text/html", page("Page A", &["/"]).into_bytes()),
        "/b" => (200, "text/html", page("Page B", &["/"]).into_bytes()),
        "/dup1" | "/dup2" => (200, "text/html", page("Dup", &["/"]).into_bytes()),
        "/private/secret" => panic!("crawler fetched a robots-disallowed URL"),
        _ => (404, "text/plain", b"404".to_vec()),
    };

    let reason = match status {
        200 => "OK",
        _ => "Not Found",
    };
    let mut resp = format!("HTTP/1.1 {status} {reason}\r\n");
    resp.push_str(&format!("Content-Type: {ctype}\r\n"));
    resp.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let _ = sock.write_all(resp.as_bytes()).await;
    let _ = sock.write_all(&body).await;
    let _ = sock.shutdown().await;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = spawn_fixture().await;
    let save_dir = scratch("corpus");

    let cfg = CrawlConfig {
        seeds: vec![format!("{base}/")],
        max_pages: 10,
        max_depth: 4,
        delay_ms: 0,
        timeout_ms: 5_000,
        concurrency: 3,
        user_agent: "origin-crawler/dogfood".to_string(),
        max_pages_per_host: 100,
        respect_robots: true,
        same_site_only: true,
        save_dir: Some(save_dir.clone()),
        resume: false,
        use_sitemaps: false,
    };

    // ── crawl ────────────────────────────────────────────────────────
    let report = crawler::run(cfg).await?;
    let urls: Vec<&str> = report.pages.iter().map(|p| p.url.as_str()).collect();

    assert!(urls.iter().any(|u| u.ends_with('/')), "seed crawled");
    assert!(urls.iter().any(|u| u.ends_with("/a")), "link /a followed");
    assert!(urls.iter().any(|u| u.ends_with("/b")), "link /b followed");
    assert!(
        report.pages.iter().all(|p| !p.url.contains("/private")),
        "robots-disallowed URL never fetched"
    );
    assert_eq!(report.blocked_by_robots, 1, "one robots block recorded");
    assert!(
        report.duplicates_skipped >= 1,
        "identical /dup1 + /dup2 bodies deduped"
    );
    let dup_stored = urls.iter().filter(|u| u.contains("/dup")).count();
    assert_eq!(dup_stored, 1, "only one copy of duplicate content stored");
    let index = report.pages.iter().find(|p| p.url.ends_with('/')).unwrap();
    assert_eq!(index.title.as_deref(), Some("Index"));
    assert_eq!(index.content_hash.len(), 64, "BLAKE3 hex content hash");
    println!(
        "✓ crawled {} pages, {} duplicates skipped, {} robots-blocked (title extraction + BLAKE3 dedup)",
        report.pages_crawled, report.duplicates_skipped, report.blocked_by_robots
    );

    // ── corpus analysis over the save-dir ────────────────────────────
    let analysis = corpus::analyze(&save_dir, 30).map_err(|e| e.to_string())?;
    assert_eq!(
        analysis.bodies,
        report
            .pages
            .iter()
            .map(|p| p.content_hash.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len()
    );
    assert_eq!(analysis.orphan_bodies, 0);
    assert!(analysis.total_bytes > 0);
    println!(
        "✓ corpus analysis: {} bodies, {} sources, {} hosts",
        analysis.bodies, analysis.total_sources, analysis.distinct_hosts
    );

    // ── resume: second pass skips everything already stored ──────────
    let resume_cfg = CrawlConfig {
        seeds: vec![format!("{base}/")],
        max_pages: 10,
        max_depth: 4,
        delay_ms: 0,
        timeout_ms: 5_000,
        concurrency: 3,
        user_agent: "origin-crawler/dogfood".to_string(),
        max_pages_per_host: 100,
        respect_robots: true,
        same_site_only: true,
        save_dir: Some(save_dir.clone()),
        resume: true,
        use_sitemaps: false,
    };
    let second = crawler::run(resume_cfg.clone()).await?;
    assert_eq!(
        second.resumed_hashes, analysis.bodies,
        "pre-loaded saved hashes"
    );
    assert_eq!(second.pages_crawled, 0, "nothing re-stored");
    assert!(second.duplicates_skipped > 0);
    println!(
        "✓ resume mode: {} hashes pre-loaded, no re-download",
        second.resumed_hashes
    );

    // ── validation: config errors surface up front ───────────────────
    let empty = crawler::run(CrawlConfig {
        seeds: vec![],
        ..resume_cfg
    })
    .await;
    assert!(empty.is_err(), "empty seeds must be rejected up front");
    println!("✓ config validation (empty seeds rejected)");

    std::fs::remove_dir_all(&save_dir).ok();
    println!("\norigin-crawler dogfood OK — usable as a foundational dependency");
    Ok(())
}
