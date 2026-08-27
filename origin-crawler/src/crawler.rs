// SPDX-License-Identifier: Apache-2.0

//! Crawl orchestrator — bounded-concurrency workers over a shared priority
//! URL frontier with politeness slots, robots.txt gating (including sitemap
//! harvesting), and BLAKE3 content de-duplication (hashing goes through
//! origin-crypto-sdk, per suite policy: no tool implements its own crypto).
//!
//! The result is a JSON-serializable [`CrawlReport`] suitable for piping
//! into other tools.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use url::Url;

use crate::downloader::{self, Downloader, FetchOutcome};
use crate::frontier::Frontier;
use crate::parser;
use crate::robots::Robots;
use crate::sidecar::{self, SourceRef};

/// Hard cap on any single queued URL's length (spider-trap guard).
const MAX_URL_LEN: usize = 2048;

/// Tunables for a crawl run.
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    pub seeds: Vec<String>,
    /// Stop after this many successfully stored pages.
    pub max_pages: usize,
    /// Maximum BFS depth below the seeds (seeds are depth 0).
    pub max_depth: usize,
    /// Politeness delay enforced per host between consecutive requests.
    pub delay_ms: u64,
    /// Per-request HTTP timeout.
    pub timeout_ms: u64,
    /// Number of concurrent worker tasks.
    pub concurrency: usize,
    pub user_agent: String,
    /// Per-host page quota (spider-trap guard).
    pub max_pages_per_host: usize,
    /// Fetch and honor robots.txt.
    pub respect_robots: bool,
    /// Restrict discovery to the seed URLs' host(s).
    pub same_site_only: bool,
    /// If set, store each unique page body as `<dir>/<blake3-hex>`.
    pub save_dir: Option<PathBuf>,
    /// Resume mode: pre-load content hashes from files already in
    /// `save_dir` so stored pages are skipped instead of re-fetched.
    /// Requires `save_dir`.
    pub resume: bool,
    /// Before BFS starts, fetch `/sitemap.xml` for each seed origin and
    /// enqueue its listed URLs as extra depth-0 seeds.
    pub use_sitemaps: bool,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            seeds: Vec::new(),
            max_pages: 100,
            max_depth: 3,
            delay_ms: 250,
            timeout_ms: 10_000,
            concurrency: 4,
            user_agent: format!("origin-crawler/{}", env!("CARGO_PKG_VERSION")),
            max_pages_per_host: 50,
            respect_robots: true,
            same_site_only: false,
            save_dir: None,
            resume: false,
            use_sitemaps: false,
        }
    }
}

/// One stored page in the crawl report.
#[derive(Debug, Clone, Serialize)]
pub struct PageRecord {
    pub url: String,
    pub status: u16,
    pub depth: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(rename = "bytes")]
    pub body_len: usize,
    /// Hex BLAKE3 of the body — the dedup key.
    pub content_hash: String,
    /// Path the body was saved to, when `save_dir` is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_path: Option<String>,
}

/// Aggregate outcome of a crawl run.
#[derive(Debug, Default, Serialize)]
pub struct CrawlReport {
    pub pages_crawled: usize,
    pub pages_failed: usize,
    pub urls_discovered: usize,
    pub duplicates_skipped: usize,
    pub blocked_by_robots: usize,
    pub quota_skipped: usize,
    /// Number of hashes pre-loaded from `save_dir` in resume mode.
    #[serde(skip_serializing_if = "is_zero")]
    pub resumed_hashes: usize,
    /// URLs injected from sitemaps when seeding is enabled.
    #[serde(skip_serializing_if = "is_zero")]
    pub sitemap_urls: usize,
    /// Pages answered by `304 Not Modified` — only possible in resume mode
    /// with stored HTTP validators.
    #[serde(skip_serializing_if = "is_zero")]
    pub revalidated: usize,
    pub hosts: Vec<String>,
    pub elapsed_ms: u128,
    pub pages: Vec<PageRecord>,
}

struct SharedState {
    frontier: Mutex<Frontier>,
    robots_cache: Mutex<HashMap<String, Option<Robots>>>,
    content_seen: Mutex<HashSet<[u8; 32]>>,
    hosts_seen: Mutex<HashSet<String>>,
    pages: Mutex<Vec<PageRecord>>,
    /// Serializes sidecar read-modify-write cycles across workers.
    /// Async-aware because it is held across file I/O awaits.
    sidecar_lock: tokio::sync::Mutex<()>,
    /// Remaining page budget; consumed atomically so `max_pages` is exact.
    budget: Mutex<usize>,
    inflight: AtomicUsize,
    failed: AtomicUsize,
    duplicates: AtomicUsize,
    blocked: AtomicUsize,
    quota_skipped: AtomicUsize,
    discovered: AtomicUsize,
    revalidated: AtomicUsize,
}

impl SharedState {
    fn new(max_pages: usize, seed_hosts: &[String]) -> Self {
        Self {
            frontier: Mutex::new(Frontier::new(MAX_URL_LEN, seed_hosts.iter().cloned())),
            robots_cache: Mutex::new(HashMap::new()),
            content_seen: Mutex::new(HashSet::new()),
            hosts_seen: Mutex::new(HashSet::new()),
            pages: Mutex::new(Vec::new()),
            sidecar_lock: tokio::sync::Mutex::new(()),
            budget: Mutex::new(max_pages),
            inflight: AtomicUsize::new(0),
            failed: AtomicUsize::new(0),
            duplicates: AtomicUsize::new(0),
            blocked: AtomicUsize::new(0),
            quota_skipped: AtomicUsize::new(0),
            discovered: AtomicUsize::new(0),
            revalidated: AtomicUsize::new(0),
        }
    }

    fn enqueue(&self, url: Url, depth: usize) {
        let added = self.frontier.lock().unwrap().push(url, depth);
        if added {
            self.discovered.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn robots_for(
        &self,
        downloader: &Downloader,
        url: &Url,
        user_agent: &str,
    ) -> Option<Robots> {
        let origin = format!("{}://{}", url.scheme(), url.authority());
        if let Some(cached) = self.robots_cache.lock().unwrap().get(&origin) {
            return cached.clone();
        }
        let robots = downloader.fetch_robots(&origin, user_agent).await;
        self.robots_cache
            .lock()
            .unwrap()
            .insert(origin, robots.clone());
        robots
    }
}

/// Run a crawl to completion and return its report.
pub async fn run(config: CrawlConfig) -> Result<CrawlReport, String> {
    if config.seeds.is_empty() {
        return Err("no seed URLs provided".to_string());
    }
    if config.concurrency == 0 || config.max_pages == 0 {
        return Err("max_pages and concurrency must be > 0".to_string());
    }
    if config.resume && config.save_dir.is_none() {
        return Err("resume requires save_dir".to_string());
    }

    let started = Instant::now();
    let downloader = Arc::new(Downloader::new(config.timeout_ms, &config.user_agent)?);

    // Distinct hosts of the seed URLs — used both for the frontier's
    // same-site priority bonus and (in same-site mode) as the allowed set.
    let mut seed_hosts: Vec<String> = config
        .seeds
        .iter()
        .filter_map(|s| Url::parse(s.trim()).ok())
        .filter_map(|u| u.host_str().map(str::to_string))
        .collect();
    seed_hosts.sort();
    seed_hosts.dedup();

    // Allowed-host set for same-site mode.
    let allowed_hosts: Option<HashSet<String>> = if config.same_site_only {
        Some(seed_hosts.iter().cloned().collect())
    } else {
        None
    };

    let state = Arc::new(SharedState::new(config.max_pages, &seed_hosts));

    // Resume mode: the save directory's filenames *are* content hashes,
    // so pre-loading them into `content_seen` makes every already-stored
    // page dedup away on encounter — no body re-written, no budget spent.
    // Sidecars additionally carry per-URL HTTP validators, enabling `304
    // Not Modified` short-circuits before anything is downloaded.
    let mut resumed_hashes = 0usize;
    let url_validators: HashMap<String, sidecar::UrlValidators> = if config.resume {
        let dir = config.save_dir.as_ref().unwrap();
        for hash in load_saved_hashes(dir).await? {
            state.content_seen.lock().unwrap().insert(hash);
            resumed_hashes += 1;
        }
        sidecar::load_url_validators(dir).await?
    } else {
        HashMap::new()
    };

    for s in &config.seeds {
        let url = Url::parse(s.trim()).map_err(|e| format!("bad seed URL {s:?}: {e}"))?;
        state.enqueue(url, 0);
    }

    // Sitemap seeding: each distinct seed origin contributes the URLs its
    // sitemaps list (often pages unreachable by link traversal). Sitemap
    // locations are harvested from global `Sitemap:` directives in
    // robots.txt when available; only when none are declared do we probe
    // the conventional /sitemap.xml path. Entries enter as depth-0 seeds
    // and pass through the normal pipeline — robots gating, politeness,
    // quota — during the crawl proper.
    let mut sitemap_urls = 0usize;
    if config.use_sitemaps {
        let mut origins: Vec<String> = config
            .seeds
            .iter()
            .filter_map(|s| Url::parse(s.trim()).ok())
            .map(|u| format!("{}://{}", u.scheme(), u.authority()))
            .collect();
        origins.sort();
        origins.dedup();

        let mut candidates: Vec<String> = Vec::new();
        let mut seen_docs: HashSet<String> = HashSet::new();
        for origin in &origins {
            let mut from_robots = Vec::new();
            if config.respect_robots {
                if let Some(rules) = downloader.fetch_robots(origin, &config.user_agent).await {
                    from_robots.extend(rules.sitemaps().iter().cloned());
                }
            }
            if from_robots.is_empty() {
                from_robots.push(format!("{origin}/sitemap.xml"));
            }
            for doc in from_robots {
                if seen_docs.insert(doc.clone()) {
                    candidates.push(doc);
                }
            }
        }

        for doc in &candidates {
            let Ok(doc_url) = Url::parse(doc) else {
                continue;
            };
            let Some(xml) = downloader.fetch_sitemap(&doc_url).await else {
                continue;
            };
            for loc in crate::sitemap::extract_locations(&xml) {
                // Resolve against the document's own URL so relative paths
                // work regardless of where the sitemap lives.
                let Some(url) = parser::resolve(&loc, &doc_url) else {
                    continue;
                };
                state.enqueue(url, 0);
                sitemap_urls += 1;
            }
        }
    }

    let mut handles = Vec::with_capacity(config.concurrency);

    // Prepare the save directory up front so a bad path fails fast, before
    // any network I/O happens.
    if let Some(dir) = &config.save_dir {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| format!("create save dir {}: {e}", dir.display()))?;
    }

    for _ in 0..config.concurrency {
        handles.push(tokio::spawn(worker(
            state.clone(),
            downloader.clone(),
            config.clone(),
            allowed_hosts.clone(),
            Arc::new(url_validators.clone()),
        )));
    }
    for h in handles {
        h.await.map_err(|e| format!("worker panicked: {e}"))?;
    } // NOTE: snapshot into locals first. Building these locks inline inside
      // the CrawlReport literal would keep every MutexGuard alive until the
      // end of the `let` statement — deadlocking on the second `pages` lock.
    let pages_crawled = state.pages.lock().unwrap().len();
    let pages_failed = state.failed.load(Ordering::Relaxed);
    let urls_discovered = state.discovered.load(Ordering::Relaxed);
    let duplicates_skipped = state.duplicates.load(Ordering::Relaxed);
    let blocked_by_robots = state.blocked.load(Ordering::Relaxed);
    let quota_skipped = state.quota_skipped.load(Ordering::Relaxed);
    let revalidated = state.revalidated.load(Ordering::Relaxed);
    let mut hosts: Vec<String> = state.hosts_seen.lock().unwrap().iter().cloned().collect();
    hosts.sort();
    let elapsed_ms = started.elapsed().as_millis();
    let pages = state.pages.lock().unwrap().clone();

    let report = CrawlReport {
        pages_crawled,
        pages_failed,
        urls_discovered,
        duplicates_skipped,
        blocked_by_robots,
        quota_skipped,
        resumed_hashes,
        sitemap_urls,
        revalidated,
        hosts,
        elapsed_ms,
        pages,
    };
    Ok(report)
}

async fn worker(
    state: Arc<SharedState>,
    downloader: Arc<Downloader>,
    config: CrawlConfig,
    allowed_hosts: Option<HashSet<String>>,
    url_validators: Arc<HashMap<String, sidecar::UrlValidators>>,
) {
    loop {
        // Drain condition: queue empty AND no other worker can produce work
        // (every popped item holds one unit of `inflight` while processed).
        let item = { state.frontier.lock().unwrap().pop() };
        let Some(item) = item else {
            if state.inflight.load(Ordering::SeqCst) == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
            continue;
        };
        state.inflight.fetch_add(1, Ordering::SeqCst);

        process_item(
            &state,
            &downloader,
            &item,
            &config,
            allowed_hosts.as_ref(),
            &url_validators,
        )
        .await;

        state.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn process_item(
    state: &Arc<SharedState>,
    downloader: &Arc<Downloader>,
    item: &crate::frontier::QueuedUrl,
    config: &CrawlConfig,
    allowed_hosts: Option<&HashSet<String>>,
    url_validators: &HashMap<String, sidecar::UrlValidators>,
) {
    let host = item.url.host_str().unwrap_or_default().to_string();
    if host.is_empty() {
        return;
    }
    state.hosts_seen.lock().unwrap().insert(host.clone());

    // Politeness: reserve the host's slot before doing anything else.
    let wait_until = state
        .frontier
        .lock()
        .unwrap()
        .reserve_slot(&host, Duration::from_millis(config.delay_ms));
    let now = Instant::now();
    if wait_until > now {
        tokio::time::sleep(wait_until - now).await;
    }

    // Spider-trap guard: per-host page quota.
    if state
        .frontier
        .lock()
        .unwrap()
        .host_quota_exhausted(&host, config.max_pages_per_host)
    {
        state.quota_skipped.fetch_add(1, Ordering::Relaxed);
        eprintln!("skip (quota): {}", item.url);
        return;
    }

    // robots.txt gate (cached per origin).
    if config.respect_robots {
        if let Some(rules) = state
            .robots_for(downloader, &item.url, &config.user_agent)
            .await
        {
            if !rules.allows(item.url.path()) {
                state.blocked.fetch_add(1, Ordering::Relaxed);
                eprintln!("skip (robots): {}", item.url);
                return;
            }
        }
    }

    // Fetch — conditionally when resume mode has stored validators for this
    // exact URL: a `304 Not Modified` confirms our cached copy is current
    // with no body transfer, so the URL costs nothing (no budget, no store,
    // no parse).
    let fetch_result = match url_validators
        .get(item.url.as_str())
        .filter(|v| v.is_usable())
    {
        Some(v) => {
            let cond = downloader::Validators {
                etag: v.etag.clone(),
                last_modified: v.last_modified.clone(),
            };
            downloader.fetch(&item.url, Some(&cond)).await
        }
        None => downloader.fetch(&item.url, None).await,
    };
    let page = match fetch_result {
        Ok(FetchOutcome::NotModified) => {
            state.revalidated.fetch_add(1, Ordering::Relaxed);
            eprintln!("not-modified: {}", item.url);
            return;
        }
        Ok(FetchOutcome::Page(p)) => p,
        Err(e) => {
            state.failed.fetch_add(1, Ordering::Relaxed);
            eprintln!("fail: {} ({e})", item.url);
            return;
        }
    };

    // Content dedup via SDK BLAKE3 ("one crypto provider" policy).
    let hash = *origin_crypto_sdk::blake3::hash(page.body.as_bytes()).as_bytes();
    let hash_hex = hex_encode(&hash);
    if !state.content_seen.lock().unwrap().insert(hash) {
        state.duplicates.fetch_add(1, Ordering::Relaxed);
        // Provenance: this URL maps onto an already-stored body — record it
        // in that body's sidecar so the corpus keeps full source history.
        if let Some(dir) = &config.save_dir {
            let body_path = dir.join(&hash_hex);
            if tokio::fs::try_exists(&body_path).await.unwrap_or(false) {
                let _guard = state.sidecar_lock.lock().await;
                match sidecar::record_source(
                    dir,
                    &hash_hex,
                    SourceRef::new(item.url.as_str().to_string(), None, item.depth),
                )
                .await
                {
                    Ok(true) => eprintln!("sidecar+: {} -> {}", item.url, hash_hex),
                    Ok(false) => {}
                    Err(e) => eprintln!("warn: sidecar {hash_hex}: {e}"),
                }
            }
        }
        eprintln!("dup: {}", item.url);
        return;
    }

    // Consume page budget exactly.
    {
        let mut budget = state.budget.lock().unwrap();
        if *budget == 0 {
            return;
        }
        *budget -= 1;
    }

    let meta = parser::parse(&page.body);

    // Persist the body keyed by its content hash (each unique body is
    // written exactly once — dedup has already run) plus its provenance
    // sidecar.
    let saved_path = if let Some(dir) = &config.save_dir {
        let file = dir.join(&hash_hex);
        match tokio::fs::write(&file, page.body.as_bytes()).await {
            Ok(()) => {
                let _guard = state.sidecar_lock.lock().await;
                if let Err(e) = sidecar::record_source(
                    dir,
                    &hash_hex,
                    SourceRef::new(
                        item.url.as_str().to_string(),
                        meta.title.clone(),
                        item.depth,
                    )
                    .with_validators(page.etag.clone(), page.last_modified.clone()),
                )
                .await
                {
                    eprintln!("warn: sidecar {hash_hex}: {e}");
                }
                Some(file.to_string_lossy().into_owned())
            }
            Err(e) => {
                state.failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("fail: {} (save {}: {e})", item.url, file.display());
                return;
            }
        }
    } else {
        None
    };

    let record = PageRecord {
        url: item.url.as_str().to_string(),
        status: page.status,
        depth: item.depth,
        title: meta.title.clone(),
        body_len: page.body.len(),
        content_hash: hash_hex,
        saved_path,
    };
    eprintln!(
        "ok: {} (depth {}, \"{}\")",
        record.url,
        record.depth,
        record.title.as_deref().unwrap_or("")
    );
    state.pages.lock().unwrap().push(record);

    // Discover links only if children stay within the depth budget.
    if item.depth >= config.max_depth {
        return;
    }
    for raw in &meta.links {
        let Some(url) = parser::resolve(raw, &item.url) else {
            continue;
        };
        if let Some(allowed) = allowed_hosts {
            if !url.host_str().is_some_and(|h| allowed.contains(h)) {
                continue;
            }
        }
        state.enqueue(url, item.depth + 1);
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Inverse of [`hex_encode`] for BLAKE3 digests; used to turn save-dir
/// filenames back into hash keys in resume mode.
fn hex_decode(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Collect the content hashes already stored in a save directory.
/// Entries whose names are not valid 64-char hex digests are ignored.
async fn load_saved_hashes(dir: &std::path::Path) -> Result<Vec<[u8; 32]>, String> {
    let mut rd = tokio::fs::read_dir(dir)
        .await
        .map_err(|e| format!("resume: read dir {}: {e}", dir.display()))?;
    let mut hashes = Vec::new();
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
        if let Some(name) = entry.file_name().to_str() {
            if let Some(hash) = hex_decode(name) {
                hashes.push(hash);
            }
        }
    }
    Ok(hashes)
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(v: &usize) -> bool {
    *v == 0
}
