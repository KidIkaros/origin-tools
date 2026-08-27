// SPDX-License-Identifier: Apache-2.0

//! CLI surface for origin-crawler — pure clap definitions, no logic.
//!
//! `origin-crawler` crawls the web breadth-first from seed URLs with
//! per-host politeness delays, robots.txt compliance, content
//! de-duplication (BLAKE3 via origin-crypto-sdk), and spider-trap guards.
//! The crawl report is emitted as JSON on stdout for composability.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "origin-crawler",
    version,
    about = "Polite BFS web crawler (URL frontier + politeness + robots.txt)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Crawl from one or more seed URLs and print a JSON report
    Crawl(CrawlArgs),

    /// Summarize an existing --save-dir corpus from its sidecars
    Corpus(CorpusArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct CorpusArgs {
    /// Corpus directory containing hash-keyed bodies and .json sidecars
    #[arg(long)]
    pub save_dir: std::path::PathBuf,

    /// Classify sources not seen within this many days as stale
    #[arg(long, default_value_t = 30)]
    pub stale_days: u64,

    /// Delete orphans, stale sources, and entries emptied by stale pruning
    #[arg(long, default_value_t = false)]
    pub prune: bool,

    /// With --prune: report what would be removed without modifying files
    #[arg(long, requires = "prune", default_value_t = false)]
    pub dry_run: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct CrawlArgs {
    /// Seed URLs to start from (BFS roots)
    pub seeds: Vec<String>,

    /// Stop after this many successfully stored pages
    #[arg(long, default_value_t = 100)]
    pub max_pages: usize,

    /// Maximum BFS depth below the seeds (seeds are depth 0)
    #[arg(long, default_value_t = 3)]
    pub max_depth: usize,

    /// Politeness delay in ms between consecutive requests to the same host
    #[arg(long, default_value_t = 250)]
    pub delay_ms: u64,

    /// Per-request HTTP timeout in ms
    #[arg(long, default_value_t = 10_000)]
    pub timeout_ms: u64,

    /// Number of concurrent worker tasks
    #[arg(long, default_value_t = 4)]
    pub concurrency: usize,

    /// User-Agent header to send (also used for robots.txt group matching)
    #[arg(long, default_value_t = format!("origin-crawler/{}", env!("CARGO_PKG_VERSION")))]
    pub user_agent: String,

    /// Per-host page quota (spider-trap guard)
    #[arg(long, default_value_t = 50)]
    pub max_pages_per_host: usize,

    /// Ignore robots.txt (default is to fetch and honor it)
    #[arg(long, default_value_t = false)]
    pub no_robots: bool,

    /// Restrict discovery to the seeds' host(s)
    #[arg(long, default_value_t = false)]
    pub same_site_only: bool,

    /// Directory to store unique page bodies, keyed by content hash
    #[arg(long)]
    pub save_dir: Option<std::path::PathBuf>,

    /// Resume: skip content already stored in --save-dir (requires it)
    #[arg(long, requires = "save_dir", default_value_t = false)]
    pub resume: bool,

    /// Seed the crawl with URLs listed in each seed origin's /sitemap.xml
    #[arg(long, default_value_t = false)]
    pub sitemaps: bool,
}
