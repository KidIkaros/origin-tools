// SPDX-License-Identifier: Apache-2.0

//! Command implementations for origin-crawler.
//!
//! Every command returns `Result<(), String>`; errors go to stderr via
//! `main`. Progress lines go to stderr so stdout stays pure JSON.

use crate::cli::{Cli, Commands, CorpusArgs, CrawlArgs};
use crate::{corpus, crawler};

pub fn dispatch(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Crawl(args) => cmd_crawl(args),
        Commands::Corpus(args) => cmd_corpus(args),
    }
}

/// Summarize a save-dir corpus (optionally pruning it) and print a JSON
/// report on stdout.
fn cmd_corpus(args: CorpusArgs) -> Result<(), String> {
    let report = if args.prune {
        serde_json::to_string_pretty(&corpus::prune(
            &args.save_dir,
            args.stale_days,
            args.dry_run,
        )?)
        .map_err(|e| format!("report serialization: {e}"))?
    } else {
        serde_json::to_string_pretty(&corpus::analyze(&args.save_dir, args.stale_days)?)
            .map_err(|e| format!("report serialization: {e}"))?
    };
    println!("{report}");
    Ok(())
}

/// Crawl from seeds and print a JSON report on stdout.
pub fn cmd_crawl(args: CrawlArgs) -> Result<(), String> {
    if args.seeds.is_empty() {
        return Err("at least one seed URL is required".to_string());
    }

    let config = crawler::CrawlConfig {
        seeds: args.seeds.clone(),
        max_pages: args.max_pages,
        max_depth: args.max_depth,
        delay_ms: args.delay_ms,
        timeout_ms: args.timeout_ms,
        concurrency: args.concurrency,
        user_agent: args.user_agent,
        max_pages_per_host: args.max_pages_per_host,
        respect_robots: !args.no_robots,
        same_site_only: args.same_site_only,
        save_dir: args.save_dir,
        resume: args.resume,
        use_sitemaps: args.sitemaps,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("async runtime: {e}"))?;

    let report = runtime.block_on(crawler::run(config))?;

    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| format!("report serialization: {e}"))?
    );
    Ok(())
}
