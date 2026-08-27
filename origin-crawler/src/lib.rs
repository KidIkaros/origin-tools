// SPDX-License-Identifier: Apache-2.0

//! origin-crawler library surface.
//!
//! A polite, breadth-first web crawler following the classic URL-frontier
//! design (system-design notes ch. 9), scaled down to a foundational crate:
//!
//! - **URL frontier** (`frontier`): priority queue (`depth`, same-site
//!   bonus, FIFO tiebreak) + `url seen?` set + per-host politeness slots
//!   (one in-flight request per host, spaced by a configurable delay) +
//!   spider-trap guards (URL length, per-host quota).
//! - **HTML downloader** (`downloader`): reqwest client with timeout and a
//!   content-type gate.
//! - **robots.txt compliance** (`robots`): minimal parser honoring the `*`
//!   group and exact product tokens, longest-match Allow/Disallow.
//! - **Link extraction** (`parser`): dependency-light anchor scanning and
//!   relative URL resolution.
//! - **Sitemap seeding** (`sitemap`): optional discovery of sitemap
//!   documents — harvested from global `Sitemap:` directives in robots.txt,
//!   with fallback to the conventional `/sitemap.xml` probe — whose listed
//!   URLs are injected as extra BFS roots.
//! - **Metadata sidecars** (`sidecar`): per-body JSON provenance recording
//!   every source URL observed for a content hash, including HTTP validators
//!   (`ETag` / `Last-Modified`) that let resume crawls revalidate with `304`
//!   instead of re-downloading.
//! - **Corpus analysis** (`corpus`): offline summaries of a save-dir —
//!   inventory, source hosts, and staleness.
//! - **Orchestrator** (`crawler`): bounded-concurrency BFS workers, content
//!   de-duplication via the SDK's BLAKE3, JSON crawl report.
//!
//! Re-exports the command implementations so other crates can call them
//! programmatically (e.g. from integration tests or the unified `origin`
//! binary).

pub mod cli;
pub mod commands;
pub mod corpus;
pub mod crawler;
pub mod downloader;
pub mod frontier;
pub mod parser;
pub mod robots;
pub mod sidecar;
pub mod sitemap;
