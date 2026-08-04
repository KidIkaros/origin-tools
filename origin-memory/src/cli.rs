// SPDX-License-Identifier: Apache-2.0

//! CLI surface for origin-memory — pure clap definitions, no logic.
//!
//! Wired into the unified `origin` binary as `origin memory <cmd>`. The
//! standalone `origin-memory` binary uses the same definitions.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "origin-memory",
    version,
    about = "Provenance-tagged, temporally-aware memory graph",
    long_about = "A signed, temporally-layered memory graph. Every node is \
        hybrid-signed (Ed25519 + Falcon-1024), layered by time/topic/evidence/\
        tier, and queryable via semantic zoom.\n\n\
        Identity & seed come from the suite's unified origin identity \
        (~/.origin); the master seed for this graph is derived per-domain."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Open/create the graph and print its fingerprint + schema version
    Init(GraphArgs),
    /// Add a node from a markdown file or inline fields
    Add(AddArgs),
    /// Retract a node without deleting it (append-only revocation journal)
    Revoke(RevokeArgs),
    /// Semantic zoom across the orthogonal axes
    Zoom(ZoomArgs),
    /// Render the recursive tree under a summary node
    Tree(TreeArgs),
    /// Render the star-chart view (time x topic wings)
    Chart(GraphArgs),
    /// Verify signatures + journals (+ layer proofs with --layer)
    Verify(VerifyArgs),
    /// Endorse another signer in a capability domain
    Endorse(EndorseArgs),
    /// Show this agent's trust graph score for a fingerprint
    Trust(TrustArgs),
}

/// Flags shared by every command that opens the graph.
#[derive(Parser, Clone, Debug, Default)]
pub struct GraphArgs {
    /// Graph root directory (default: ~/.origin/memory)
    #[arg(short, long)]
    pub root: Option<String>,

    /// Domain label used to derive the graph's master seed (default: "origin-memory")
    #[arg(short, long, default_value = "origin-memory")]
    pub domain: String,

    /// Read the origin identity passphrase from this file instead of prompting
    #[arg(short = 'P', long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct AddArgs {
    #[command(flatten)]
    pub graph: GraphArgs,

    /// Markdown node file (id taken from the filename stem)
    #[arg(short, long, conflicts_with = "id")]
    pub file: Option<String>,

    /// Node id (inline mode)
    #[arg(long)]
    pub id: Option<String>,

    /// Node title (inline mode)
    #[arg(long)]
    pub title: Option<String>,

    /// Node date, YYYY-MM-DD (inline mode)
    #[arg(long)]
    pub time: Option<String>,

    /// Comma-separated topics (inline mode)
    #[arg(long, value_delimiter = ',')]
    pub topics: Vec<String>,

    /// Evidence label: documented|assertion|summary|fiction (inline mode)
    #[arg(long, default_value = "assertion")]
    pub evidence: String,

    /// Body text (inline mode; if omitted, read from stdin)
    #[arg(long)]
    pub body: Option<String>,

    /// Encrypt the body at rest (XChaCha20-Poly1305); signature still commits
    /// to the plaintext.
    #[arg(long)]
    pub secret: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct RevokeArgs {
    #[command(flatten)]
    pub graph: GraphArgs,

    /// Node id to retract
    pub id: String,

    /// Why it is being retracted
    #[arg(long, default_value = "retracted")]
    pub reason: String,
}

#[derive(Parser, Clone, Debug)]
pub struct ZoomArgs {
    #[command(flatten)]
    pub graph: GraphArgs,

    /// Window center date, YYYY-MM-DD (pairs with --window)
    #[arg(long)]
    pub date: Option<String>,

    /// Half-width of the temporal window in days
    #[arg(short, long, default_value_t = 30)]
    pub window: i64,

    /// Restrict to nodes tagged with this topic (repeatable)
    #[arg(short, long)]
    pub topic: Vec<String>,

    /// Evidence filter: documented|assertion|summary|fiction
    #[arg(short, long)]
    pub evidence: Option<String>,

    /// Tier filter: nano|standard|sovereign
    #[arg(long)]
    pub tier: Option<String>,

    /// Minimum signer trust [0,1] required for a node to appear
    #[arg(long)]
    pub min_trust: Option<f64>,

    /// Capability domain to evaluate --min-trust in
    #[arg(long)]
    pub trust_domain: Option<String>,

    /// Print full per-axis scores (uses zoom_scored) instead of bare ids
    #[arg(long)]
    pub scored: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct TreeArgs {
    #[command(flatten)]
    pub graph: GraphArgs,

    /// Summary node id to render the tree under
    pub id: String,
}

#[derive(Parser, Clone, Debug)]
pub struct VerifyArgs {
    #[command(flatten)]
    pub graph: GraphArgs,

    /// Verify one node by id instead of the whole graph
    #[arg(short, long)]
    pub id: Option<String>,

    /// Also check layer-membership proofs for every summary/leaf pair
    #[arg(long)]
    pub layer: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct EndorseArgs {
    #[command(flatten)]
    pub graph: GraphArgs,

    /// Fingerprint (Ed25519 public key hex) of the signer to endorse
    #[arg(short, long)]
    pub target: String,

    /// Capability domain being endorsed
    #[arg(short = 'c', long, default_value = "memory-write")]
    pub capability: String,

    /// Endorsement confidence [0,1]
    #[arg(short = 'f', long, default_value_t = 0.5)]
    pub confidence: f64,
}

#[derive(Parser, Clone, Debug)]
pub struct TrustArgs {
    #[command(flatten)]
    pub graph: GraphArgs,

    /// Fingerprint (Ed25519 public key hex) to score
    #[arg(short, long)]
    pub target: String,

    /// Capability domain to evaluate in
    #[arg(short = 'c', long, default_value = "memory-write")]
    pub capability: String,
}
