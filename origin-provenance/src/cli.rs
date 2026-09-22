// SPDX-License-Identifier: Apache-2.0

//! CLI surface for origin-provenance — pure clap definitions, no logic.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "origin-provenance",
    version,
    about = "File provenance — stamps, watermarks, directory manifests, verification"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a provenance stamp for a file
    Stamp(StampArgs),
    /// Verify a file against a stamp
    Verify(VerifyArgs),
    /// Embed a watermark into a file (experimental)
    #[command(alias = "watermark-embed")]
    Watermark(WatermarkArgs),
    /// Extract and verify a watermark from a file
    Unwatermark(UnwatermarkArgs),
    /// Scan a directory tree into a manifest
    Scan(ScanArgs),
    /// Verify a directory against a manifest
    Check(CheckArgs),
    /// Create an OPM provenance manifest for a file
    Create(CreateArgs),
    /// Append a signed edit checkpoint to an OPM manifest
    Append(AppendArgs),
    /// Add an independent attestation to an OPM manifest
    Attest(AttestArgs),
    /// Verify a file against its OPM manifest (three-state output)
    VerifyManifest(VerifyManifestArgs),
    /// Publish a signed head anchor for a file's manifest (announcement copy)
    Anchor(AnchorArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct StampArgs {
    /// File to stamp
    pub file: String,

    /// Output file for the stamp JSON (default: <file>.stamp.json)
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct VerifyArgs {
    /// File to verify
    pub file: String,

    /// Stamp JSON file to verify against
    #[arg(short, long)]
    pub stamp: String,
}

#[derive(Parser, Clone, Debug)]
pub struct WatermarkArgs {
    /// File to watermark (modified in place)
    pub file: String,

    /// Optional label (e.g. signer identity)
    #[arg(short, long)]
    pub label: Option<String>,

    /// Write to a new file instead of modifying in place
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct UnwatermarkArgs {
    /// Watermarked file to inspect
    pub file: String,

    /// Strip the watermark and write the original to this path
    #[arg(short, long)]
    pub strip: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct ScanArgs {
    /// Directory to scan
    pub dir: String,

    /// Output manifest file (default: provenance-manifest.json in the directory)
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct CheckArgs {
    /// Directory to verify
    pub dir: String,

    /// Manifest file to check against
    #[arg(short, long)]
    pub manifest: String,
}

#[derive(Parser, Clone, Debug)]
pub struct CreateArgs {
    /// Asset file to bind (its CURRENT bytes become edit 0)
    pub asset: String,

    /// Signer seed file (32 raw bytes, or 64-char hex) — never printed
    #[arg(long)]
    pub seed_file: String,

    /// Initial action: capture|edit|publish|annotate
    #[arg(long, default_value = "capture")]
    pub action: String,

    /// Chunk size in bytes for the content-commitment tree (default 1 MiB)
    #[arg(long)]
    pub chunk_size: Option<u32>,

    /// Sidecar path (default: <asset>.opm)
    #[arg(long)]
    pub sidecar: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct AppendArgs {
    /// Asset file — its CURRENT (post-edit) bytes are bound
    pub asset: String,

    /// Signer seed file (32 raw bytes, or 64-char hex) — never printed
    #[arg(long)]
    pub seed_file: String,

    /// Action for this edit: capture|edit|publish|annotate
    #[arg(long, default_value = "edit")]
    pub action: String,

    /// Note attached to this edit (outside the trust path)
    #[arg(long)]
    pub note: Option<String>,

    /// Sidecar path (default: <asset>.opm)
    #[arg(long)]
    pub sidecar: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct VerifyManifestArgs {
    /// File to verify against its OPM manifest
    pub asset: String,

    /// Sidecar path (default: <asset>.opm, then watermark-hint discovery)
    #[arg(long)]
    pub sidecar: Option<String>,

    /// Authoritative attestation threshold K (verifier policy)
    #[arg(long)]
    pub k: Option<u32>,

    /// Roster file: one trusted signer/attestor fingerprint hex per line
    #[arg(long)]
    pub roster: Option<String>,

    /// Expected manifest head (hex, from the publisher's announcement) —
    /// detects truncation/rollback of history to a genuine checkpoint
    /// (manifest-local checks cannot; transparency-log pattern).
    #[arg(long)]
    pub expect_manifest_id: Option<String>,

    /// Expected edit count (from the publisher's announcement). Fewer edits
    /// than announced ⇒ truncated history ⇒ invalid.
    #[arg(long)]
    pub expect_edits: Option<u64>,

    /// Anchor file (signed head announcement, ticket T-RT1). Explicit path
    /// must exist; otherwise an `<asset>.anchor` beside the asset is applied
    /// automatically when present.
    #[arg(long)]
    pub anchor: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct AnchorArgs {
    /// Asset whose manifest head is announced
    pub asset: String,

    /// Signer seed file (32 raw bytes, or 64-char hex) — should be the
    /// manifest signer
    #[arg(long)]
    pub seed_file: String,

    /// Sidecar path (default: <asset>.opm)
    #[arg(long)]
    pub sidecar: Option<String>,

    /// Output path for the anchor JSON (default: <asset>.anchor)
    #[arg(long)]
    pub output: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct AttestArgs {
    /// Asset whose OPM sidecar receives the attestation
    pub asset: String,

    /// ATTESTOR seed file (32 raw bytes, or 64-char hex) — never printed
    #[arg(long)]
    pub seed_file: String,

    /// Sidecar path (default: <asset>.opm)
    #[arg(long)]
    pub sidecar: Option<String>,
}
