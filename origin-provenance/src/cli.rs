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
    /// Embed a watermark into a file
    Watermark(WatermarkArgs),
    /// Extract and verify a watermark from a file
    Unwatermark(UnwatermarkArgs),
    /// Scan a directory tree into a manifest
    Scan(ScanArgs),
    /// Verify a directory against a manifest
    Check(CheckArgs),
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
