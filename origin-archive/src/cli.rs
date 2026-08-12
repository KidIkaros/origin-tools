// SPDX-License-Identifier: Apache-2.0

//! CLI surface for origin-archive — pure clap definitions, no logic.
//!
//! `origin-archive` performs atomic compress-then-encrypt (and the inverse
//! decrypt-then-decompress) using the origin-crypto-sdk's `compressed` module.
//! Zstd is the default compressor; DEFLATE is available as a fallback.
//! Cha-ha20-BLAKE3 (committing AEAD, 32-byte tag) is used for encryption,
//! with a STREAM nonce construction for chunked data.

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "origin-archive",
    version,
    about = "Atomic compress-then-encrypt archive (zstd + ChaCha20-BLAKE3)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Compress and encrypt data atomically
    Archive(ArchiveArgs),
    /// Decrypt and decompress data atomically
    Unarchive(UnarchiveArgs),
    /// Inspect an archive's header (without decrypting)
    Inspect(InspectArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct ArchiveArgs {
    /// Input file (default: stdin)
    #[arg(short, long)]
    pub input: Option<String>,

    /// Output file (default: stdout)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Passphrase file (default: interactive prompt)
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Argon2id memory tier (nano, standard, sovereign)
    #[arg(short, long, default_value = "standard")]
    pub tier: String,

    /// Compressor to use
    #[arg(short, long, default_value = "zstd")]
    pub compressor: Compressor,

    /// Chunk size in bytes for STREAM nonce construction (64KB default)
    #[arg(long, default_value = "65536")]
    pub chunk_size: usize,
}

#[derive(Parser, Clone, Debug)]
pub struct UnarchiveArgs {
    /// Input archive file (default: stdin)
    #[arg(short, long)]
    pub input: Option<String>,

    /// Output file (default: stdout)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Passphrase file (default: interactive prompt)
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Argon2id memory tier (must match encryption tier)
    #[arg(short, long, default_value = "standard")]
    pub tier: String,
}

#[derive(Parser, Clone, Debug)]
pub struct InspectArgs {
    /// Input archive file (default: stdin)
    #[arg(short, long)]
    pub input: Option<String>,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum Compressor {
    /// Zstd (default) — fast, high ratio
    Zstd,
    /// DEFLATE — fallback, no extra deps
    Deflate,
}
