// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "origin-seed",
    version,
    about = "Seed lifecycle — generate, derive, encode, create encrypted blobs"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new random 32-byte seed
    Generate(GenerateArgs),
    /// Derive a child seed from a parent seed with domain separation
    Derive(DeriveArgs),
    /// Encode a seed as a mnemonic phrase or unicode
    Encode(EncodeArgs),
    /// Decode a seed from a mnemonic phrase or unicode
    Decode(DecodeArgs),
    /// Create an encrypted seed blob (passphrase-protected)
    BlobCreate(BlobCreateArgs),
    /// Recover a seed from an encrypted blob
    BlobRecover(BlobRecoverArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct GenerateArgs {
    /// Output format (hex, raw)
    #[arg(short, long, default_value = "hex")]
    pub format: String,
}

#[derive(Parser, Clone, Debug)]
pub struct DeriveArgs {
    /// Parent seed (hex)
    #[arg(long)]
    pub seed: Option<String>,

    /// Use the suite identity (~/.origin/identity.seed)
    #[arg(long)]
    pub identity: bool,

    /// Domain separation string
    #[arg(short, long)]
    pub domain: String,

    /// Passphrase file for identity decryption
    #[arg(long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct EncodeArgs {
    /// Seed to encode (hex)
    #[arg(long)]
    pub seed: String,

    /// Encoding format (hex, base64)
    #[arg(short, long, default_value = "hex")]
    pub format: String,
}

#[derive(Parser, Clone, Debug)]
pub struct DecodeArgs {
    /// Encoded seed
    #[arg(long)]
    pub input: String,

    /// Encoding format (hex, base64)
    #[arg(short, long, default_value = "hex")]
    pub format: String,
}

#[derive(Parser, Clone, Debug)]
pub struct BlobCreateArgs {
    /// Seed to encrypt (hex)
    #[arg(long)]
    pub seed: String,

    /// Output blob file
    #[arg(short, long)]
    pub output: String,

    /// Passphrase file (default: interactive prompt)
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Argon2id memory tier
    #[arg(short, long, default_value = "standard")]
    pub tier: String,
}

#[derive(Parser, Clone, Debug)]
pub struct BlobRecoverArgs {
    /// Encrypted blob file
    #[arg(short, long)]
    pub input: String,

    /// Passphrase file (default: interactive prompt)
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Argon2id memory tier (must match creation tier)
    #[arg(short, long, default_value = "standard")]
    pub tier: String,
}
