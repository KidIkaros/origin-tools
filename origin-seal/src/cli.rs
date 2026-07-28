// SPDX-License-Identifier: Apache-2.0

//! CLI surface for origin-seal — pure clap definitions, no logic.

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "origin-seal",
    version,
    about = "Data operations — encrypt, decrypt, sign, verify, hash, MAC, KDF",
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Hash data (SHA3-256, SHA3-512, BLAKE3, HMAC-SHA3-256)
    Hash(HashArgs),
    /// Encrypt data with XChaCha20-Poly1305 + Argon2id
    Encrypt(EncryptArgs),
    /// Decrypt data encrypted by `origin-seal encrypt`
    Decrypt(DecryptArgs),
    /// Hybrid-sign data (Ed25519 + Falcon-1024)
    Sign(SignArgs),
    /// Verify a hybrid signature
    Verify(VerifyArgs),
    /// Derive a key from a passphrase (Argon2id)
    Kdf(KdfArgs),
    /// Compute HMAC-SHA3-256
    Mac(MacArgs),
}

// ---------------------------------------------------------------------------
// hash
// ---------------------------------------------------------------------------

#[derive(Parser, Clone, Debug)]
pub struct HashArgs {
    /// Hash algorithm
    #[arg(short, long, default_value = "sha3-256")]
    pub algo: HashAlgo,

    /// Input file (default: stdin)
    #[arg(short, long)]
    pub input: Option<String>,

    /// HMAC key (hex) — required for hmac-sha3-256
    #[arg(long)]
    pub key: Option<String>,

    /// HMAC key file (alternative to --key)
    #[arg(long)]
    pub key_file: Option<String>,

    /// Output raw bytes instead of hex
    #[arg(long)]
    pub raw: bool,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum HashAlgo {
    /// SHA3-256 (32-byte digest)
    Sha3_256,
    /// SHA3-512 (64-byte digest)
    Sha3_512,
    /// BLAKE3 (32-byte digest)
    Blake3,
    /// HMAC-SHA3-256 (32-byte MAC, requires --key)
    HmacSha3_256,
}

// ---------------------------------------------------------------------------
// encrypt / decrypt
// ---------------------------------------------------------------------------

#[derive(Parser, Clone, Debug)]
pub struct EncryptArgs {
    /// Input file (default: stdin)
    #[arg(short, long)]
    pub input: Option<String>,

    /// Output file (default: stdout)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Passphrase file (default: interactive prompt)
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Argon2id memory tier
    #[arg(short, long, default_value = "standard")]
    pub tier: String,

    /// Compress data before encryption (zstd)
    #[arg(long)]
    pub compress: bool,

    /// Compression level (1-22, default 3)
    #[arg(long, default_value = "3")]
    pub compress_level: u8,

    /// Stream in chunks (for files larger than memory)
    #[arg(long)]
    pub stream: bool,

    /// Chunk size in bytes for --stream (power of 2, 1KB–1GB, default 64KB)
    #[arg(long, default_value = "65536")]
    pub chunk_size: usize,
}

#[derive(Parser, Clone, Debug)]
pub struct DecryptArgs {
    /// Input file (default: stdin)
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

    /// Stream in chunks (must match encryption mode)
    #[arg(long)]
    pub stream: bool,

    /// Chunk size in bytes for --stream (must match encryption, default 64KB)
    #[arg(long, default_value = "65536")]
    pub chunk_size: usize,
}

// ---------------------------------------------------------------------------
// sign / verify
// ---------------------------------------------------------------------------

#[derive(Parser, Clone, Debug)]
pub struct SignArgs {
    /// Input file (default: stdin)
    #[arg(short, long)]
    pub input: Option<String>,

    /// Use the suite identity (~/.origin/identity.seed) for signing
    #[arg(long)]
    pub identity: bool,

    /// Seed blob file (encrypted identity from origin-identity)
    #[arg(long)]
    pub blob: Option<String>,

    /// Raw seed (hex, 32 bytes) — alternative to --blob
    #[arg(long)]
    pub seed: Option<String>,

    /// Domain separation string for key derivation
    #[arg(short, long, default_value = "origin-seal")]
    pub domain: String,

    /// Passphrase file for blob decryption
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Argon2id memory tier for blob decryption
    #[arg(short, long, default_value = "standard")]
    pub tier: String,

    /// Output format
    #[arg(short, long, default_value = "json")]
    pub format: OutputFormat,
}

#[derive(Parser, Clone, Debug)]
pub struct VerifyArgs {
    /// Input file (default: stdin)
    #[arg(short, long)]
    pub input: Option<String>,

    /// Signature file (JSON or hex wire format)
    #[arg(short, long)]
    pub signature: String,

    /// Seed blob file (to derive public keys)
    #[arg(long)]
    pub blob: Option<String>,

    /// Raw seed (hex, 32 bytes) — alternative to --blob
    #[arg(long)]
    pub seed: Option<String>,

    /// Ed25519 public key (hex, 32 bytes) — for pubkey-only verification
    #[arg(long)]
    pub ed25519_pubkey: Option<String>,

    /// Falcon-1024 public key file (raw bytes)
    #[arg(long)]
    pub falcon_pubkey: Option<String>,

    /// Domain separation string (must match signing domain)
    #[arg(short, long, default_value = "origin-seal")]
    pub domain: String,

    /// Passphrase file for blob decryption
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Argon2id memory tier for blob decryption
    #[arg(short, long, default_value = "standard")]
    pub tier: String,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    /// JSON with ed25519 + falcon1024 hex fields
    Json,
    /// Length-prefixed binary wire format (hex-encoded)
    Hex,
}

// ---------------------------------------------------------------------------
// kdf
// ---------------------------------------------------------------------------

#[derive(Parser, Clone, Debug)]
pub struct KdfArgs {
    /// Passphrase file (default: interactive prompt)
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Salt (hex, 16 bytes). Generated randomly if omitted.
    #[arg(long)]
    pub salt: Option<String>,

    /// Argon2id memory tier
    #[arg(short, long, default_value = "standard")]
    pub tier: String,

    /// Output key length in bytes
    #[arg(short, long, default_value = "32")]
    pub len: usize,

    /// Output raw bytes instead of hex
    #[arg(long)]
    pub raw: bool,
}

// ---------------------------------------------------------------------------
// mac
// ---------------------------------------------------------------------------

#[derive(Parser, Clone, Debug)]
pub struct MacArgs {
    /// Input file (default: stdin)
    #[arg(short, long)]
    pub input: Option<String>,

    /// HMAC key (hex)
    #[arg(long)]
    pub key: Option<String>,

    /// HMAC key file (alternative to --key)
    #[arg(long)]
    pub key_file: Option<String>,

    /// Output raw bytes instead of hex
    #[arg(long)]
    pub raw: bool,
}
