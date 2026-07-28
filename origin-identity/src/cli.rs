// SPDX-License-Identifier: Apache-2.0

//! CLI surface for origin-identity — pure clap definitions, no logic.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "origin-identity",
    version,
    about = "Identity key management — hybrid post-quantum signing"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new identity key pair
    Keygen(KeygenArgs),
    /// Hybrid-sign a message
    Sign(SignArgs),
    /// Verify a hybrid signature
    Verify(VerifyArgs),
    /// List identities in the default directory
    List(ListArgs),
    /// Restore an identity from a recovery phrase
    Import(ImportArgs),
    /// Show metadata for a single identity (no decryption)
    Show(ShowArgs),
    /// Rename an identity blob (filesystem-only, no key change)
    Rename(RenameArgs),
    /// Secure-delete an identity blob (single-pass overwrite + unlink)
    Delete(DeleteArgs),
    /// Export the public keys for an identity (no secret material)
    ExportPubkey(ExportPubkeyArgs),
    /// Re-encrypt an identity blob with a new passphrase
    RotatePassphrase(RotatePassphraseArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct KeygenArgs {
    /// Identity name (used for the blob filename)
    #[arg(short, long, default_value = "personal")]
    pub name: String,

    /// Argon2id memory tier (nano, standard, sovereign)
    #[arg(short, long, default_value = "standard")]
    pub tier: String,

    /// Output directory for the identity blob
    #[arg(short, long, default_value = "~/.origin/identities")]
    pub dir: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Skip displaying the recovery phrase
    #[arg(long)]
    pub no_phrase: bool,

    /// Write the 24-codepoint recovery phrase to `<file>` as
    /// whitespace-separated codepoints with a trailing newline
    /// (one line, suitable for direct `import --phrase @file` consumption).
    /// When this flag is set, the on-screen banner is suppressed and the
    /// "press enter" interactive prompt is skipped — the file IS the
    /// output. Atomic via tmp + rename.
    #[arg(long, value_name = "FILE")]
    pub phrase_output: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct SignArgs {
    /// Identity name (reads ~/.origin/identities/`<name>`.id)
    #[arg(short, long, default_value = "personal")]
    pub name: String,

    /// Message to sign (literal string, @file to read bytes, or hex bytes with --hex)
    #[arg(short, long)]
    pub message: String,

    /// Domain label for key derivation
    #[arg(long, default_value = "origin-identity:v1")]
    pub domain: String,

    /// Output format: json, hex
    #[arg(short, long, default_value = "json")]
    pub output: OutputFormat,

    /// Argon2id memory tier
    #[arg(long, default_value = "standard")]
    pub tier: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Identity directory (default: ~/.origin/identities)
    #[arg(short, long, default_value = "~/.origin/identities")]
    pub dir: String,

    /// Interpret --message as hex-encoded raw bytes (instead of a literal UTF-8 string)
    #[arg(long)]
    pub hex: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct VerifyArgs {
    /// Identity name
    #[arg(short, long, default_value = "personal")]
    pub name: String,

    /// Original message (literal string, @file bytes, or hex bytes with --hex)
    #[arg(short, long)]
    pub message: String,

    /// Signature file (JSON, or hex bytes with --hex)
    #[arg(short, long)]
    pub signature: String,

    /// Domain label
    #[arg(long, default_value = "origin-identity:v1")]
    pub domain: String,

    /// Argon2id memory tier
    #[arg(long, default_value = "standard")]
    pub tier: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Identity directory (default: ~/.origin/identities)
    #[arg(short, long, default_value = "~/.origin/identities")]
    pub dir: String,

    /// Raw-bytes mode: --message is hex bytes AND --signature is length-prefixed ed25519‖falcon1024 hex
    #[arg(long)]
    pub hex: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct ListArgs {
    /// Identity directory (default: ~/.origin/identities)
    #[arg(short, long, default_value = "~/.origin/identities")]
    pub dir: String,

    /// Output format
    #[arg(long, value_enum, default_value_t = ListFormat::Table)]
    pub format: ListFormat,

    /// Show only identity names (one per line)
    #[arg(long, conflicts_with = "format")]
    pub names_only: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct ImportArgs {
    /// Identity name (used for the new blob filename)
    #[arg(short, long, default_value = "personal")]
    pub name: String,

    /// Recovery phrase (24 codepoints, separated by whitespace; @file to read from file)
    #[arg(long)]
    pub phrase: String,

    /// Argon2id memory tier
    #[arg(short, long, default_value = "standard")]
    pub tier: String,

    /// Output directory for the new identity blob
    #[arg(short, long, default_value = "~/.origin/identities")]
    pub dir: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Overwrite existing blob with same name
    #[arg(long)]
    pub force: bool,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Json,
    Hex,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum ListFormat {
    Table,
    Csv,
    Json,
}

// ─── Show ──────────────────────────────────────────────────────────

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum ShowFormat {
    /// Human-readable text (default)
    Text,
    /// JSON for shell parsing
    Json,
}

#[derive(Parser, Clone, Debug)]
pub struct ShowArgs {
    /// Identity name
    #[arg(short, long, default_value = "personal")]
    pub name: String,

    /// Identity directory
    #[arg(short, long, default_value = "~/.origin/identities")]
    pub dir: String,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = ShowFormat::Text)]
    pub format: ShowFormat,
}

// ─── Rename ────────────────────────────────────────────────────────

#[derive(Parser, Clone, Debug)]
pub struct RenameArgs {
    /// Current identity name
    pub old_name: String,

    /// New identity name
    pub new_name: String,

    /// Identity directory
    #[arg(short, long, default_value = "~/.origin/identities")]
    pub dir: String,

    /// Overwrite if new_name already exists
    #[arg(long)]
    pub force: bool,
}

// ─── Delete ────────────────────────────────────────────────────────

#[derive(Parser, Clone, Debug)]
pub struct DeleteArgs {
    /// Identity name to delete
    pub name: String,

    /// Identity directory
    #[arg(short, long, default_value = "~/.origin/identities")]
    pub dir: String,

    /// Skip interactive confirmation prompt
    #[arg(long)]
    pub force: bool,

    /// Skip secure overwrite (plain remove_file; faster but less safe on SSDs)
    #[arg(long)]
    pub no_overwrite: bool,
}

// ─── ExportPubkey ──────────────────────────────────────────────────

#[derive(Parser, Clone, Debug)]
pub struct ExportPubkeyArgs {
    /// Identity name
    #[arg(short, long, default_value = "personal")]
    pub name: String,

    /// Domain label for key derivation (must match what was used in `sign`)
    #[arg(long, default_value = "origin-identity:v1")]
    pub domain: String,

    /// Argon2id memory tier (must match the tier used at keygen)
    #[arg(long, default_value = "standard")]
    pub tier: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Identity directory
    #[arg(short, long, default_value = "~/.origin/identities")]
    pub dir: String,

    /// Output format (json or hex)
    #[arg(short, long, default_value = "json")]
    pub format: OutputFormat,
}

// ─── RotatePassphrase ──────────────────────────────────────────────

#[derive(Parser, Clone, Debug)]
pub struct RotatePassphraseArgs {
    /// Identity name
    #[arg(short, long, default_value = "personal")]
    pub name: String,

    /// Argon2id tier of the EXISTING blob (must match what was used at keygen)
    #[arg(short, long, default_value = "standard")]
    pub tier: String,

    /// New tier (defaults to --tier; use this to migrate e.g. nano → standard)
    #[arg(long)]
    pub new_tier: Option<String>,

    /// Read CURRENT passphrase from file
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Read NEW passphrase from file (skips confirmation prompt)
    #[arg(long)]
    pub new_passphrase_file: Option<String>,

    /// Identity directory
    #[arg(short, long, default_value = "~/.origin/identities")]
    pub dir: String,
}

// ── Helpers used by clap defaults ──────────────────────────────────

/// Resolve `~/` prefix against `$HOME`. Errors if `$HOME` is unset so
/// identity blobs are never silently written to `/tmp` (a shared,
/// world-readable directory on many systems).
pub fn resolve_dir(raw: &str) -> Result<PathBuf, String> {
    if let Some(rest) = raw.strip_prefix("~/") {
        let home = std::env::var("HOME").map_err(|_| {
            "$HOME is unset; cannot expand ~/ paths. Pass an absolute path instead.".to_string()
        })?;
        Ok(PathBuf::from(home).join(rest))
    } else {
        Ok(PathBuf::from(raw))
    }
}
