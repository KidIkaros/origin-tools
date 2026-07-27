// SPDX-License-Identifier: Apache-2.0

//! CLI surface for `origin-pass` — pure clap definitions, no logic.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "origin-pass",
    version,
    about = "Encrypted password vault + 2FA authenticator (TOTP/HOTP)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new vault
    Init(InitArgs),
    /// Unlock the vault into session memory
    Unlock(UnlockArgs),
    /// Drop the in-memory unlocked vault
    Lock(LockArgs),
    /// Add or update an entry
    Add(AddArgs),
    /// Retrieve a single entry
    Get(GetArgs),
    /// List entry names + types
    List(ListArgs),
    /// Remove an entry
    Rm(RmArgs),
    /// Compute and display a TOTP/HOTP code
    Code(CodeArgs),
    /// Print the otpauth:// URI for QR provisioning
    ExportQr(ExportQrArgs),
    /// Add an entry by parsing an otpauth:// URI
    ImportQr(ImportQrArgs),
    /// Re-encrypt the vault header with a new master passphrase
    ChangePassphrase(ChangePassphraseArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct InitArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// Argon2id memory tier
    #[arg(long, default_value = "standard")]
    pub tier: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct UnlockArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// Argon2id memory tier (must match the tier used at init)
    #[arg(long, default_value = "standard")]
    pub tier: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Persist unlock to a token file at <path> for non-interactive shells
    #[arg(long)]
    pub session_token: Option<PathBuf>,
}

#[derive(Parser, Clone, Debug)]
pub struct LockArgs {}

#[derive(Parser, Clone, Debug)]
pub struct AddArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// Entry name (e.g. "github.com", "github-2fa")
    pub name: String,

    /// Entry type
    #[arg(long, value_enum, default_value_t = EntryType::Password)]
    pub r#type: EntryType,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Optional URL associated with the entry
    #[arg(long)]
    pub url: Option<String>,

    /// Optional notes
    #[arg(long)]
    pub notes: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct GetArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// Entry name
    pub name: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct ListArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct RmArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// Entry name
    pub name: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct CodeArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// Entry name (must be an OTP entry)
    pub name: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Override the entry's stored OTP algorithm
    #[arg(long)]
    pub algo: Option<HashAlgorithm>,

    /// Override the entry's stored digit count
    #[arg(long)]
    pub digits: Option<u32>,

    /// Auto-clear the code from the terminal after N seconds (default 30)
    #[arg(long)]
    pub auto_clear: Option<u32>,

    /// Suppress echo (codes go to stderr only, briefly)
    #[arg(long)]
    pub quiet: bool,

    /// Compute an OCRA (RFC 6287) challenge-response code instead of TOTP/HOTP.
    /// Entry must have been stored with `--type ocra`. Triggers OCRA mode
    /// for the duration of this invocation.
    #[arg(long)]
    pub ocra: bool,

    /// OCRA: server-provided challenge string (e.g. `"00000000"` for QN08).
    /// Required when `--ocra` is set; the UTF-8 bytes of this string are
    /// fed into OCRA's Q slot (RFC 6287 §6.1).
    #[arg(long, value_name = "STRING", requires = "ocra")]
    pub challenge: Option<String>,

    /// OCRA: override the C counter value (default 0).
    #[arg(long, value_name = "N", requires = "ocra")]
    pub counter: Option<u64>,

    /// OCRA: read the binary OCRA key from a file instead of the vault.
    /// **Testing escape hatch** — the raw bytes of the file are used as
    /// `K`. Removed once `origin-pass unlock` lands and entries can be
    /// looked up by name through the unlocked vault.
    #[arg(long, value_name = "PATH", requires = "ocra")]
    pub key_file: Option<PathBuf>,
}

#[derive(Parser, Clone, Debug)]
pub struct ExportQrArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// Entry name (must be an OTP entry)
    pub name: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct ImportQrArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// otpauth:// URI (literal, or @file to read from a file)
    pub uri: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct ChangePassphraseArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// Read CURRENT passphrase from file
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Read NEW passphrase from file (skips confirmation prompt)
    #[arg(long)]
    pub new_passphrase_file: Option<String>,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum EntryType {
    /// Password entry (secret is a UTF-8 string)
    Password,
    /// TOTP entry (secret is base32-encoded shared key)
    Otp,
    /// OCRA challenge-response entry (RFC 6287).
    /// Stored payload includes the raw OCRA key + suite parameters
    /// (algorithm, digits, default counter); entries of this type are
    /// consumed by `origin-pass code --ocra <name> --challenge <challenge>`.
    Ocra,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// Resolve `~/` prefix against `$HOME`. Errors if `$HOME` is unset so vault
/// files are never silently written to `/tmp`.
pub fn resolve_dir(raw: &str) -> Result<PathBuf, String> {
    if raw.starts_with("~/") {
        let home = std::env::var("HOME")
            .map_err(|_| "$HOME is unset; cannot expand ~/ paths. Pass an absolute path instead.".to_string())?;
        Ok(PathBuf::from(home).join(&raw[2..]))
    } else {
        Ok(PathBuf::from(raw))
    }
}
