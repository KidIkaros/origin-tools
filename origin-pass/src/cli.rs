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
    /// Unlock the vault (optionally writing a persisted session token)
    Unlock(UnlockArgs),
    /// Revoke a persisted session token file
    Lock(LockArgs),
    /// Revoke every persisted session token (optionally per vault)
    LockAll(LockAllArgs),
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
    /// Generate a random password or word-based passphrase
    Generate(GenerateArgs),
    /// List or revoke persisted session tokens
    Tokens(TokensArgs),
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

    /// Session token lifetime in seconds (default 8h). Only relevant
    /// with --session-token.
    #[arg(long, default_value_t = crate::session::DEFAULT_SESSION_TTL_SECS)]
    pub session_ttl: u64,

    /// Refresh the token automatically whenever a command uses it and
    /// its remaining lifetime drops below --auto-rotate-threshold
    #[arg(long, requires = "session_token")]
    pub auto_rotate: bool,

    /// Auto-rotate when remaining lifetime drops below this many
    /// seconds (default 15 minutes; requires --auto-rotate)
    #[arg(long)]
    pub auto_rotate_threshold: Option<u64>,

    /// Fresh lifetime after auto-rotation in seconds (default:
    /// --session-ttl; requires --auto-rotate)
    #[arg(long)]
    pub auto_rotate_ttl: Option<u64>,
}

#[derive(Parser, Clone, Debug)]
pub struct LockArgs {
    /// Revoke a persisted session token file (deletes it)
    #[arg(long)]
    pub session_token: Option<PathBuf>,
}

#[derive(Parser, Clone, Debug)]
pub struct LockAllArgs {
    /// Token store directory
    #[arg(long, default_value = "~/.origin/tokens")]
    pub dir: String,

    /// Only revoke tokens bound to this vault path
    #[arg(long)]
    pub vault: Option<String>,
}

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

    /// Use a persisted session token (from `unlock --session-token`)
    /// instead of a passphrase
    #[arg(long, value_name = "PATH", conflicts_with = "passphrase_file")]
    pub session_token: Option<PathBuf>,

    /// RFC 6287 OCRASuite string, required for --type ocra
    /// (e.g. "OCRA-1:HOTP-SHA1-6:QN08")
    #[arg(long, value_name = "SUITE")]
    pub suite: Option<String>,

    /// Optional URL associated with the entry
    #[arg(long)]
    pub url: Option<String>,

    /// Optional notes
    #[arg(long)]
    pub notes: Option<String>,

    /// Read the entry's secret from a file. Trailing whitespace and
    /// newlines are stripped. The secret never appears in argv or
    /// shell history. **Prefer this over an interactive prompt in
    /// automation.** Mutually exclusive with `--secret-stdin`.
    #[arg(long, value_name = "FILE", conflicts_with = "secret_stdin")]
    pub secret_file: Option<String>,

    /// Read the entry's secret from stdin (one line, trailing newline
    /// stripped). Useful for `echo "$PW" | origin-pass add …`
    /// pipelines. **The secret lives in your shell environment or
    /// process substitution; do not include it in argv.** Mutually
    /// exclusive with `--secret-file`.
    #[arg(long, conflicts_with = "secret_file")]
    pub secret_stdin: bool,

    /// Overwrite an existing entry with the same name. **--force
    /// REPLACES ALL FIELDS unconditionally** (secret, url, notes) —
    /// re-issue your `--url` / `--notes` if you don't want them wiped
    /// to None. Without this flag, adding an entry whose name already
    /// exists is a hard error (protects against accidental clobbering).
    #[arg(long)]
    pub force: bool,

    /// TOTP period in seconds (default 30). Only relevant for --type otp.
    #[arg(long, default_value_t = 30)]
    pub period: u32,

    /// Number of OTP digits (4..=10, default 6). Only relevant for --type otp.
    #[arg(long, default_value_t = 6)]
    pub digits: u32,

    /// OTP hash algorithm. Only relevant for --type otp.
    #[arg(long, value_enum, default_value = "sha1")]
    pub algo: HashAlgorithm,

    /// Initial HOTP counter (default 0). Only relevant for --type otp --hotp.
    #[arg(long, default_value_t = 0)]
    pub counter: u64,

    /// Create an HOTP entry instead of TOTP. Only relevant for --type otp.
    #[arg(long)]
    pub hotp: bool,
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

    /// Use a persisted session token (from `unlock --session-token`)
    /// instead of a passphrase
    #[arg(long, value_name = "PATH", conflicts_with = "passphrase_file")]
    pub session_token: Option<PathBuf>,
}

#[derive(Parser, Clone, Debug)]
pub struct ListArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Use a persisted session token (from `unlock --session-token`)
    /// instead of a passphrase
    #[arg(long, value_name = "PATH", conflicts_with = "passphrase_file")]
    pub session_token: Option<PathBuf>,
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

    /// Use a persisted session token (from `unlock --session-token`)
    /// instead of a passphrase
    #[arg(long, value_name = "PATH", conflicts_with = "passphrase_file")]
    pub session_token: Option<PathBuf>,
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

    /// Use a persisted session token (from `unlock --session-token`)
    /// instead of a passphrase
    #[arg(long, value_name = "PATH", conflicts_with = "passphrase_file")]
    pub session_token: Option<PathBuf>,

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
    /// `K`.
    #[arg(long, value_name = "PATH", requires = "ocra")]
    pub key_file: Option<PathBuf>,

    /// OCRA: PIN/password string required by suites with a P- component
    /// (e.g. `OCRA-1:HOTP-SHA1-6:QN08-PSHA1`). The UTF-8 bytes are fed
    /// into OCRA's P slot (RFC 6287 §6.2).
    #[arg(long, value_name = "STRING", requires = "ocra")]
    pub pin: Option<String>,

    /// Bypass the OCRA replay-nonce ledger check: re-issue a response
    /// for a challenge that has already been used for this entry.
    #[arg(long, requires = "ocra")]
    pub force: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct ExportQrArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// Entry name (must be an OTP/TOTP/HOTP entry)
    pub name: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Use a persisted session token (from `unlock --session-token`)
    /// instead of a passphrase
    #[arg(long, value_name = "PATH", conflicts_with = "passphrase_file")]
    pub session_token: Option<PathBuf>,

    /// Override the issuer embedded in the otpauth:// URI. Defaults to the
    /// entry name when omitted — matching how Google Authenticator labels
    /// one-entry-per-app vaults. Use this flag to produce a multi-entry
    /// export where all entries share one issuer (e.g. `Acme Corp`) but
    /// keep distinct account names.
    #[arg(long)]
    pub issuer: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct ImportQrArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// otpauth:// URI (literal, or @file to read from a file). Mirrors
    /// origin-identity's @file semantics: a leading `@` reads the URI
    /// content from disk (handy for QR-PNG OCR pipelines or sharing
    /// via signed messages).
    pub uri: String,

    /// Read passphrase from file instead of prompting
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Use a persisted session token (from `unlock --session-token`)
    /// instead of a passphrase
    #[arg(long, value_name = "PATH", conflicts_with = "passphrase_file")]
    pub session_token: Option<PathBuf>,

    /// Overwrite an existing entry with the same name. Without this flag,
    /// importing a URI whose label maps to an existing entry is a hard
    /// error (matches `cmd_add --force` semantics).
    #[arg(long)]
    pub force: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct ChangePassphraseArgs {
    /// Vault file path
    #[arg(short, long, default_value = "~/.origin/pass.vault")]
    pub vault: String,

    /// Read CURRENT passphrase from file
    #[arg(long)]
    pub passphrase_file: Option<String>,

    /// Use a persisted session token (from `unlock --session-token`)
    /// instead of a passphrase. **Rejected**: rotating the passphrase
    /// changes the master key, which invalidates any existing token.
    #[arg(long, value_name = "PATH", conflicts_with = "passphrase_file")]
    pub session_token: Option<PathBuf>,

    /// Read NEW passphrase from file (skips confirmation prompt)
    #[arg(long)]
    pub new_passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct GenerateArgs {
    /// Length of the generated password (default 24, max 512)
    #[arg(long, default_value_t = crate::generate::DEFAULT_LENGTH)]
    pub length: usize,

    /// Generate a word-based passphrase instead of a random password
    #[arg(long)]
    pub passphrase: bool,

    /// Number of words in a passphrase (default 8, 8 bits of entropy each)
    #[arg(long, default_value_t = crate::generate::DEFAULT_WORDS, requires = "passphrase")]
    pub words: usize,

    /// Exclude symbols (!@#$%^&*…) from the password charset
    #[arg(long)]
    pub exclude_symbols: bool,

    /// Exclude digits from the password charset
    #[arg(long)]
    pub exclude_digits: bool,

    /// Exclude uppercase letters from the password charset
    #[arg(long)]
    pub exclude_upper: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct TokensArgs {
    #[command(subcommand)]
    pub command: TokensCommand,
}

#[derive(Subcommand, Clone, Debug)]
pub enum TokensCommand {
    /// List session tokens in the token store
    List(TokensListArgs),
    /// Revoke a single session token by name (or path)
    Revoke(TokensRevokeArgs),
    /// Rotate a token in place: new bearer key + id + expiry, same vault
    /// binding (no passphrase needed while the current token is valid)
    Rotate(TokensRotateArgs),
    /// Renew a token in place: extend its expiry, keeping the same
    /// bearer key (no passphrase needed while the current token is valid)
    Renew(TokensRenewArgs),
    /// Revoke every session token in the store (optionally only expired)
    RevokeAll(TokensRevokeAllArgs),
    /// Revoke expired + unreadable tokens, reporting each one (cleanup)
    Prune(TokensPruneArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct TokensPruneArgs {
    /// Token store directory
    #[arg(long, default_value = "~/.origin/tokens")]
    pub dir: String,
}

#[derive(Parser, Clone, Debug)]
pub struct TokensRenewArgs {
    /// Token name (resolved into the store) or explicit path
    pub name: String,

    /// Token store directory (used when `name` is a bare store name)
    #[arg(long, default_value = "~/.origin/tokens")]
    pub dir: String,

    /// New lifetime in seconds (default: the token's lifetime span from
    /// creation to its current expiry)
    #[arg(long)]
    pub ttl: Option<u64>,
}

#[derive(Parser, Clone, Debug)]
pub struct TokensRotateArgs {
    /// Token name (resolved into the store) or explicit path
    pub name: String,

    /// Token store directory (used when `name` is a bare store name)
    #[arg(long, default_value = "~/.origin/tokens")]
    pub dir: String,

    /// New lifetime in seconds (default: the token's lifetime span from
    /// creation to its current expiry)
    #[arg(long)]
    pub ttl: Option<u64>,
}

#[derive(Parser, Clone, Debug)]
pub struct TokensListArgs {
    /// Token store directory
    #[arg(long, default_value = "~/.origin/tokens")]
    pub dir: String,

    /// Output format
    #[arg(long, value_enum, default_value_t = TokensFormat::Table)]
    pub format: TokensFormat,

    /// Only show tokens expiring within this many minutes (expired
    /// tokens always match). Exit code is 1 when at least one token
    /// matches — for alerting scripts — and 0 otherwise.
    #[arg(long, value_name = "MINS")]
    pub remaining: Option<u64>,
}

#[derive(Parser, Clone, Debug)]
pub struct TokensRevokeArgs {
    /// Token name (resolved into the store) or explicit path
    pub name: String,

    /// Token store directory (used when `name` is a bare store name)
    #[arg(long, default_value = "~/.origin/tokens")]
    pub dir: String,
}

#[derive(Parser, Clone, Debug)]
pub struct TokensRevokeAllArgs {
    /// Token store directory
    #[arg(long, default_value = "~/.origin/tokens")]
    pub dir: String,

    /// Only revoke tokens that have already expired (keeps valid ones)
    #[arg(long)]
    pub expired_only: bool,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum TokensFormat {
    /// Human-readable table
    Table,
    /// JSON array for shell parsing
    Json,
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
#[allow(dead_code)]
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
