//! CLI argument parsing

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "origin-secrets")]
#[command(about = "Threshold secrets management — K-of-N recovery, post-quantum verification", long_about = None)]
pub struct Cli {
    /// Vault file path
    #[arg(short = 'V', long, default_value = "~/.origin/secrets.vault")]
    pub vault: PathBuf,

    /// Passphrase file path. Required for every command — there is no built-in
    /// default, so a command without -p fails with PassphraseRequired.
    #[arg(short = 'p', long)]
    pub passphrase_file: Option<PathBuf>,

    /// Machine-readable JSON output (for CI/automation; success prints
    /// {"ok":true}, failure prints {"ok":false,"code":...,"severity":...}).
    #[arg(long)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new vault
    #[command(
        after_help = "Example:\n  origin-secrets -V ./secrets.vault -p ./pw.txt init --tier standard"
    )]
    Init(InitArgs),
    /// Shard a master key
    #[command(
        after_help = "Example:\n  origin-secrets -V ./secrets.vault -p ./pw.txt shard --key master --threshold 3 --shares 5"
    )]
    Shard(ShardArgs),
    /// Export a share to file
    #[command(
        after_help = "Example:\n  origin-secrets -V ./secrets.vault -p ./pw.txt export-share --share 1 -o share1.json --recipient alice"
    )]
    ExportShare(ExportArgs),
    /// Recover master key from shares
    #[command(
        after_help = "Example:\n  origin-secrets -p ./pw.txt recover share_001.json share_002.json share_003.json -o seed.hex"
    )]
    Recover(RecoverArgs),
    /// Verify signatures/integrity
    #[command(
        after_help = "Example:\n  origin-secrets -V ./secrets.vault -p ./pw.txt verify --share share_001.json"
    )]
    Verify(VerifyArgs),
    /// View/export audit logs
    #[command(
        after_help = "Example:\n  origin-secrets -V ./secrets.vault -p ./pw.txt audit --export-soc2 soc2.json"
    )]
    Audit(AuditArgs),
    /// Generate shell completions
    #[command(about = "Generate shell completion scripts (bash/zsh/fish)")]
    Completions(CompletionsArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct InitArgs {
    /// Argon2id memory tier
    #[arg(long, default_value = "standard")]
    pub tier: String,
}

#[derive(Parser, Clone, Debug)]
pub struct ShardArgs {
    /// Key identifier to shard
    #[arg(long)]
    pub key: String,

    /// Minimum shares required (K)
    #[arg(long)]
    pub threshold: u8,

    /// Total shares to generate (N)
    #[arg(long)]
    pub shares: u8,
}

#[derive(Parser, Clone, Debug)]
pub struct ExportArgs {
    /// Share number (1-N)
    #[arg(long)]
    pub share: u8,

    /// Output file path
    #[arg(short = 'o', long)]
    pub out: PathBuf,

    /// Recipient identifier
    #[arg(long)]
    pub recipient: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct RecoverArgs {
    /// List of share files
    #[arg(required = true)]
    pub shares: Vec<PathBuf>,

    /// Output file path for the recovered seed (hex), or stdout if omitted
    #[arg(short = 'o', long)]
    pub out: Option<PathBuf>,

    /// Rebuild a usable vault from the recovered seed and write it to this path.
    /// The passphrase used is the one resolved by the dispatcher (e.g. from
    /// --passphrase-file). Requires --vault-out to also set a tier via --tier.
    #[arg(long)]
    pub vault_out: Option<PathBuf>,

    /// Security tier for the rebuilt vault (nano|standard|sovereign).
    /// Defaults to standard. Only used with --vault-out.
    #[arg(long, default_value = "standard")]
    pub tier: String,
}

#[derive(Parser, Clone, Debug)]
pub struct VerifyArgs {
    /// Verify vault integrity
    #[arg(long)]
    pub vault_path: Option<PathBuf>,

    /// Verify share integrity
    #[arg(long)]
    pub share: Option<PathBuf>,

    /// Verify recovery log entry
    #[arg(long)]
    pub recovery_log: Option<PathBuf>,
}

#[derive(Parser, Clone, Debug)]
pub struct AuditArgs {
    /// Show recovery log entries
    #[arg(long)]
    pub show_recovery_log: bool,

    /// Show all audit entries
    #[arg(long)]
    pub show_all_logs: bool,

    /// Show the failure journal (recorded failures, incl. pre-vault errors)
    #[arg(long)]
    pub show_failures: bool,

    /// Filter by key ID
    #[arg(long)]
    pub filter_key: Option<String>,

    /// Filter by user
    #[arg(long)]
    pub filter_user: Option<String>,

    /// Filter start date (ISO 8601)
    #[arg(long)]
    pub filter_start: Option<String>,

    /// Filter end date (ISO 8601)
    #[arg(long)]
    pub filter_end: Option<String>,

    /// Export SOC2 evidence
    #[arg(long)]
    pub export_soc2: Option<PathBuf>,

    /// Export PCI-DSS evidence
    #[arg(long)]
    pub export_pcidss: Option<PathBuf>,

    /// Export HIPAA evidence
    #[arg(long)]
    pub export_hipaa: Option<PathBuf>,
}

#[derive(Parser, Clone, Debug)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}
