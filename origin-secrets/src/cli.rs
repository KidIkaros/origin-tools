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

    /// Passphrase file path
    #[arg(short = 'p', long)]
    pub passphrase_file: Option<PathBuf>,

    /// Config file path
    #[arg(short = 'c', long, default_value = "~/.origin/config.toml")]
    pub config: PathBuf,

    /// Verbose output
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Quiet mode (errors only)
    #[arg(short = 'q', long)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new vault
    Init(InitArgs),
    /// Shard a master key
    Shard(ShardArgs),
    /// Export a share to file
    ExportShare(ExportArgs),
    /// Recover master key from shares
    Recover(RecoverArgs),
    /// Verify signatures/integrity
    Verify(VerifyArgs),
    /// View/export audit logs
    Audit(AuditArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct InitArgs {
    /// Argon2id memory tier
    #[arg(long, default_value = "standard")]
    pub tier: String,

    /// Skip passphrase confirmation (dangerous)
    #[arg(long)]
    pub no_prompt: bool,
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