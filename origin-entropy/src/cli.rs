use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "origin-entropy", version, about = "Entropy auditing — Shannon, chi-squared, quality")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze entropy of input data
    Analyze(AnalyzeArgs),
    /// Check quality against requirements for a given bit size
    Check(CheckArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct AnalyzeArgs {
    /// Input file (default: stdin)
    #[arg(short, long)]
    pub input: Option<String>,

    /// Output format (json, text)
    #[arg(short, long, default_value = "json")]
    pub format: String,
}

#[derive(Parser, Clone, Debug)]
pub struct CheckArgs {
    /// Input file (default: stdin)
    #[arg(short, long)]
    pub input: Option<String>,

    /// Expected bit size (e.g. 256 for a seed)
    #[arg(long)]
    pub bits: u32,

    /// Output format (json, text)
    #[arg(short, long, default_value = "json")]
    pub format: String,
}
