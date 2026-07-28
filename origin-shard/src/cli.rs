use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "origin-shard",
    version,
    about = "Secret sharing — Reed-Solomon split and recover"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Split data into N shards using Reed-Solomon
    Split(SplitArgs),
    /// Recover data from K shards
    Recover(RecoverArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct SplitArgs {
    /// Input file (default: stdin)
    #[arg(short, long)]
    pub input: Option<String>,

    /// Output directory for shards
    #[arg(short, long)]
    pub output: String,

    /// Number of data shards
    #[arg(long, default_value = "3")]
    pub data_shards: usize,

    /// Number of parity shards
    #[arg(long, default_value = "2")]
    pub parity_shards: usize,
}

#[derive(Parser, Clone, Debug)]
pub struct RecoverArgs {
    /// Directory containing shard files
    #[arg(short, long)]
    pub input: String,

    /// Output file (default: stdout)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Number of data shards
    #[arg(long, default_value = "3")]
    pub data_shards: usize,

    /// Number of parity shards
    #[arg(long, default_value = "2")]
    pub parity_shards: usize,
}
