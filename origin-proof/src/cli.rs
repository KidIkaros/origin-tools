use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "origin-proof",
    version,
    about = "Integrity proofs — Merkle Mountain Range"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Append data to an MMR and output the new state + append proof
    Append(AppendArgs),
    /// Compute the root hash of an MMR state
    Root(RootArgs),
    /// Generate a membership proof for a leaf
    Prove(ProveArgs),
    /// Verify a membership proof against a root hash
    Verify(VerifyArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct AppendArgs {
    /// MMR state file (JSON). If omitted, starts a new empty MMR.
    #[arg(short, long)]
    pub state: Option<String>,

    /// Data to append (hex)
    #[arg(long)]
    pub data: String,

    /// Output state file (default: stdout JSON)
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct RootArgs {
    /// MMR state file (JSON)
    #[arg(short, long)]
    pub state: String,
}

#[derive(Parser, Clone, Debug)]
pub struct ProveArgs {
    /// MMR state file (JSON)
    #[arg(short, long)]
    pub state: String,

    /// Leaf index to prove
    #[arg(long)]
    pub index: u64,
}

#[derive(Parser, Clone, Debug)]
pub struct VerifyArgs {
    /// Proof file (JSON)
    #[arg(short, long)]
    pub proof: String,

    /// Root hash (hex)
    #[arg(long)]
    pub root: String,
}
