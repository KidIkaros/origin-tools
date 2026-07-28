use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "origin-stealth", version, about = "Stealth addresses and proof-of-work")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Derive stealth master keys from a seed
    Master(MasterArgs),
    /// Generate a stealth address at a specific index
    Address(AddressArgs),
    /// Solve a PoW challenge
    Solve(SolveArgs),
    /// Verify a PoW proof
    Verify(VerifyArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct MasterArgs {
    /// Seed (hex)
    #[arg(long)]
    pub seed: Option<String>,

    /// Use the suite identity (~/.origin/identity.seed)
    #[arg(long)]
    pub identity: bool,

    /// Passphrase file for identity
    #[arg(long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct AddressArgs {
    /// Seed (hex)
    #[arg(long)]
    pub seed: Option<String>,

    /// Use the suite identity
    #[arg(long)]
    pub identity: bool,

    /// Address index
    #[arg(long)]
    pub index: u64,

    /// Passphrase file for identity
    #[arg(long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct SolveArgs {
    /// Seed (hex)
    #[arg(long)]
    pub seed: Option<String>,

    /// Use the suite identity
    #[arg(long)]
    pub identity: bool,

    /// Address index
    #[arg(long)]
    pub index: u64,

    /// Difficulty (number of leading zero bits)
    #[arg(long, default_value = "16")]
    pub difficulty: u32,

    /// Passphrase file for identity
    #[arg(long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct VerifyArgs {
    /// Proof file (JSON)
    #[arg(short, long)]
    pub proof: String,

    /// Difficulty
    #[arg(long, default_value = "16")]
    pub difficulty: u32,

    /// Address index
    #[arg(long)]
    pub index: u64,
}
