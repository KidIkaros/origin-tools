use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "origin-schnorr", version, about = "EC Schnorr zero-knowledge proofs")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a keypair from a seed
    Keygen(KeygenArgs),
    /// Prove knowledge of a secret key
    Prove(ProveArgs),
    /// Verify a Schnorr proof
    Verify(VerifyArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct KeygenArgs {
    /// Seed (hex, 32 bytes)
    #[arg(long)]
    pub seed: Option<String>,

    /// Use the suite identity
    #[arg(long)]
    pub identity: bool,

    /// Passphrase file for identity
    #[arg(long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct ProveArgs {
    /// Input data to prove knowledge of (file or stdin)
    #[arg(short, long)]
    pub input: Option<String>,

    /// Secret key (hex, 32 bytes)
    #[arg(long)]
    pub secret: Option<String>,

    /// Public key (hex)
    #[arg(long)]
    pub public: Option<String>,

    /// Use the suite identity for key generation
    #[arg(long)]
    pub identity: bool,

    /// Passphrase file for identity
    #[arg(long)]
    pub passphrase_file: Option<String>,
}

#[derive(Parser, Clone, Debug)]
pub struct VerifyArgs {
    /// Proof file (JSON)
    #[arg(short, long)]
    pub proof: String,

    /// Public key (hex). Required unless `--identity` is set.
    #[arg(long)]
    pub public: Option<String>,

    /// Message (hex)
    #[arg(long)]
    pub message: String,

    /// Use the suite identity (derives the Ed25519 public key)
    #[arg(long)]
    pub identity: bool,

    /// Passphrase file for identity
    #[arg(long)]
    pub passphrase_file: Option<String>,
}
