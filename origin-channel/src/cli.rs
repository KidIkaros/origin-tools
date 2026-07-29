// SPDX-License-Identifier: Apache-2.0

//! CLI surface for origin-channel — pure clap definitions, no logic.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "origin-channel",
    version,
    about = "Encrypted sessions — Noise handshake, double ratchet, AEAD messaging"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate an X25519 keypair for channel handshakes
    Keygen(KeygenArgs),
    /// Show the public key fingerprint for an identity
    Fingerprint(FingerprintArgs),
    /// Run a local handshake demo (both sides in-process)
    Demo(DemoArgs),
}

#[derive(Parser, Clone, Debug)]
pub struct KeygenArgs {
    /// Output file for the keypair (JSON)
    #[arg(short, long, default_value = "~/.origin/channel-keys.json")]
    pub output: String,

    /// Overwrite existing file
    #[arg(long)]
    pub force: bool,
}

#[derive(Parser, Clone, Debug)]
pub struct FingerprintArgs {
    /// Path to the keypair JSON file
    #[arg(short, long, default_value = "~/.origin/channel-keys.json")]
    pub keyfile: String,
}

#[derive(Parser, Clone, Debug)]
pub struct DemoArgs {
    /// Number of messages to exchange after handshake
    #[arg(short, long, default_value = "5")]
    pub messages: usize,
}
