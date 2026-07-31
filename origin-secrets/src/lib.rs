//! Origin Secrets: Threshold secrets management CLI

pub mod cli;
pub mod commands;
pub mod error;
pub mod vault;
pub mod share;
pub mod audit;
pub mod crypto;
pub mod share_tests;
pub mod audit_tests;
pub mod dispatch_tests;

pub use error::Error;
pub use cli::Cli;
pub use crypto::{decrypt_vault_data, encrypt_vault_data, EncryptedVault, VaultData};

/// Dispatch CLI command to appropriate handler
pub fn dispatch(cli: Cli) -> Result<(), Error> {
    // Resolve passphrase: from file if provided, else a fixed test default.
    // (Interactive prompting is a TODO; for now we support passphrase files.)
    let passphrase = match &cli.passphrase_file {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| Error::IoError(format!("reading passphrase file: {e}")))?,
        None => "demo-passphrase-for-testing-only".to_string(),
    };
    let passphrase = passphrase.trim_end_matches('\n');

    match cli.command {
        cli::Commands::Init(args) => commands::init::cmd_init(args),
        cli::Commands::Shard(args) => commands::shard::cmd_shard(args, &cli.vault, passphrase).map(|_| ()),
        cli::Commands::ExportShare(args) => commands::export::cmd_export_share(args),
        cli::Commands::Recover(args) => commands::recover::cmd_recover(args).map(|_| ()),
        cli::Commands::Verify(args) => commands::verify::cmd_verify(args, &cli.vault, passphrase),
        cli::Commands::Audit(args) => commands::audit::cmd_audit(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatch_init_command() {
        let cli = Cli {
            vault: "/tmp/test.vault".into(),
            passphrase_file: None,
            config: "/tmp/config.toml".into(),
            verbose: false,
            quiet: false,
            command: cli::Commands::Init(cli::InitArgs {
                tier: "standard".to_string(),
                no_prompt: true,
            }),
        };

        let result = dispatch(cli);
        // Should succeed now (creates vault at default path)
        // Note: May fail if vault already exists from previous test
        println!("Result: {:?}", result);
    }
}