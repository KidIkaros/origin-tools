//! Origin Secrets: Threshold secrets management CLI

pub mod audit;
#[cfg(test)]
mod audit_tests;
pub mod cli;
pub mod commands;
pub mod crypto;
#[cfg(test)]
mod dispatch_tests;
pub mod error;
pub mod observability;
pub mod share;
#[cfg(test)]
mod share_tests;
pub mod vault;

pub use cli::Cli;
pub use crypto::{decrypt_vault_data, encrypt_vault_data, EncryptedVault};
pub use error::Error;

/// Dispatch CLI command to appropriate handler
pub fn dispatch(cli: Cli) -> Result<(), Error> {
    match cli.command {
        // Generating shell completions never touches a vault or passphrase.
        cli::Commands::Completions(args) => {
            crate::commands::completions::cmd_completions(args);
            Ok(())
        }
        // `init` owns its passphrase policy (refuses without a source, since
        // interactive prompting is not yet implemented). It reads the global
        // -p/--passphrase-file when supplied.
        cli::Commands::Init(args) => {
            commands::init::cmd_init(args, &cli.vault, cli.passphrase_file.as_deref())
        }
        // Every other command opens or writes an encrypted vault and therefore
        // requires a passphrase. A missing -p is a hard error — we never fall
        // back to a built-in default, which would let an operator believe a
        // vault is protected when it is trivially decryptable.
        other => {
            let path = cli
                .passphrase_file
                .as_ref()
                .ok_or(Error::PassphraseRequired)?;
            let passphrase = std::fs::read_to_string(path)
                .map_err(|e| Error::IoError(format!("reading passphrase file: {e}")))?;
            let passphrase = passphrase.trim_end_matches('\n');
            match other {
                cli::Commands::Shard(args) => {
                    commands::shard::cmd_shard(args, &cli.vault, passphrase).map(|_| ())
                }
                cli::Commands::ExportShare(args) => {
                    commands::export::cmd_export_share(args, &cli.vault, passphrase).map(|_| ())
                }
                cli::Commands::Recover(args) => {
                    commands::recover::cmd_recover(args, passphrase).map(|_| ())
                }
                cli::Commands::Verify(args) => {
                    commands::verify::cmd_verify(args, &cli.vault, passphrase)
                }
                cli::Commands::Audit(args) => {
                    commands::audit::cmd_audit(args, &cli.vault, passphrase)
                }
                cli::Commands::Init(_) | cli::Commands::Completions(_) => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatch_init_command() {
        let dir = tempfile::tempdir().unwrap();
        let cli = Cli {
            vault: dir.path().join("test.vault"),
            passphrase_file: None,
            json: false,
            command: cli::Commands::Init(cli::InitArgs {
                tier: "standard".to_string(),
            }),
        };

        let result = dispatch(cli);
        // Without -p the dispatcher must refuse (PassphraseRequired), not create
        // a vault with a weak default.
        assert!(matches!(result, Err(Error::PassphraseRequired)));
    }
}
