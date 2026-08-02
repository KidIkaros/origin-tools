//! Origin Secrets: Threshold secrets management CLI

use std::io::IsTerminal;

pub mod audit;
#[cfg(test)]
mod audit_tests;
pub mod cli;
pub mod commands;
pub mod constant_time;
pub mod crypto;
#[cfg(test)]
mod dispatch_tests;
pub mod error;
#[cfg(test)]
mod lib_tests;
pub mod observability;
pub mod share;
#[cfg(test)]
mod share_tests;
pub mod vault;
pub mod vault_handle;

pub use cli::Cli;
pub use crypto::{decrypt_vault_data, encrypt_vault_data, EncryptedVault};
pub use error::Error;

/// Resolve the passphrase from `-p/--passphrase-file` or `--prompt`.
///
/// - `None` → prompt on a TTY, or [`Error::PassphraseRequired`] when non-interactive.
/// - `Some(Path)` where the path is `-` → read from stdin (so scripts can pipe
///   a secret without ever writing it to disk: `echo "$PW" | origin-secrets -p - ...`).
/// - `Some(Path)` otherwise → read the file contents.
/// - If `prompt` is true → read interactively from TTY using rpassword.
///
/// The trailing newline (and CR) is trimmed so a `echo`-written file does not
/// contribute a stray `\n` to the passphrase.
pub fn resolve_passphrase(
    passphrase_file: Option<&std::path::Path>,
    prompt: bool,
) -> Result<String, Error> {
    // Interactive terminals get a secure prompt by default. Non-interactive
    // callers must provide an explicit file or stdin source so CI never blocks.
    let prompt = prompt || (passphrase_file.is_none() && std::io::stdin().is_terminal());
    if prompt {
        let passphrase = rpassword::prompt_password("Enter passphrase: ")
            .map_err(|e| Error::IoError(format!("reading passphrase from TTY: {e}")))?;
        return Ok(passphrase);
    }

    let path = passphrase_file.ok_or(Error::PassphraseRequired)?;
    let raw = if path.as_os_str() == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| Error::IoError(format!("reading passphrase from stdin: {e}")))?;
        buf
    } else {
        std::fs::read_to_string(path)
            .map_err(|e| Error::IoError(format!("reading passphrase file {path:?}: {e}")))?
    };
    Ok(raw.trim_end_matches(['\n', '\r']).to_string())
}

/// Dispatch CLI command to appropriate handler
pub fn dispatch(cli: Cli) -> Result<(), Error> {
    let json = cli.json;
    // Expand a leading `~` in the vault path (clap does not do this itself).
    let resolved_vault = cli::expand_tilde(cli.vault.clone());
    match cli.command {
        // Generating shell completions never touches a vault or passphrase.
        cli::Commands::Completions(args) => {
            crate::commands::completions::cmd_completions(args);
            Ok(())
        }
        // `init` owns its passphrase policy (refuses without a source). It reads the global
        // -p/--passphrase-file or --prompt when supplied.
        cli::Commands::Init(args) => commands::init::cmd_init(
            args,
            &resolved_vault,
            cli.passphrase_file.as_deref(),
            cli.prompt,
            json,
        ),
        // Status can report an uninitialized product without a passphrase. An
        // existing vault is opened only when a passphrase source is available.
        cli::Commands::Status(args) => {
            let passphrase = if resolved_vault.exists() {
                Some(resolve_passphrase(
                    cli.passphrase_file.as_deref(),
                    cli.prompt,
                )?)
            } else {
                None
            };
            commands::status::cmd_status(args, &resolved_vault, passphrase.as_deref(), json)
        }
        // Handoff manifests can describe moved plaintext/exported shares without
        // a vault; an existing vault is used only when the operator supplies its
        // passphrase so encrypted local shares can also be described.
        cli::Commands::Handoff(args) => {
            let passphrase = if resolved_vault.exists() {
                Some(resolve_passphrase(
                    cli.passphrase_file.as_deref(),
                    cli.prompt,
                )?)
            } else {
                None
            };
            commands::handoff::cmd_handoff(args, &resolved_vault, passphrase.as_deref(), json)
        }
        // Diagnose is deliberately vault-independent and never resolves a
        // passphrase, so it remains safe to run while troubleshooting access.
        cli::Commands::Diagnose(args) => {
            commands::diagnose::cmd_diagnose(args, &resolved_vault, json)
        }
        // Every other command opens or writes an encrypted vault and therefore
        // requires a passphrase. A missing -p is a hard error — we never fall
        // back to a built-in default, which would let an operator believe a
        // vault is protected when it is trivially decryptable.
        other => {
            let passphrase = resolve_passphrase(cli.passphrase_file.as_deref(), cli.prompt)?;
            match other {
                cli::Commands::Shard(args) => {
                    commands::shard::cmd_shard(args, &resolved_vault, &passphrase, json).map(|_| ())
                }
                cli::Commands::ExportShare(args) => {
                    commands::export::cmd_export_share(args, &resolved_vault, &passphrase, json)
                        .map(|_| ())
                }
                cli::Commands::Recover(args) => {
                    // P3.3: shares are encrypted at rest, so even a share-only
                    // recovery must open the (sibling) vault to decrypt them and
                    // enforce revocation. The passphrase is always required.
                    commands::recover::cmd_recover(args, &passphrase, json).map(|_| ())
                }
                cli::Commands::Verify(args) => {
                    commands::verify::cmd_verify(args, &resolved_vault, &passphrase, json)
                }
                cli::Commands::Audit(args) => {
                    commands::audit::cmd_audit(args, &resolved_vault, &passphrase, json)
                }
                cli::Commands::RotatePassphrase(args) => commands::rotate::cmd_rotate_passphrase(
                    args,
                    &resolved_vault,
                    &passphrase,
                    json,
                ),
                cli::Commands::ListKeys(args) => {
                    commands::keys::cmd_list_keys(args, &resolved_vault, &passphrase, json)
                        .map(|_| ())
                }
                cli::Commands::ListShares(args) => {
                    commands::shares::cmd_list_shares(args, &resolved_vault, &passphrase, json)
                        .map(|_| ())
                }
                cli::Commands::RevokeShare(args) => {
                    commands::revoke::cmd_revoke_share(args, &resolved_vault, &passphrase, json)
                        .map(|_| ())
                }
                cli::Commands::Init(_)
                | cli::Commands::Completions(_)
                | cli::Commands::Status(_)
                | cli::Commands::Handoff(_)
                | cli::Commands::Diagnose(_) => {
                    unreachable!()
                }
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
            prompt: false,
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
