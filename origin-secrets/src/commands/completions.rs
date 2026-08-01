//! `completions` subcommand: emit shell completion scripts.

use crate::cli::{Cli, CompletionsArgs};
use clap::CommandFactory;
use clap_complete::Shell;
use std::io;

/// Print a shell completion script for the given shell to stdout.
pub fn cmd_completions(args: CompletionsArgs) {
    let shell: Shell = args.shell;
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, bin_name, &mut io::stdout());
}
