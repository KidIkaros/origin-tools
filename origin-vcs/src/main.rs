use clap::Parser;
use origin_vcs::cli::Cli;

fn main() {
    let cli = Cli::parse();
    if let Err(e) = origin_vcs::commands::dispatch(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
