use clap::Parser;
use origin_shard::cli::Cli;

fn main() {
    let cli = Cli::parse();
    match origin_shard::commands::dispatch(cli) {
        Ok(()) => {}
        Err(e) => { eprintln!("error: {e}"); std::process::exit(1); }
    }
}
