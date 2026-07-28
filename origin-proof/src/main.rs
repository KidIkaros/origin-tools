use clap::Parser;
use origin_proof::cli::Cli;

fn main() {
    let cli = Cli::parse();
    match origin_proof::commands::dispatch(cli) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
