use clap::Parser;
use origin_seed::cli::Cli;

fn main() {
    let cli = Cli::parse();
    match origin_seed::commands::dispatch(cli) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
