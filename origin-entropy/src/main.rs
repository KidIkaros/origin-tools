use clap::Parser;
use origin_entropy::cli::Cli;

fn main() {
    let cli = Cli::parse();
    match origin_entropy::commands::dispatch(cli) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
