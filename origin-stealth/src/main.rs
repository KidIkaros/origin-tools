use clap::Parser;
use origin_stealth::cli::Cli;

fn main() {
    let cli = Cli::parse();
    match origin_stealth::commands::dispatch(cli) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
