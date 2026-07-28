use clap::Parser;
use origin_schnorr::cli::Cli;

fn main() {
    let cli = Cli::parse();
    match origin_schnorr::commands::dispatch(cli) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
