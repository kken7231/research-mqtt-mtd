use crate::certgen::{CertgenArgs, certgen};
use clap::{Parser, Subcommand};

mod certgen;

/// Command-line arguments for the certificate generator.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate certificates for testing
    Certgen(CertgenArgs),
}

fn main() {
    let args: Args = Args::parse();
    match args.command {
        Commands::Certgen(args) => certgen(args).expect("failed to generate certs"),
    };
}
