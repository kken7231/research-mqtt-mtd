use crate::certgen::{certgen, CertgenArgs};
use clap::{Parser, Subcommand};
use std::error::Error;

pub(crate) mod certgen;

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

fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = Args::parse();
    match args.command {
        Commands::Certgen(args) => certgen(args)?,
    };
    Ok(())
}
