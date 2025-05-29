use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::Write;
use tdx_workload_attestation::{
    error::{Error, Result},
    provider::AttestationProvider,
    tdx::LinuxTdxProvider,
};

mod platform;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Platform-related commands
    Platform {
        #[command(subcommand)]
        command: platform::PlatformCommands,
    },
    /// Quote the TD, if available
    Quote {
        /// Only extract the static launch measurement (MRTD) from the quote (cannot be used with --out-file)
        #[arg(short, long = "launch-measurement", default_value = "false")]
        mrtd_only: bool,
        /// The filename to save the TD's quote (must be set with --save)
        #[arg(short, long = "out-file", default_value = "")]
        out_file: String,
        /// Save the JSON-encoded TD quote to a file
        #[arg(short, long = "save", default_value = "false")]
        save: bool,
    },
}

fn handle_not_supported(e: Error) -> Result<()> {
    match e {
        Error::NotSupported(_) => {
            // we don't actually want the CLI to error when TDX isn't supported
            println!("This platform does not support TDX 1.5!");
            Ok(())
        }
        _ => return Err(e),
    }
}

fn handle_quote(mrtd_only: bool, out_file: String, save: bool) -> Result<()> {
    let provider = LinuxTdxProvider::new();
    if mrtd_only {
        match provider.get_launch_measurement() {
            Ok(mrtd) => {
                println!("Launch measurement (MRTD): {}", hex::encode(mrtd));
                Ok(())
            }
            Err(e) => handle_not_supported(e),
        }
    } else {
        if save && out_file.is_empty() {
            return Err(Error::NotSupported(
                "Output file cannot be empty when saving the TD quote".to_string(),
            ));
        }
        match provider.get_attestation_report() {
            Ok(report) => {
                if save {
                    let mut file = File::create(&out_file)?;
                    file.write_all(report.as_bytes())?;
                    println!("Saved TD report (JSON-encoded) to {}", out_file);
                } else {
                    println!("TD Report: {}", report);
                }
                Ok(())
            }
            Err(e) => handle_not_supported(e),
        }
    }
}

fn main() -> Result<()> {
    // Parse command line arguments
    let args = Cli::parse();

    // Handle commands
    let result = match args.command {
        Commands::Platform { command } => platform::handle(command),
        Commands::Quote {
            mrtd_only,
            out_file,
            save,
        } => handle_quote(mrtd_only, out_file, save),
    };

    result
}
