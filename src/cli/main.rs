use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::Write;
use tdx_workload_attestation::{
    error::{Error, Result},
    provider::AttestationProvider,
    tdx::LinuxTdxProvider,
};
#[cfg(feature = "host-gcp-tdx")]
use tdx_workload_attestation::{gcp::GcpTdxHost, host::TeeHost};

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
    #[command(alias = "p")]
    Platform {
        #[command(subcommand)]
        command: platform::PlatformCommands,
    },
    /// Quote the TD, if available
    #[command(alias = "q")]
    Quote {
        /// Only extract the static launch measurement (MRTD) from the quote (cannot be used with --out-file)
        #[arg(short, long = "launch-measurement", default_value = "false")]
        mrtd_only: bool,
        /// The filename to save the TD's quote (must be set with --save)
        #[arg(
            short,
            long = "out-file",
            default_value = "",
            required_if_eq("save", "true")
        )]
        out_file: String,
        /// Save the JSON-encoded TD quote to a file
        #[arg(short, long = "save", default_value = "false")]
        save: bool,
    },
    #[cfg(feature = "host-gcp-tdx")]
    /// Verify the TD, if available
    #[command(alias = "V")]
    Verify {
        /// Only verify the static launch measurement (MRTD) of the TD
        #[arg(short, long = "verify-launch", default_value = "false")]
        launch_only: bool,
    },
}

fn handle_not_supported(e: Error) -> Result<()> {
    match e {
        Error::NotSupported(_) => {
            // we don't actually want the CLI to error when TDX isn't supported
            println!("This platform does not support TDX 1.5!");
            Ok(())
        }
        _ => Err(e),
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

#[cfg(feature = "host-gcp-tdx")]
fn handle_verification(launch_only: bool) -> Result<()> {
    let provider = LinuxTdxProvider::new();

    if launch_only {
        let mrtd = provider.get_launch_measurement()?;

        let gcp_host = GcpTdxHost::new(&mrtd)?;

        let passed = gcp_host.verify_launch_endorsement()?;

        if passed {
            println!("TD launch measurement (MRTD) verification passed!");
        } else {
            println!(
                "TD launch measurement (MRTD) verification failed: TD did not match GCP's endorsed measurement"
            );
        }
        Ok(())
    } else {
        // TODO: implement workload attestation
        return Err(Error::NotSupported(
            "Only TD launch measurement verification is currently supported on GCP".to_string(),
        ));
    }
}

fn main() -> Result<()> {
    // Parse command line arguments
    let args = Cli::parse();

    // Handle commands

    match args.command {
        Commands::Platform { command } => platform::handle(command),
        Commands::Quote {
            mrtd_only,
            out_file,
            save,
        } => handle_quote(mrtd_only, out_file, save),
        #[cfg(feature = "host-gcp-tdx")]
        Commands::Verify { launch_only } => handle_verification(launch_only),
    }
}
