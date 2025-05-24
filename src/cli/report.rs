use clap::Subcommand;

use tdx_workload_attestation::{
    error::{Error, Result},
    tdx::LinuxTdxProvider,
    tdx::provider::AttestationProvider;
};

#[derive(Debug, Subcommand)]
pub enum ReportCommands {
    /// Print the whole report
    Print,
}

pub fn handle(cmd: ReportCommands) -> Result<()> {
    match cmd {

    }
}
