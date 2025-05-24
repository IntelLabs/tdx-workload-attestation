use clap::Subcommand;

use tdx_workload_attestation::{error::Result, get_platform_name};

#[derive(Subcommand)]
pub enum PlatformCommands {
    /// Print the platform name
    Name,
    /// Check if TDX is supported
    IsTdxAvailable,
}

pub fn handle(cmd: PlatformCommands) -> Result<()> {
    match cmd {
        PlatformCommands::Name => {
            let name = get_platform_name()?;
            println!("{}", name);
        }
        PlatformCommands::IsTdxAvailable => {
            // get_platform_name() calls tdx::linus::is_v15_kvm_device() under the hood
            let name = get_platform_name()?;
            let mut available = false;
            if name == "tdx-linux" {
                available = true;
            }
            println!("TDX 1.5 available: {}", available);
        }
    }
    Ok(())
}
