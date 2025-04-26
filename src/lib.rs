pub mod error;
#[cfg(feature = "host-gcp-tdx")]
pub mod host;
pub mod provider;
#[cfg(feature = "tdx-linux")]
pub mod tdx;

use error::{Error, Result};
#[cfg(feature = "host-gcp-tdx")]
use host::TeeHost;
use provider::AttestationProvider;
#[cfg(feature = "tdx-linux")]
use tdx::LinuxTdxProvider;
#[cfg(feature = "host-gcp-tdx")]
use tdx::gcp::GcpTdxHost;
#[cfg(feature = "tdx-linux")]
use tdx::linux::is_v15_kvm_device;

pub fn get_platform_name() -> Result<String> {
    let name = std::env::consts::OS;

    #[cfg(feature = "tdx-linux")]
    if is_v15_kvm_device()? {
        return Ok("tdx-linux".to_string());
    }

    Ok(name.to_string())
}

pub fn get_report(show: bool) -> Result<String> {
    // Select the appropriate provider based on platform and current OS
    let platform = get_platform_name()?;

    let provider: Box<dyn AttestationProvider> = match platform.as_str() {
        #[cfg(feature = "tdx-linux")]
        "tdx-linux" => Box::new(LinuxTdxProvider::new()),
        _ => {
            return Err(Error::NotSupported(format!(
                "get_report for platform {}",
                platform
            )));
        }
    };

    // Get the attestation report from the provider
    let report = provider.get_attestation_report()?;

    if show {
        println!("Got report: {}", &report);
    }

    Ok(report)
}

pub fn get_launch_measurement() -> Result<[u8; 48]> {
    // Select the appropriate provider based on platform and current OS
    let platform = get_platform_name()?;

    let provider: Box<dyn AttestationProvider> = match platform.as_str() {
        #[cfg(feature = "tdx-linux")]
        "tdx-linux" => Box::new(LinuxTdxProvider::new()),
        _ => {
            return Err(Error::NotSupported(format!(
                "get_launch_measurement for platform {}",
                platform
            )));
        }
    };

    // Get the measurement from the provider
    let measurement = provider.get_launch_measurement()?;

    Ok(measurement)
}

#[cfg(feature = "host-verification")]
pub fn verify_launch_endorsement(host_platform: &str) -> Result<bool> {
    // Get the launch measurement for the current platform
    let measurement = get_launch_measurement()?;

    let result: bool;

    // Get the launch endorsement from the specific host, if possible
    match host_platform {
        #[cfg(feature = "host-gcp-tdx")]
        "gcp-tdx" => {
            let gcp_host = GcpTdxHost::new(&measurement);
            result = gcp_host.verify_launch_endorsement()?;
        }
        _ => {
            return Err(Error::NotSupported(format!(
                "Launch endorsement verification for platform {}",
                host_platform
            )));
        }
    };

    Ok(result)
}
