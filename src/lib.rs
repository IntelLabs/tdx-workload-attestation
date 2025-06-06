//! # Intel TDX Workload Attestation Library
//!
//! This module provides a library for retrieving and verifying the attestations
//! of Intel TDX (Trust Domain Extensions) VM workloads.
//!
//! The library provides the following functionality:
//! - `error`: Custom error types
//! - `gcp`: Google Cloud Platform (GCP) host interface for TDX guests (when
//!   compiled with the `host-gcp-tdx` feature)
//! - `host`: Host interface for VM-based trusted execution environment (TEE)
//!   guests (when compiled with the `host-verification` feature)
//! - `provider`: Trusted execution environment (TEE) attestation interface
//! - `tdx`: Intel TDX guest attestation interface (when compiled with the
//!   `tdx-linux` feature)
//! - `verification`: Workload attestation verification utilities (when compiled
//!   with the `host-verification` feature)
//!
//! ## Example Usage
//!
//! ```no_run
//! use tdx_workload_attestation::tdx::LinuxTdxProvider;
//! use tdx_workload_attestation::provider::AttestationProvider;
//! use tdx_workload_attestation::get_platform_name;
//!
//! // Get the platform name
//! let platform = get_platform_name().unwrap();
//!
//! // Create a new provider instance
//! match platform.as_str() {
//!     "tdx-linux" => {
//!         let provider = LinuxTdxProvider::new();
//!
//!         // Get the attestation report
//!         let report = provider.get_attestation_report().unwrap();
//!
//!         // Get the launch measurement
//!         let measurement = provider.get_launch_measurement().unwrap();
//!
//!         // Do something else
//!     },
//!     // Can also throw an error here
//!     _ => println!("This platform does not support TDX"),
//! }
//! ```

pub mod error;
#[cfg(feature = "host-gcp-tdx")]
pub mod gcp;
#[cfg(feature = "host-verification")]
pub mod host;
pub mod provider;
#[cfg(feature = "tdx-linux")]
pub mod tdx;
#[cfg(feature = "host-verification")]
pub mod verification;

use error::Result;
#[cfg(feature = "tdx-linux")]
use tdx::linux::is_v15_kvm_device;

/// Retrieves the platform name for the current compute environment.
///
/// This function determines the platform name based on the operating system and
/// additional feature flags.
///
/// If the `tdx-linux` feature is enabled and the system supports TDX (Trust
/// Domain Extensions) 1.5 on a Linux KVM device, the platform name will be
/// returned as `"tdx-linux"`. Otherwise, it defaults to the operating system
/// name.
///
/// # Errors
///
/// Returns an error if support for TDX 1.5 on Linux cannot be determined
/// (requires the `tdx-linux` feature).
pub fn get_platform_name() -> Result<String> {
    let name = std::env::consts::OS;

    #[cfg(feature = "tdx-linux")]
    if is_v15_kvm_device()? {
        return Ok("tdx-linux".to_string());
    }

    Ok(name.to_string())
}
