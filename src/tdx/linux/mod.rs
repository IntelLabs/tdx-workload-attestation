//! # TDX 1.5 KVM Device Utilities for Linux Guests
//!
//! This module provides high-level utilities for interacting with Intel TDX 1.5 KVM devices.
//! It includes functions to check the availability of the TDX 1.5 KVM device and to retrieve
//! and parse the attestation report (`TDREPORT`) from the device.
//!
//! ## Example Usage
//! ```no_run
//! use tdx_workload_attestation::tdx::linux::{is_v15_kvm_device, get_tdreport_v15_kvm};
//! use tdx_workload_attestation::tdx::TDX_REPORT_DATA_LEN;
//!
//! // Check if TDX 1.5 KVM device is available
//! match is_v15_kvm_device() {
//!     Ok(true) => println!("TDX 1.5 KVM device is available."),
//!     Ok(false) => println!("TDX 1.5 KVM device is not available."),
//!     Err(e) => println!("Error checking device availability: {:?}", e),
//! }
//!
//! // Example report data (dummy data)
//! let report_data: [u8; TDX_REPORT_DATA_LEN] = [0; TDX_REPORT_DATA_LEN];
//!
//! // Retrieve the TDREPORT
//! let td_report = get_tdreport_v15_kvm(&report_data).unwrap();
//!
//! // Access fields from the parsed TDREPORT
//! println!("MRTD: {:?}", td_report.get_mrtd());
//! ```
//!
//! # Notes
//! - The `get_tdreport_v15_kvm` function assumes that the device node is accessible and properly configured.
//! - The `report_data` parameter must be a 64-byte array, as required by the TDX 1.5 specification.
//!
//! # Errors
//! - The `is_v15_kvm_device` function may return an error if the device node is not accessible or valid.
//! - The `get_tdreport_v15_kvm` function will panic if the device interaction fails (e.g., due to an invalid ioctl operation).

pub mod device;

use crate::error::Result;
use crate::tdx::TDX_REPORT_DATA_LEN;
use crate::tdx::report::TdReportV15;

/// Checks whether the Intel TDX 1.5 KVM device node is available and valid for use.
pub fn is_v15_kvm_device() -> Result<bool> {
    let is_device = device::TdxDeviceKvmV15::is_available()?;

    Ok(is_device)
}

/// Retrieves the `TDREPORT` from the Intel TDX 1.5 KVM device and parses it into a `TdReportV15` structure.
pub fn get_tdreport_v15_kvm(report_data: &[u8; TDX_REPORT_DATA_LEN]) -> Result<TdReportV15> {
    // Initialize the KVM device for TDX 1.5
    let tdx_device = device::TdxDeviceKvmV15::new();

    // Create the request
    let req = TdReportV15::create_request(report_data);

    // Get the TDREPORT from the hardware device
    let raw_report = tdx_device.get_tdreport_raw(&req)?;

    // Extract the report from the raw report
    TdReportV15::get_tdreport_from_bytes(&raw_report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tdx::test_utils::handle_expected_tdx_error;

    // No need to test is_v15_kvm_device() because it's simply a public wrapper
    // around device::is_available(), which has its own unit test

    #[test]
    fn test_get_tdreport_v15_kvm() -> Result<()> {
        let report_data: [u8; 64] = [0; 64];

        match get_tdreport_v15_kvm(&report_data) {
            Ok(report) => {
                println!("Got TDREPORT: {:?}", report);
                Ok(())
            }
            Err(e) => handle_expected_tdx_error(e),
        }
    }
}
