// Rust implementation of https://github.com/canonical/tdx/blob/2cd1a182323bad17d80a2f491c63679ac6b73e7f/tests/lib/tdx-tools/src/tdxtools/utility.py

//! # Intel TDX KVM Device
//!
//! This module provides functionality for interacting with a KVM-based
//! Intel TDX device. Its main purpose is to provide APIs for retrieving
//! the quote/signed attestation report from the TDX device.
//!
//! The module currently only supports TDX 1.5 KVM devices located at
//! `"/dev/tdx_guest"`.
//!
//! ## Example Usage
//!
//! ```rust
//! use device::TdxDeviceKvm15;
//!
//! // Create a new instance of TdxDeviceKvmV15
//! let tdx_device = TdxDeviceKvmV15::new();
//!
//! // Check if the device is available
//! match TdxDeviceKvmV15::is_available() {
//!     Ok(true) => println!("TDX device is available."),
//!     Ok(false) => println!("TDX device is not available."),
//!     Err(e) => println!("Error checking device availability: {:?}", e),
//! }
//!
//! // Example request buffer
//! let request: [u8; 1088] = [0; 1088];
//!
//! // Retrieve the raw TD report
//! match tdx_device.get_tdreport_raw(&request) {
//!     Ok(response) => println!("TD report retrieved successfully: {:?}", response),
//!     Err(e) => println!("Error retrieving TD report: {:?}", e),
//! }
//! ```
//!
//! ## Errors
//!
//! The module uses custom `Error` types, including:
//!   - `Error::NotSupported`: Returned when the device node is a symlink or not available.
//!   - `Error::QuoteError`: Returned when a report operation fails or the device cannot be accessed.
//!
//! ## Notes
//! - The module is currently designed to work specifically with Intel TDX 1.5 devices.
//! - Ensure that the expected guest OS is based on an enlightened Linux kernel.

use crate::error::{Error, Result};
use std::fs;
use std::path::Path;
use vmm_sys_util::{errno, ioctl};

// The path to the KVM device node for TDX 1.5
const TDX15_DEV_PATH: &str = "/dev/tdx_guest";

// The device operators for tdx v1.5
// Reference: TDX_CMD_GET_REPORT0
// defined in include/uapi/linux/tdx-guest.h in kernel source
// Layout: dir(2bit) size(14bit)         type(8bit) nr(8bit)
//         11        00,0100,0100,0000   b'T'       0000,0001
// The higher 16bit is standed by 0xc440 in big-endian,
// 0x40c4 in little-endian.
const TDX_CMD_GET_REPORT0_V1_5: u64 = u64::from_be_bytes([0, 0, 0, 0, 0xc4, 0x40, b'T', 1]);

/// This struct represents a TDX 1.5 KVM device node and provides an interface
/// for performing operations to retrieve attestation reports.
#[derive(Debug)]
pub struct TdxDeviceKvmV15 {
    /// A `String` representing the path to the device node where the
    /// Quote/Signed Attestation Report can be retrieved.
    device_path: String,
}

impl TdxDeviceKvmV15 {
    /// Creates a new instance of `TdxDeviceKvmV15`, and ensures that the TDX
    /// device node is available before creating the instance.
    pub fn new() -> TdxDeviceKvmV15 {
        match Self::is_available() {
            Ok(true) => TdxDeviceKvmV15 {
                device_path: TDX15_DEV_PATH.to_string(),
            },
            // return an empty device path, if TDX isn't available or there was an error
            _ => TdxDeviceKvmV15 {
                device_path: "".to_string(),
            },
        }
    }

    /// Checks whether the Intel TDX 1.5 KVM device node is available and valid
    /// for use.
    pub fn is_available() -> Result<bool> {
        let path = Path::new(TDX15_DEV_PATH);
        let available = fs::exists(path).map_err(|e| Error::NotSupported(format!("{}", e)))?;

        if available {
            // throw an error if this is a symlink
            if path.is_symlink() {
                return Err(Error::NotSupported(format!(
                    "Path {} is a symlink",
                    path.display()
                )));
            }
        }

        Ok(available)
    }

    /// Retrieves the raw TD report (Quote/Signed Attestation Report) from the
    /// TDX device by using an ioctl system call to interact with the device.
    pub fn get_tdreport_raw(&self, &req: &[u8; 1088]) -> Result<[u8; 1088]> {
        // Before we do anything, check if the device_path is empty.
        // If it is, TDX isn't supported, throw an error
        if self.device_path.is_empty() {
            return Err(Error::NotSupported(
                "TDX 1.5 KVM device is not supported".to_string(),
            ));
        }

        // 1. Get device file descriptor: must open in RW mode
        let tdx_dev = fs::File::options()
            .read(true)
            .write(true)
            .open(&self.device_path)
            .map_err(|e| {
                Error::QuoteError(format!(
                    "Failed to open TDX device at {}: {}",
                    self.device_path, e
                ))
            })?;

        let mut resp = req;

        // 3. Call the ioctl
        let ret =
            unsafe { ioctl::ioctl_with_mut_ptr(&tdx_dev, TDX_CMD_GET_REPORT0_V1_5, &mut resp) };
        if ret < 0 {
            // as seen in virtee/tdx
            let err = errno::Error::last();
            return Err(Error::QuoteError(format!(
                "IOCTL failed with errno {}: {}",
                err.errno(),
                err
            )));
        }
        drop(tdx_dev);

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available() -> Result<()> {
        match TdxDeviceKvmV15::is_available() {
            Ok(true) => {
                let path = Path::new(TDX15_DEV_PATH);
                assert!(fs::exists(path).expect("TDX 1.5 KVM device should be available"));
                Ok(())
            }
            Ok(false) => {
                println!("TDX device is a broken symlink, which is not supported");
                Ok(())
            }
            Err(e) => match e {
                Error::NotSupported(_) => {
                    println!("{}", e);
                    Ok(())
                }
                // Any other error type is unexpected
                _ => Err(e),
            },
        }
    }

    #[test]
    fn test_get_tdreport_raw() -> Result<()> {
        let device = TdxDeviceKvmV15::new();
        let request: [u8; 1088] = [0; 1088];

        match device.get_tdreport_raw(&request) {
            Ok(report) => {
                // Assert that the device didn't just return an empty report
                assert!(report != [0; 1088]);
                Ok(())
            }
            Err(e) => match e {
                Error::NotSupported(_) => {
                    println!("{}", e);
                    Ok(())
                }
                Error::QuoteError(_) => {
                    println!("{}", e);
                    Ok(())
                }
		// Any other error type is unexpected
                _ => Err(e),
            },
        }
    }
}
