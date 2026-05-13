//! # Intel TDX Guest Attestation Interface
//!
//! This module provides a library for interacting with Intel TDX (Trust Domain
//! Extensions) platforms within an enlightened VM guest.
//! It includes functionality for retrieving TDX attestation reports and launch
//! measurements using the`AttestationProvider` trait.
//!
//! This module currently supports interactions with TDX on Linux VM guests.
//!
//! ## Example Usage
//!
//! ```no_run
//! use tdx_workload_attestation::tdx::LinuxTdxProvider;
//! use tdx_workload_attestation::provider::AttestationProvider;
//!
//! let provider = LinuxTdxProvider::new();
//!
//! // Get the attestation report
//! let report = provider.get_attestation_report().expect("Failed to get attestation report");
//! println!("Attestation Report: {}", report);
//!
//! // Get the launch measurement
//! let measurement = provider.get_launch_measurement().expect("Failed to get launch measurement");
//! println!("Launch Measurement: {:?}", measurement);
//! ```

use crate::error::{Error, Result};
use crate::provider::AttestationProvider;

pub mod linux;
pub mod report;

use report::TdReportV15;

/// The length of the `report_data` field in the TDX report.
pub const TDX_REPORT_DATA_LEN: usize = 64_usize;

/// The length of the TDX measurement registers.
pub const TDX_MR_REG_LEN: usize = 48_usize;

/// An interface for retrieving attestation reports and launchmeasurements with
/// TDX on Linux VM guests.
///
/// This struct implements the `AttestationProvider` trait.
pub struct LinuxTdxProvider;

impl Default for LinuxTdxProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxTdxProvider {
    /// Creates a new instance of `LinuxTdxProvider`.
    pub fn new() -> Self {
        Self
    }

    /// Retrieves the `TDREPORT` for the current environment with empty
    /// `REPORTDATA`.
    ///
    /// This method internally calls the Linux-specific implementation to fetch
    /// the TD report using the KVM (Kernel-based Virtual Machine) device.
    ///
    /// # Returns
    ///
    /// A `TdReportV15` struct containing the TD report data.
    fn get_tdreport(&self) -> Result<TdReportV15> {
        self.get_tdreport_with_data(&[])
    }

    /// Retrieves the `TDREPORT` for the current environment, binding the
    /// caller-supplied `report_data` into the TDX `REPORTDATA` field.
    ///
    /// `report_data` may be up to [`TDX_REPORT_DATA_LEN`] (64) bytes. Shorter
    /// inputs are zero-padded on the right to fill the field. Pass an empty
    /// slice to request a report with an all-zero `REPORTDATA`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotSupported`] if `report_data` is longer than
    /// [`TDX_REPORT_DATA_LEN`] bytes.
    fn get_tdreport_with_data(&self, report_data: &[u8]) -> Result<TdReportV15> {
        if report_data.len() > TDX_REPORT_DATA_LEN {
            return Err(Error::NotSupported(format!(
                "report_data length {} exceeds maximum of {} bytes",
                report_data.len(),
                TDX_REPORT_DATA_LEN
            )));
        }

        let mut buf = [0u8; TDX_REPORT_DATA_LEN];
        buf[..report_data.len()].copy_from_slice(report_data);

        linux::get_tdreport_v15_kvm(&buf)
    }
}

impl AttestationProvider for LinuxTdxProvider {
    /// Retrieves the attestation report for a TDX Linux guest environment.
    ///
    /// This method fetches the TD report and serializes it into a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an `Error:SerializationError` if the TD report cannot be
    /// serialized into JSON.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tdx_workload_attestation::tdx::LinuxTdxProvider;
    /// use tdx_workload_attestation::provider::AttestationProvider;
    ///
    /// let provider = LinuxTdxProvider::new();
    /// let report = provider.get_attestation_report().expect("Failed to get attestation report");
    /// println!("Attestation Report: {}", report);
    /// ```
    fn get_attestation_report(&self) -> Result<String> {
        let report = self.get_tdreport()?;

        // Serialize it to a JSON string.
        let report_str =
            serde_json::to_string(&report).map_err(|e| Error::SerializationError(e.to_string()))?;

        Ok(report_str)
    }

    /// Retrieves the attestation report for a TDX Linux guest environment,
    /// binding `report_data` into the TDX `REPORTDATA` field.
    ///
    /// `report_data` may be up to [`TDX_REPORT_DATA_LEN`] (64) bytes; shorter
    /// inputs are zero-padded on the right.
    ///
    /// # Errors
    ///
    /// - [`Error::NotSupported`] if `report_data` exceeds 64 bytes.
    /// - [`Error::SerializationError`] if the TD report cannot be serialized
    ///   into JSON.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tdx_workload_attestation::tdx::LinuxTdxProvider;
    /// use tdx_workload_attestation::provider::AttestationProvider;
    ///
    /// let provider = LinuxTdxProvider::new();
    /// // Bind a 32-byte challenge (e.g. SHA-256 of a transcript) into REPORTDATA.
    /// let nonce = [0xAB; 32];
    /// let report = provider
    ///     .get_attestation_report_with_data(&nonce)
    ///     .expect("Failed to get attestation report");
    /// println!("Attestation Report: {}", report);
    /// ```
    fn get_attestation_report_with_data(&self, report_data: &[u8]) -> Result<String> {
        let report = self.get_tdreport_with_data(report_data)?;

        let report_str =
            serde_json::to_string(&report).map_err(|e| Error::SerializationError(e.to_string()))?;

        Ok(report_str)
    }

    /// Retrieves the launch measurement for a TDX Linux guest environment.
    ///
    /// This method fetches the `TDREPORT` and extracts the `MRTD` field, which
    /// represents the static measurement of the Trust Domain at launch time.
    ///
    /// # Returns
    ///
    /// A 48-byte array containing the launch measurement.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tdx_workload_attestation::tdx::LinuxTdxProvider;
    /// use tdx_workload_attestation::provider::AttestationProvider;
    ///
    /// let provider = LinuxTdxProvider::new();
    /// let measurement = provider.get_launch_measurement().expect("Failed to get launch measurement");
    /// println!("Launch Measurement: {:?}", measurement);
    /// ```
    fn get_launch_measurement(&self) -> Result<[u8; 48]> {
        let report = self.get_tdreport()?;
        Ok(report.get_mrtd())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tdx::test_utils::handle_expected_tdx_error;

    #[test]
    fn test_get_attestation_report() -> Result<()> {
        let provider = LinuxTdxProvider::new();
        match provider.get_attestation_report() {
            Ok(report) => {
                // Verify it returned a non-empty string
                assert!(!report.is_empty());

                // Verify report is valid JSON
                let _: serde_json::Value = serde_json::from_str(&report)
                    .map_err(|e| Error::SerializationError(e.to_string()))?;
                Ok(())
            }
            Err(e) => handle_expected_tdx_error(e),
        }
    }

    #[test]
    fn test_get_launch_measurement() -> Result<()> {
        let provider = LinuxTdxProvider::new();
        match provider.get_launch_measurement() {
            Ok(mrtd) => {
                // Verify it returned a non-empty buffer
                assert!(!mrtd.is_empty());
                Ok(())
            }
            Err(e) => handle_expected_tdx_error(e),
        }
    }

    #[test]
    fn test_get_attestation_report_with_data_rejects_oversized_input() {
        let provider = LinuxTdxProvider::new();
        let oversized = [0u8; TDX_REPORT_DATA_LEN + 1];

        // Length validation runs before the device call, so this branch
        // returns a deterministic error even on non-TDX hosts.
        let err = provider
            .get_attestation_report_with_data(&oversized)
            .expect_err("expected length validation to reject 65-byte input");

        match err {
            Error::NotSupported(msg) => {
                assert!(
                    msg.contains("exceeds maximum"),
                    "unexpected NotSupported message: {msg}"
                );
            }
            other => panic!("expected NotSupported, got {other:?}"),
        }
    }

    #[test]
    fn test_get_attestation_report_with_data_accepts_short_input() -> Result<()> {
        let provider = LinuxTdxProvider::new();
        // A 32-byte challenge (e.g. SHA-256 digest); the impl should
        // zero-pad up to TDX_REPORT_DATA_LEN before issuing the request.
        let nonce = [0xAB_u8; 32];

        match provider.get_attestation_report_with_data(&nonce) {
            Ok(report) => {
                assert!(!report.is_empty());
                let _: serde_json::Value = serde_json::from_str(&report)
                    .map_err(|e| Error::SerializationError(e.to_string()))?;
                Ok(())
            }
            Err(e) => handle_expected_tdx_error(e),
        }
    }

    #[test]
    fn test_get_attestation_report_with_data_accepts_full_length_input() -> Result<()> {
        let provider = LinuxTdxProvider::new();
        let full = [0x5A_u8; TDX_REPORT_DATA_LEN];

        match provider.get_attestation_report_with_data(&full) {
            Ok(report) => {
                assert!(!report.is_empty());
                Ok(())
            }
            Err(e) => handle_expected_tdx_error(e),
        }
    }

    #[test]
    fn test_get_attestation_report_with_data_accepts_empty_input() -> Result<()> {
        let provider = LinuxTdxProvider::new();

        // Empty input should behave equivalently to the no-arg method:
        // an all-zero REPORTDATA buffer is forwarded to the device.
        match provider.get_attestation_report_with_data(&[]) {
            Ok(report) => {
                assert!(!report.is_empty());
                Ok(())
            }
            Err(e) => handle_expected_tdx_error(e),
        }
    }
}
/// Test utilities for TDX-related tests.
///
/// This module provides helper functions for testing TDX functionality in
/// environments without actual TDX hardware support. These utilities help ensure
/// that tests can run successfully both on TDX-enabled and non-TDX hosts.
#[cfg(test)]
pub(crate) mod test_utils {
    use crate::error::{Error, Result};

    pub fn handle_expected_tdx_error(e: Error) -> Result<()> {
        match e {
            // These errors are expected on non-TDX hosts
            Error::NotSupported(_) | Error::QuoteError(_) => {
                println!("Test skipped on non-TDX host: {}", e);
                Ok(()) // Return OK to pass the test
            }
            // Any other error should cause the test to fail!
            _ => Err(e),
        }
    }
}
