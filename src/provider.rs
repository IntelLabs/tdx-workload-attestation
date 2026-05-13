//! # Trusted Execution Environment (TEE) Attestation Interface
//!
//! This module provides the `AttestationProvider` trait, which VM-based TEE
//! guests can use to interact with the TEE platform within the guest
//! environment.
//!
//! The trait provides functions for retrieving TEE attestation reports and
//! launch-time measurements.

use crate::error::{Error, Result};

pub trait AttestationProvider {
    /// Retrieves an attestation report for the current TEE environment.
    fn get_attestation_report(&self) -> Result<String>;

    /// Retrieves an attestation report with caller-supplied data bound into
    /// the TEE's `REPORTDATA` field (or platform-equivalent).
    ///
    /// `REPORTDATA` is a TEE-defined field that is signed alongside the rest
    /// of the report, allowing a verifier to confirm that the report was
    /// generated in response to a specific challenge (typically a nonce or a
    /// hash of a transcript). The exact length and padding rules are
    /// platform-specific; implementations should document and enforce them.
    ///
    /// The default implementation returns [`Error::NotSupported`]. Providers
    /// that can bind data into a report should override this method.
    fn get_attestation_report_with_data(&self, _report_data: &[u8]) -> Result<String> {
        Err(Error::NotSupported(
            "REPORTDATA binding is not supported by this provider".to_string(),
        ))
    }

    // TODO: Make the return value less dependent on TDX
    fn get_launch_measurement(&self) -> Result<[u8; 48]>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal provider that exercises the default trait methods. It only
    /// implements the required methods, so `get_attestation_report_with_data`
    /// should fall through to the trait's default and return `NotSupported`.
    struct DefaultsProvider;

    impl AttestationProvider for DefaultsProvider {
        fn get_attestation_report(&self) -> Result<String> {
            Ok("{}".to_string())
        }

        fn get_launch_measurement(&self) -> Result<[u8; 48]> {
            Ok([0; 48])
        }
    }

    #[test]
    fn default_get_attestation_report_with_data_returns_not_supported() {
        let provider = DefaultsProvider;
        let err = provider
            .get_attestation_report_with_data(&[0xDE, 0xAD, 0xBE, 0xEF])
            .expect_err("default impl must surface NotSupported");

        match err {
            Error::NotSupported(_) => {}
            other => panic!("expected NotSupported, got {other:?}"),
        }
    }
}
