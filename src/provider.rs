//! # Trusted Execution Environment (TEE) Attestation Interface
//!
//! This module provides the `AttestationProvider` trait, which VM-based TEE
//! guests can use to interact with the TEE platform within the guest
//! environment.
//!
//! The trait provides a function for retrieving TEE attestation reports and
//! launch-time measurements.

use crate::error::Result;

pub trait AttestationProvider {
    fn get_attestation_report(&self) -> Result<String>;
    // TODO: Make the return value less dependent on TDX
    fn get_launch_measurement(&self) -> Result<[u8; 48]>;
}
