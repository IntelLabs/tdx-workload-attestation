//! # Host Interface for VM-based Trusted Execution Environment (TEE) Guests
//!
//! This module provides the `TeeHost` trait, which VM hosts can use to
//! expose TEE attestation features to VM guests, such as Intel TDX VMs hosted
//! on public clouds.
//!
//! The trait provides a function for verifying the launch-time TEE measurements
//! against the endorsed values by the host.

use crate::error::Result;

pub trait TeeHost {
    fn verify_launch_endorsement(&self) -> Result<bool>;
}
