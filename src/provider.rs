use crate::error::Result;

pub trait AttestationProvider {
    fn get_attestation_report(&self) -> Result<String>;
    // TODO: Make the return value less dependent on TDX
    fn get_launch_measurement(&self) -> Result<[u8; 48]>;
}
