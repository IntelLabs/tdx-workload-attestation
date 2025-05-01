pub mod error;
#[cfg(feature = "host-gcp-tdx")]
pub mod gcp;
#[cfg(feature = "host-gcp-tdx")]
pub mod host;
pub mod provider;
#[cfg(feature = "tdx-linux")]
pub mod tdx;
#[cfg(feature = "host-verification")]
pub mod verification;

use error::Result;
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
