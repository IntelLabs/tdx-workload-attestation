// Rust implementation of https://github.com/torvalds/linux/blob/e6b9dce0aeeb91dfc0974ab87f02454e24566182/arch/x86/virt/vmx/tdx/tdxcall.S
// Follows Intel TDX Module v1.5 Base Architecture Specification (September 2021)

use tdx_guest::tdcall::extend_rtmr;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tdx::linux::device::TdxDeviceKvmV15;
    use crate::error::{Error, Result};

    #[test]
    fn test_rtmr_extend() -> Result<()> {
        match TdxDeviceKvmV15::is_available() {
            Ok(true) => {
		let mut test_data: Vec<u8> = Vec::new();
		test_data.push(0x01);
		match rtmr_extend(&test_data, 3) {
		    Ok() => Ok(()),
		    Err(e) => Err(Error::RtmrExtendError("An error occurred".to_string()))
		}
		Ok(())
            }
	    _ => {
                Err(Error::NotSupported("TDX device is not available, which is expected on non-TDX hosts".to_string()))
	    }
	}
    }
}
