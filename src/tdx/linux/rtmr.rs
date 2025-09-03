// Rust implementation of https://github.com/torvalds/linux/blob/e6b9dce0aeeb91dfc0974ab87f02454e24566182/arch/x86/virt/vmx/tdx/tdxcall.S
// Follows Intel TDX Module v1.5 Base Architecture Specification (September 2021)

use x86_64::addr::{PhysAddr, VirtAddr};
use x86_64::structures::paging::page::Page::SIZE;

pub fn gva_to_gpa(gva: u64) -> u64 {
    let virt_addr = VirtAddr::new(gva).align_down(SIZE);

    virt_addr.as_u64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tdx_guest::tdcall::extend_rtmr;
    use crate::tdx::linux::device::TdxDeviceKvmV15;
    use crate::error::{Error, Result};

    #[test]
    fn test_rtmr_extend() -> Result<()> {
        match TdxDeviceKvmV15::is_available() {
            Ok(true) => {
		let mut test_data: Vec<u8> = Vec::new();
		test_data.push(0x01);
		let data_ptr = test_data.as_ptr() as u64;
		eprintln!("Virtual addr {data_ptr} to RTMR");
		let data_gpa = gva_to_gpa(data_ptr);
		eprintln!("Virtual addr {data_gpa} to RTMR");
		match extend_rtmr(data_gpa, 2) {
		    Ok(()) => (),
		    Err(_e) => return Err(Error::RtmrExtendError("An error occurred".to_string())),
		};
		Ok(())
            }
	    _ => {
                Err(Error::NotSupported("TDX device is not available, which is expected on non-TDX hosts".to_string()))
	    }
	}
    }
}
