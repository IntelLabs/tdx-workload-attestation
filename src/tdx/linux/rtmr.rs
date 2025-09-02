// Rust implementation of https://github.com/torvalds/linux/blob/e6b9dce0aeeb91dfc0974ab87f02454e24566182/arch/x86/virt/vmx/tdx/tdxcall.S
// Follows Intel TDX Module v1.5 Base Architecture Specification (September 2021)

use std::arch::asm;

// The TDX 1.5 TDCALL Leaf for TDG.MR.RTMR.EXTEND
const TDX_RTMR_EXTEND_LEAF_V1_5: u64 = 2;

// Extends the TD guest's RTMR at the given index
pub fn rtmr_extend(index: u64, data: &Vec<u8>) -> u64 {
    let ret: u64;
    unsafe {
	asm!(
	    // Move leaf to rax
            "mov rax, ${leaf}",
	    // Move data to rcx
            "mov rcx, {data}",
	    // Move rtmr index to rdx
	    "mov rdx, {index}",
	    // Make the TDCALL
	    ".byte 0x66,0x0f,0x01,0xcc",
	    leaf = const TDX_RTMR_EXTEND_LEAF_V1_5,
	    index = in(reg) index,
	    data = in(reg) data,
	    // return value is 0 on success
	    out("rax") ret,
	);
    }
    ret
}

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
		let ret = rtmr_extend(3, &test_data);
		assert_eq!(ret, 0);
		Ok(())
            }
	    _ => {
                Err(Error::NotSupported("TDX device is not available, which is expected on non-TDX hosts".to_string()))
	    }
	}
    }
}
