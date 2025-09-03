
// Follows Intel TDX Module v1.5 Base Architecture Specification (September 2021)

use crate::error::{Error, Result};

use pagemap::{PageMap};
use std::process;
use x86_64::addr::VirtAddr;

// Adapted from https://ephemeral.cx/2014/12/translating-virtual-addresses-to-physcial-addresses-in-user-space/
pub fn gva_to_gpa(gva: u64) -> Result<u64> {
    let pid = process::id() as u64;
    let page_size = pagemap::page_size().map_err(|e| Error::AddressError(e.to_string()))?;

    // get the pagemap for this process
    let mut pagemap = PageMap::new(pid).map_err(|e| Error::AddressError(e.to_string()))?;
    let entries = pagemap.maps().map_err(|e| Error::AddressError(e.to_string()))?;

    // aligns to the top of the page
    let aligned_gva = VirtAddr::new(gva).align_down(page_size).as_u64();

    let mut vma = None; 
    for i in 0..entries.len() {
	let mr = entries[i].memory_region();

	if mr.contains(aligned_gva) {
	   vma = Some(mr);
	   break;
	}
     }

     match vma {
     	   None => {
     	   return Err(Error::AddressError("GVA not found in process pagemap".to_string()));
     	   },
	   Some(mr) => {
     	   	    let pages = pagemap.pagemap_region(&mr).map_err(|e| Error::AddressError(e.to_string()))?;

     		    let pagemap_idx = ((aligned_gva - mr.start_address()) / page_size) as usize;

     		    let pfn = pages[pagemap_idx].pfn().map_err(|e| Error::AddressError(e.to_string()))?;

		    eprintln!("PFN = {pfn}");
		    
     		    let gpa = (pfn << 12) + (aligned_gva - mr.start_address());

		    Ok(gpa)
		    },
    }
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
		eprintln!("Virtual addr {data_ptr}");
		let data_gpa = gva_to_gpa(data_ptr)?;
		eprintln!("GPA {data_gpa} passed to RTMR");
		extend_rtmr(data_gpa, 2).map_err(|e| Error::RtmrExtendError("An error occurred".to_string()))?;
		Ok(())
            }
	    _ => {
                Err(Error::NotSupported("TDX device is not available, which is expected on non-TDX hosts".to_string()))
	    }
	}
    }
}
