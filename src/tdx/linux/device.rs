// Provides APIs for sending commands to the TDX 1.5 KVM device node
// Rust implementation of https://github.com/canonical/tdx/blob/2cd1a182323bad17d80a2f491c63679ac6b73e7f/tests/lib/tdx-tools/src/tdxtools/utility.py

use crate::error::{Error, Result};
use std::fs;
use std::path::Path;
use vmm_sys_util::{errno, ioctl};

// The path to the KVM device node for TDX 1.5
const TDX15_DEV_PATH: &str = "/dev/tdx_guest";

// The device operators for tdx v1.5
// Reference: TDX_CMD_GET_REPORT0
// defined in include/uapi/linux/tdx-guest.h in kernel source
// Layout: dir(2bit) size(14bit)         type(8bit) nr(8bit)
//         11        00,0100,0100,0000   b'T'       0000,0001
// The higher 16bit is standed by 0xc440 in big-endian,
// 0x40c4 in little-endian.
const TDX_CMD_GET_REPORT0_V1_5: u64 = u64::from_be_bytes([0, 0, 0, 0, 0xc4, 0x40, b'T', 1]);

#[derive(Debug)]
pub struct TdxDeviceKvmV15 {
    // Path to the device node where we can retrieve the Quote/Signed Attestation Report.
    device_path: String,
}

impl TdxDeviceKvmV15 {
    pub fn new() -> TdxDeviceKvmV15 {
        assert!(Self::is_available().expect("Intel TDX KVM device node supported"));

        TdxDeviceKvmV15 {
            device_path: TDX15_DEV_PATH.to_string(),
        }
    }

    pub fn is_available() -> Result<bool> {
        let path = Path::new(TDX15_DEV_PATH);
        let available = fs::exists(path).map_err(|e| Error::NotSupported(format!("{}", e)))?;

        if available {
            // throw an error if this is a symlink
            if path.is_symlink() {
                return Err(Error::NotSupported(format!(
                    "Path {} is a symlink",
                    path.display()
                )));
            }
        }

        Ok(available)
    }

    pub fn get_tdreport_raw(&self, &req: &[u8; 1088]) -> Result<[u8; 1088]> {
        assert!(TdxDeviceKvmV15::is_available().expect("Intel TDX KVM device node supported"));

        // 1. Get device file descriptor: must open in RW mode
        let tdx_dev = fs::File::options()
            .read(true)
            .write(true)
            .open(&self.device_path)
            .map_err(|e| {
                Error::QuoteError(format!(
                    "Failed to open TDX device at {}: {}",
                    self.device_path, e
                ))
            })?;

        println!("Found TDX device: {:?}", tdx_dev);

        let mut resp = req;

        // 3. Call the ioctl
        let ret =
            unsafe { ioctl::ioctl_with_mut_ptr(&tdx_dev, TDX_CMD_GET_REPORT0_V1_5, &mut resp) };
        if ret < 0 {
            // as seen in virtee/tdx
            let err = errno::Error::last();
            return Err(Error::QuoteError(format!(
                "IOCTL failed with errno {}: {}",
                err.errno(),
                err
            )));
        }
        drop(tdx_dev);

        Ok(resp)
    }
}
