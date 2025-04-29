mod device;

use crate::error::Result;
use crate::tdx::TDX_REPORT_DATA_LEN;
use crate::tdx::report::TdReportV15;

pub fn is_v15_kvm_device() -> Result<bool> {
    let is_device = device::TdxDeviceKvmV15::is_available()?;

    Ok(is_device)
}

pub fn get_tdreport_v15_kvm(report_data: &[u8; TDX_REPORT_DATA_LEN]) -> TdReportV15 {
    // Initialize the KVM device for TDX 1.5
    let tdx_device = device::TdxDeviceKvmV15::new();

    // Create the request
    let req = TdReportV15::create_request(report_data);

    // Get the TDREPORT from the hardware device
    let raw_report = tdx_device.get_tdreport_raw(&req).unwrap();

    // Extract the report from the raw report
    TdReportV15::get_tdreport_from_bytes(&raw_report)
}
