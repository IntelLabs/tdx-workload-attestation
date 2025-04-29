use crate::error::{Error, Result};

use crate::provider::AttestationProvider;

pub mod linux;
pub mod report;

use report::TdReportV15;

// The length of the report_data
pub const TDX_REPORT_DATA_LEN: usize = 64 as usize;

// The length of TDX measurement regs
pub const TDX_MR_REG_LEN: usize = 48 as usize;

pub struct LinuxTdxProvider;

impl LinuxTdxProvider {
    pub fn new() -> Self {
        Self
    }

    fn get_tdreport(&self) -> TdReportV15 {
        let report_data = [0; 64]; // keep report data empty for now

        linux::get_tdreport_v15_kvm(&report_data)
    }
}

impl AttestationProvider for LinuxTdxProvider {
    fn get_attestation_report(&self) -> Result<String> {
        let report = self.get_tdreport();

        // Serialize it to a JSON string.
        let report_str =
            serde_json::to_string(&report).map_err(|e| Error::SerializationError(e.to_string()))?;

        Ok(report_str)
    }

    fn get_launch_measurement(&self) -> Result<[u8; 48]> {
        let report = self.get_tdreport();

        Ok(report.get_mrtd())
    }
}
