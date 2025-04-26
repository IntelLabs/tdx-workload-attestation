// Provides TDX 1.5 TDREPORT structs
// Rust implementation of https://github.com/canonical/tdx/blob/2cd1a182323bad17d80a2f491c63679ac6b73e7f/tests/lib/tdx-tools/src/tdxtools/tdreport.py

use crate::tdx::{TDX_MR_REG_LEN, TDX_REPORT_DATA_LEN};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

// constants for report struct sizes
const REPORT_MAC_STRUCT_LEN: usize = 256 as usize;
const TEE_TCB_INFO_LEN: usize = 239 as usize;
const TDREPORT_RESERVED_LEN: usize = 17 as usize;
const TD_INFO_LEN: usize = 512 as usize;

// The length of the TDREPORT (1024 bytes)
const TDREPORT_LEN: usize =
    REPORT_MAC_STRUCT_LEN + TEE_TCB_INFO_LEN + TDREPORT_RESERVED_LEN + TD_INFO_LEN;

// The length of a TDREPORT request
const TDREPORT_REQ_LEN: usize = TDX_REPORT_DATA_LEN + TDREPORT_LEN;

// All TDX attestation data structures should implement this
trait BinaryBlob {
    fn from_bytes(&mut self, raw_bytes: &[u8]);
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
struct ReportMacStruct {
    //
    //   Struct REPORTMACSTRUCT's layout:
    //   offset, len
    //   0x0,    0x8     report_type
    //   0x8,    0x8     reserverd1
    //   0x10,   0x10    cpusvn
    //   0x20,   0x30    tee_tcb_info_hash
    //   0x50,   0x30    tee_info_hash
    //   0x80,   0x40    report_data
    //   0xc0,   0x20    reserverd2
    //   0xe0,   0x20    mac
    //
    report_type: [u8; 8], // [8 bytes]
    reserved1: [u8; 8],   // [8 bytes]
    cpusvn: [u8; 16],     // [16 bytes]
    #[serde(with = "BigArray")]
    tee_tcb_info_hash: [u8; 48], // [48 bytes]
    #[serde(with = "BigArray")]
    tee_info_hash: [u8; 48], // [48 bytes]
    #[serde(with = "BigArray")]
    report_data: [u8; 64], // [64 bytes]
    reserved2: [u8; 32],  // [32 bytes]
    mac: [u8; 32],        // [32 bytes]
}

impl ReportMacStruct {
    fn new() -> ReportMacStruct {
        ReportMacStruct {
            report_type: [0; 8],
            reserved1: [0; 8],
            cpusvn: [0; 16],
            tee_tcb_info_hash: [0; 48],
            tee_info_hash: [0; 48],
            report_data: [0; 64],
            reserved2: [0; 32],
            mac: [0; 32],
        }
    }
}

impl BinaryBlob for ReportMacStruct {
    fn from_bytes(&mut self, raw_bytes: &[u8]) {
        assert!(raw_bytes.len() == REPORT_MAC_STRUCT_LEN);

        // copy the bytes into the struct
        let mut offset: usize = 0;
        self.report_type.copy_from_slice(&raw_bytes[offset..8]);
        offset += 8;
        self.reserved1
            .copy_from_slice(&raw_bytes[offset..offset + 8]);
        offset += 8;
        self.cpusvn.copy_from_slice(&raw_bytes[offset..offset + 16]);
        offset += 16;
        self.tee_tcb_info_hash
            .copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.tee_info_hash
            .copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.report_data
            .copy_from_slice(&raw_bytes[offset..offset + TDX_REPORT_DATA_LEN]);
        offset += TDX_REPORT_DATA_LEN;
        self.reserved2
            .copy_from_slice(&raw_bytes[offset..offset + 32]);
        offset += 32;
        self.mac.copy_from_slice(&raw_bytes[offset..offset + 32]);
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
struct TeeTcbInfo {
    //
    //   Struct TEE_TCB_INFO's layout:
    //   offset, len
    //   0x0,    0x8     valid
    //   0x8,    0x10    tee_tcb_svn
    //   0x18,   0x30    mrseam
    //   0x48,   0x30    mrsignerseam
    //   0x78,   0x8     attributes (set to all 0s)
    //   0x80,   0x10    tee_tcb_svn2
    //   0x90,   0x5f    reserverd
    //
    valid: [u8; 8],        // [8 bytes]
    tee_tcb_svn: [u8; 16], // [16 bytes]
    #[serde(with = "BigArray")]
    mrseam: [u8; 48], // [48 bytes]
    #[serde(with = "BigArray")]
    mrsignerseam: [u8; 48], // [48 bytes]
    attributes: [u8; 8],   // [8 bytes]
    tee_tcb_svn2: [u8; 16], // [16 bytes]
    #[serde(with = "BigArray")]
    reserved: [u8; 95], // [95 bytes]
}

impl TeeTcbInfo {
    fn new() -> TeeTcbInfo {
        TeeTcbInfo {
            valid: [0; 8],
            tee_tcb_svn: [0; 16],
            mrseam: [0; 48],
            mrsignerseam: [0; 48],
            attributes: [0; 8],
            tee_tcb_svn2: [0; 16],
            reserved: [0; 95],
        }
    }
}

impl BinaryBlob for TeeTcbInfo {
    fn from_bytes(&mut self, raw_bytes: &[u8]) {
        assert!(raw_bytes.len() == TEE_TCB_INFO_LEN);

        // copy the bytes into the struct
        let mut offset: usize = 0;
        self.valid.copy_from_slice(&raw_bytes[offset..8]);
        offset += 8;
        self.tee_tcb_svn
            .copy_from_slice(&raw_bytes[offset..offset + 16]);
        offset += 16;
        self.mrseam.copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.mrsignerseam
            .copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.attributes
            .copy_from_slice(&raw_bytes[offset..offset + 8]);
        offset += 8;
        self.tee_tcb_svn2
            .copy_from_slice(&raw_bytes[offset..offset + 16]);
        offset += 16;
        self.reserved
            .copy_from_slice(&raw_bytes[offset..offset + 95]);
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
struct TdInfo {
    //
    //   Struct TDINFO's layout:
    //   offset, len
    //   0x0,     0x8     attributes
    //   0x8,     0x8     xfam
    //   0x10,    0x30    mrtd
    //   0x40,    0x30    mrconfigid
    //   0x70,    0x30    mrowner
    //   0xa0,    0x30    mrownerconfig
    //   0xd0,    0x30    rtmr0
    //   0x100,   0x30    rtmr1
    //   0x130,   0x30    rtmr2
    //   0x160,   0x30    rtmr3
    //   0x190,   0x30    servtd_hash
    //   0x1c0,   0x40    reserved
    //
    attributes: [u8; 8], // [8 bytes]
    xfam: [u8; 8],       // [8 bytes]
    #[serde(with = "BigArray")]
    mrtd: [u8; 48], // [48 bytes]
    #[serde(with = "BigArray")]
    mrconfigid: [u8; 48], // [48 bytes]
    #[serde(with = "BigArray")]
    mrowner: [u8; 48], // [48 bytes]
    #[serde(with = "BigArray")]
    mrownerconfig: [u8; 48], // [48 bytes]
    #[serde(with = "BigArray")]
    rtmr0: [u8; 48], // [48 bytes]
    #[serde(with = "BigArray")]
    rtmr1: [u8; 48], // [48 bytes]
    #[serde(with = "BigArray")]
    rtmr2: [u8; 48], // [48 bytes]
    #[serde(with = "BigArray")]
    rtmr3: [u8; 48], // [48 bytes]
    #[serde(with = "BigArray")]
    servtd_hash: [u8; 48], // [48 bytes]
    #[serde(with = "BigArray")]
    reserved: [u8; 64], // [64 bytes]
}

impl TdInfo {
    fn new() -> TdInfo {
        TdInfo {
            attributes: [0; 8],
            xfam: [0; 8],
            mrtd: [0; 48],
            mrconfigid: [0; 48],
            mrowner: [0; 48],
            mrownerconfig: [0; 48],
            rtmr0: [0; 48],
            rtmr1: [0; 48],
            rtmr2: [0; 48],
            rtmr3: [0; 48],
            servtd_hash: [0; 48],
            reserved: [0; 64],
        }
    }
}

impl BinaryBlob for TdInfo {
    fn from_bytes(&mut self, raw_bytes: &[u8]) {
        assert!(raw_bytes.len() == TD_INFO_LEN);

        // copy the bytes into the struct
        let mut offset: usize = 0;
        self.attributes.copy_from_slice(&raw_bytes[offset..8]);
        offset += 8;
        self.xfam.copy_from_slice(&raw_bytes[offset..offset + 8]);
        offset += 8;
        self.mrtd.copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.mrconfigid
            .copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.mrowner
            .copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.mrownerconfig
            .copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.rtmr0.copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.rtmr1.copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.rtmr2.copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.rtmr3.copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.servtd_hash
            .copy_from_slice(&raw_bytes[offset..offset + 48]);
        offset += 48;
        self.reserved
            .copy_from_slice(&raw_bytes[offset..offset + 64]);
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct TdReportV15 {
    //
    //   Struct TDREPORT's layout:
    //   offset, len
    //   0x0,     0x100   ReportMacStruct
    //   0x100,   0xef    TeeTcbInfo
    //   0x1ef,   0x11    Reserved
    //   0x200,   0x200   TdInfo
    //
    report_mac_struct: ReportMacStruct,    // [256 bytes]
    tee_tcb_info: TeeTcbInfo,              // [239 bytes]
    reserved: [u8; TDREPORT_RESERVED_LEN], // [17 bytes]
    td_info: TdInfo,                       // [512 bytes]
}

impl BinaryBlob for TdReportV15 {
    fn from_bytes(&mut self, raw_bytes: &[u8]) {
        assert!(raw_bytes.len() == TDREPORT_REQ_LEN);

        let report_bytes = &raw_bytes[TDX_REPORT_DATA_LEN..];
        //println!("Got td report: {:?}", report_bytes);

        // copy the bytes into the struct
        let mut offset: usize = 0;
        self.report_mac_struct
            .from_bytes(&report_bytes[offset..REPORT_MAC_STRUCT_LEN]);
        offset += REPORT_MAC_STRUCT_LEN;
        self.tee_tcb_info
            .from_bytes(&report_bytes[offset..offset + TEE_TCB_INFO_LEN]);
        offset += TEE_TCB_INFO_LEN;
        self.reserved
            .copy_from_slice(&report_bytes[offset..offset + TDREPORT_RESERVED_LEN]);
        offset += TDREPORT_RESERVED_LEN;
        self.td_info
            .from_bytes(&report_bytes[offset..offset + TD_INFO_LEN]);
    }
}

impl TdReportV15 {
    pub fn create_request(report_data: &[u8; TDX_REPORT_DATA_LEN]) -> [u8; TDREPORT_REQ_LEN] {
        let mut req: [u8; TDREPORT_REQ_LEN] = [0; TDREPORT_REQ_LEN];
        for i in 0..TDX_REPORT_DATA_LEN {
            req[i] = report_data[i];
        }

        //println!("sending report request (len={}): {:?}", raw_req.len(), raw_req);
        req
    }

    pub fn get_tdreport_from_bytes(raw_bytes: &[u8; TDREPORT_REQ_LEN]) -> TdReportV15 {
        let mut tdreport = TdReportV15 {
            report_mac_struct: ReportMacStruct::new(),
            tee_tcb_info: TeeTcbInfo::new(),
            reserved: [0; TDREPORT_RESERVED_LEN],
            td_info: TdInfo::new(),
        };
        tdreport.from_bytes(raw_bytes);

        tdreport
    }

    pub fn get_mrtd(&self) -> [u8; TDX_MR_REG_LEN] {
        self.td_info.mrtd
    }
}
