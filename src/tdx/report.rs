// Rust implementation of https://github.com/canonical/tdx/blob/2cd1a182323bad17d80a2f491c63679ac6b73e7f/tests/lib/tdx-tools/src/tdxtools/tdreport.py

//! # Intel TDX `TDREPORT` Structures
//!
//! This module provides data structures and utilities for working with TDX
//! attestation reports, specifically the `TDREPORT` and its associated
//! sub-fields. These structures are used to parse and manipulate the raw
//! attestation data retrieved from a TDX device.
//!
//! The module currently only supports the TDX 1.5 report format.
//!
//! ## Overview
//!
//! The `TDREPORT` is a 1024-byte structure that contains various fields
//! containing information about the TDX guest (i.e., the Trust Domain, or TD)
//! as well as the CPU.
//! Specifically, the `TDREPORT` consists of the `ReportMacStruct`,
//! `TeeTcbInfo`, and `TdInfo`.
//!
//! # Notes
//! - The module is currently designed to work specifically with Intel TDX 1.5 devices.
//! - The `TDREPORT` structure and its substructures are based on the TDX 1.5 specification.

use crate::error::{Error, Result};
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

/// A trait that defines a method for populating a structure from raw bytes.
/// All TDX attestation-related data structures should implement this trait.
trait BinaryBlob {
    /// Populates the structure from a slice of raw bytes.
    fn from_bytes(&mut self, raw_bytes: &[u8]) -> Result<()>;
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
    fn from_bytes(&mut self, raw_bytes: &[u8]) -> Result<()> {
        if raw_bytes.len() != REPORT_MAC_STRUCT_LEN {
            return Err(Error::ParseError(
                "ReportMacStruct length is wrong".to_string(),
            ));
        }

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

        Ok(())
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
    fn from_bytes(&mut self, raw_bytes: &[u8]) -> Result<()> {
        if raw_bytes.len() != TEE_TCB_INFO_LEN {
            return Err(Error::ParseError("TeeTcbInfo length is wrong".to_string()));
        }

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

        Ok(())
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
    fn from_bytes(&mut self, raw_bytes: &[u8]) -> Result<()> {
        if raw_bytes.len() != TD_INFO_LEN {
            return Err(Error::ParseError("TdInfo length is wrong".to_string()));
        }

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

        Ok(())
    }
}

/// Represents the full `TDREPORT` structure, which includes the internal
/// `ReportMacStruct`, `TeeTcbInfo`, `TdInfo` structs and reserved fields.
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
    /// Populates the `TdReportV15` structure from a slice of raw bytes.
    fn from_bytes(&mut self, raw_bytes: &[u8]) -> Result<()> {
        if raw_bytes.len() != TDREPORT_LEN {
            return Err(Error::ParseError("TdReport length is wrong".to_string()));
        }

        // copy the bytes into the struct
        let mut offset: usize = 0;
        self.report_mac_struct
            .from_bytes(&raw_bytes[offset..REPORT_MAC_STRUCT_LEN])?;
        offset += REPORT_MAC_STRUCT_LEN;
        self.tee_tcb_info
            .from_bytes(&raw_bytes[offset..offset + TEE_TCB_INFO_LEN])?;
        offset += TEE_TCB_INFO_LEN;
        self.reserved
            .copy_from_slice(&raw_bytes[offset..offset + TDREPORT_RESERVED_LEN]);
        offset += TDREPORT_RESERVED_LEN;
        self.td_info
            .from_bytes(&raw_bytes[offset..offset + TD_INFO_LEN])?;

        Ok(())
    }
}

impl TdReportV15 {
    /// Creates a new `TdReportV15` instance with default values.
    pub fn new() -> TdReportV15 {
        TdReportV15 {
            report_mac_struct: ReportMacStruct::new(),
            tee_tcb_info: TeeTcbInfo::new(),
            reserved: [0; TDREPORT_RESERVED_LEN],
            td_info: TdInfo::new(),
        }
    }

    /// Creates a request for retrieving a TDX report from the CPU.
    pub fn create_request(report_data: &[u8; TDX_REPORT_DATA_LEN]) -> [u8; TDREPORT_REQ_LEN] {
        let mut req: [u8; TDREPORT_REQ_LEN] = [0; TDREPORT_REQ_LEN];
        req[..TDX_REPORT_DATA_LEN].copy_from_slice(report_data);

        //println!("sending report request (len={}): {:?}", raw_req.len(), raw_req);
        req
    }

    /// Creates a new `TdReportV15` instance from raw bytes.
    pub fn get_tdreport_from_bytes(raw_bytes: &[u8; TDREPORT_REQ_LEN]) -> Result<TdReportV15> {
        let mut tdreport = TdReportV15::new();

        let report_bytes = &raw_bytes[TDX_REPORT_DATA_LEN..];
        tdreport.from_bytes(report_bytes)?;

        Ok(tdreport)
    }

    /// Returns the `MRTD` field from the TDX report, which is a 48-byte
    /// SHA-3 hash of the TD memory and configuration.
    pub fn get_mrtd(&self) -> [u8; TDX_MR_REG_LEN] {
        self.td_info.mrtd
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::SliceRandom;

    #[test]
    fn test_create_request() -> Result<()> {
        let report_data: [u8; TDX_REPORT_DATA_LEN] = [1; TDX_REPORT_DATA_LEN];

        let request = TdReportV15::create_request(&report_data);

        assert!(&request[0..TDX_REPORT_DATA_LEN] == [1; TDX_REPORT_DATA_LEN]);

        Ok(())
    }

    #[test]
    fn test_get_tdreport_from_bytes() -> Result<()> {
        let mut rng = rand::rng();
        let mut rand_bytes: Vec<u8> = (0..127).collect();
        rand_bytes.resize(TDREPORT_REQ_LEN, 0);
        rand_bytes.shuffle(&mut rng);

        let rand_req: [u8; TDREPORT_REQ_LEN] = rand_bytes.try_into().unwrap();

        // this should not throw an error
        match TdReportV15::get_tdreport_from_bytes(&rand_req) {
            Ok(_r) => Ok(()),
            Err(e) => Err(e),
        }
    }

    #[test]
    fn test_get_tdreport_from_bytes_wrong_size() -> Result<()> {
        let mut tdreport = TdReportV15::new();

        let mut rng = rand::rng();
        let mut rand_bytes: Vec<u8> = (0..127).collect();
        rand_bytes.shuffle(&mut rng);

        match tdreport.from_bytes(&rand_bytes) {
            Err(e) => match e {
                Error::ParseError(_) => {
                    println!("{}", e);
                    Ok(())
                }
                // any other error is unexpected
                _ => Err(e),
            },
            _ => Err(Error::NotSupported(
                "Wrong buffer size should throw an error".to_string(),
            )),
        }
    }
}
