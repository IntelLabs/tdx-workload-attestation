//! # Google Cloud Platform (GCP) Host Interface for Intel TDX Guests
//!
//! This module uses the `TeeHost` trait to implements an interface for Intel
//! TDX VM _guests_ to verify the TDX attestations against expected values
//! endorsed by GCP hosts.
//!
//! This module assumes that the `gcp:endorsement` module, which is created at
//! build time from Google-provided protobufs, exists.
//!
//! ## Example Usage
//!
//! ```rust
//! use gcp::GcpTdxHost;
//! use host::TeeHost;
//!
//! // Example host interface setup with dummy TDX MRTD value
//! let mrtd = [0u8; 48];
//! let host = GcpTdxHost::new(&mrtd);
//!
//! // Verify a TDX guest's MRTD against the GCP host's launch endorsement
//! match host.verify_launch_endorsement() {
//!     Ok(true) => println!("Launch endorsement is valid."),
//!     Ok(false) => println!("Launch endorsement is invalid."),
//!     Err(e) => eprintln!("Error verifying launch endorsement: {}", e),
//! }
//! ```

mod endorsement;

use crate::error::{Error, Result};
use crate::host::TeeHost;
use crate::tdx::TDX_MR_REG_LEN;
use crate::verification;

use protobuf::Message;
use std::fs;
use std::process::Command;

const GCE_TCB_ROOT_CERT_PATH: &str = "target/gcp/GCE-cc-tcb-root_1.crt";

/// Represents a GCP TDX host.
///
/// The `mrtd` field holds the MRTD (Measurement Register TD) obtained
/// from an Intel TDX guest environment.
pub struct GcpTdxHost {
    mrtd: [u8; TDX_MR_REG_LEN],
}

impl GcpTdxHost {
    /// Creates a new `GcpTdxHost` instance with the given guest MRTD.
    pub fn new(mrtd_bytes: &[u8; TDX_MR_REG_LEN]) -> GcpTdxHost {
        GcpTdxHost {
            mrtd: mrtd_bytes.clone(),
        }
    }

    fn retrieve_launch_endorsement(&self) -> Result<endorsement::VMLaunchEndorsement> {
        // Make sure the GCP CLI is installed
        let gcloud_cli_path = fs::canonicalize("/usr/bin/gcloud")?;

        // Insert the MRTD as hex-encoded string into the URL to retrieve the endorsement
        let storage_url = format!(
            "gs://gce_tcb_integrity/ovmf_x64_csm/tdx/{}.binarypb",
            hex::encode(self.mrtd)
        );

        let output = Command::new(gcloud_cli_path)
            .arg("storage")
            .arg("cat")
            .arg(storage_url)
            .output()
            .map_err(|e| Error::IoError(e))?;

        if !output.status.success() {
            return Err(Error::VerificationError(format!(
                "failed to retrieve GCP launch endorsement for TD verification: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let endorsement = endorsement::VMLaunchEndorsement::parse_from_bytes(&output.stdout)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

        Ok(endorsement)
    }

    fn verify_launch_endorsement_signing_cert(
        golden: &endorsement::VMGoldenMeasurement,
    ) -> Result<bool> {
        let gcp_root_cert = verification::x509::load_x509_der(GCE_TCB_ROOT_CERT_PATH)?;
        let signing_cert = verification::x509::x509_from_der_bytes(&golden.cert)?;

        verification::x509::verify_x509_cert(&signing_cert, &gcp_root_cert)
    }

    fn verify_launch_endorsement_sig(
        endorsement: &endorsement::VMLaunchEndorsement,
        signing_cert: Vec<u8>,
    ) -> Result<bool> {
        let cert_x509 = verification::x509::x509_from_der_bytes(&signing_cert)?;

        let signing_key = verification::x509::get_x509_pubkey(&cert_x509)?;

        verification::signature::verify_signature_sha256_rsa_pss(
            &endorsement.serialized_uefi_golden,
            &endorsement.signature,
            &signing_key,
        )
    }
}

impl TeeHost for GcpTdxHost {
    /// Verifies the GCP launch endorsement for the current TDX guest.
    ///
    /// This method performs the following steps:
    /// 1. Retrieves the TDX guest's launch endorsement from GCP storage.
    /// 2. Verifies the signing certificate of the endorsement against Google's
    /// root cert.
    /// 3. Verifies the signature on the endorsement.
    /// 4. Compares the endorsed MRTD with the guest's MRTD.
    ///
    /// # Errors
    ///
    /// - `Error::IoError` if the endorsement cannot be retrieved.
    /// - `Error::ParseError` if the endorsement or golden measurement cannot be
    /// parsed.
    /// - `Error::SignatureError` if the certificate or signature verification
    /// fails.
    ///
    /// # Note
    ///
    /// This method calls an internal function that uses the GCP CLI (`gcloud`)
    /// to fetch the launch endorsement from GCP storage, and assumes is being
    /// run from within an Intel TDX guest environment on GCP (needed for
    /// authentication).
    fn verify_launch_endorsement(&self) -> Result<bool> {
        // get the launch endorsement
        let launch_endorsement = self.retrieve_launch_endorsement()?;

        // The MRTD is the GCP endorsement is within the UEFI golden measurement
        let uefi_golden = endorsement::VMGoldenMeasurement::parse_from_bytes(
            &launch_endorsement.serialized_uefi_golden,
        )
        .map_err(|e| Error::ParseError(e.to_string()))?;

        // Check signature on the endorsement
        let valid_cert = GcpTdxHost::verify_launch_endorsement_signing_cert(&uefi_golden)?;

        if !valid_cert {
            return Err(Error::SignatureError(
                "Invalid launch endorsement signing cert".to_string(),
            ));
        }

        let valid_sig =
            GcpTdxHost::verify_launch_endorsement_sig(&launch_endorsement, uefi_golden.cert)?;

        if !valid_sig {
            return Err(Error::SignatureError(
                "Invalid launch endorsement signature".to_string(),
            ));
        }

        // The endorsed MRTD will be within the golden value's TDX measurements structs
        let endorsed_mrtd = uefi_golden.tdx.measurements[0].mrtd.as_slice();

        // Finally, we compare the two MRTD values
        Ok(endorsed_mrtd == self.mrtd)
    }
}
