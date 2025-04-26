use crate::host::TeeHost;
use crate::gcp::endorsement;
use crate::tdx::TDX_MR_REG_LEN;
use crate::error::{Error, Result};
use crate::verification;

use protobuf::Message;

use std::fs;
use std::process::Command;

pub struct GcpTdxHost {
    mrtd: [u8; TDX_MR_REG_LEN],
}

impl GcpTdxHost {
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
            .expect("failed to retrieve GCP launch endorsement");

        let endorsement = endorsement::VMLaunchEndorsement::parse_from_bytes(&output.stdout)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        Ok(endorsement)
    }

    fn verify_launch_endorsement_signing_cert(
        golden: &endorsement::VMGoldenMeasurement,
    ) -> Result<bool> {
        let gcp_root_cert = verification::utils::load_x509_der("GCE-cc-tcb-root_1.crt")?;
        let signing_cert = verification::utils::x509_from_der_bytes(&golden.cert)?;

        verification::verify_x509_cert(&signing_cert, &gcp_root_cert)
    }

    fn verify_launch_endorsement_sig(
        endorsement: &endorsement::VMLaunchEndorsement,
        signing_cert: Vec<u8>,
    ) -> Result<bool> {
        let cert_x509 = verification::utils::x509_from_der_bytes(&signing_cert)?;

        let signing_key = verification::utils::get_x509_pubkey(&cert_x509)?;

        verification::verify_signature_sha256_rsa_pss(
            &endorsement.serialized_uefi_golden,
            &endorsement.signature,
            &signing_key,
        )
    }
}

impl TeeHost for GcpTdxHost {
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
