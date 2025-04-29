use crate::error::{Error, Result};
use crate::verification::utils;

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
#[cfg(feature = "host-gcp-tdx")]
use openssl::rsa::Padding;
#[cfg(feature = "host-gcp-tdx")]
use openssl::sign::RsaPssSaltlen;
use openssl::sign::Verifier;
use openssl::x509::{X509VerifyResult, X509};

#[cfg(feature = "host-gcp-tdx")]
// GCP uses a SHA256 with RSA PSS padding signature scheme, so this is needed to
// Verify GCP-signed data
pub fn verify_signature_sha256_rsa_pss(
    data: &[u8],
    signature: &[u8],
    public_key: &PKey<Public>,
) -> Result<bool> {
    // Validate inputs
    if data.is_empty() {
        return Err(Error::SignatureError(
            "Empty data provided for verification".to_string(),
        ));
    }
    if signature.is_empty() {
        return Err(Error::SignatureError(
            "Empty signature provided for verification".to_string(),
        ));
    }

    // Create verifier with error handling
    let mut verifier =
        Verifier::new(MessageDigest::sha256(), public_key)
            .map_err(|e| Error::SignatureError(format!("Failed to create verifier: {}", e)))?;

    // Set RSA-PSS parameters with error handling
    verifier
        .set_rsa_padding(Padding::PKCS1_PSS)
        .map_err(|e| Error::SignatureError(format!("Failed to set RSA padding: {}", e)))?;
    verifier
        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
        .map_err(|e| Error::SignatureError(format!("Failed to set PSS salt length: {}", e)))?;
    verifier
        .set_rsa_mgf1_md(MessageDigest::sha256())
        .map_err(|e| Error::SignatureError(format!("Failed to set MGF1 hash: {}", e)))?;

    // Update with data
    verifier
        .update(data)
        .map_err(|e| Error::SignatureError(format!("Failed to update verifier with data: {}", e)))?;

    // Verify signature
    verifier
        .verify(signature)
        .map_err(|e| Error::VerificationError(format!("Signature verification failed: {}", e)))
}

pub fn verify_x509_cert(cert: &X509, issuer_cert: &X509) -> Result<bool> {
    // First, check the issuer
    match issuer_cert.issued(&cert) {
        X509VerifyResult::OK => {} // valid issuer so pass through
        _ => {
            return Err(Error::VerificationError(
                "Cert issuer verification failed".to_string(),
            ))
        }
    };

    // Then, check the signature
    let issuer_pkey = utils::get_x509_pubkey(&issuer_cert)?;

    cert.verify(&issuer_pkey)
        .map_err(|e| Error::SignatureError(e.to_string()))
}
