//! # Attestation Signature Utilities
//!
//! This module provides utilities for working with digital signatures
//! used in attestation verification.
//! It currently supports verification of SHA256 signatures that use RSA-PSS
//! padding.
//!
//! ## Example Usage
//!
//! ```rust
//! use signature::verify_signature_sha256_rsa_pss;
//! use x509::{load_x509_der, get_x509_pubkey};
//!
//! // Load signing cert
//! let cert = load_x509_der("/path/to/cert.der")?;
//! let signing_key = verification::x509::get_x509_pubkey(&cert)?;
//!
//! // Verify the digital `signature` on `data` with the `public_key` found in the cert
//! match verify_signature_sha256_rsa_pss(data, &signature, &public_key) {
//!     Ok(true) => println!("Signature is valid."),
//!     Err(e) => eprintln!("Signature verification failed: {}", e),
//! }
//! ```

use crate::error::{Error, Result};

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
#[cfg(feature = "host-gcp-tdx")]
use openssl::rsa::Padding;
#[cfg(feature = "host-gcp-tdx")]
use openssl::sign::RsaPssSaltlen;
use openssl::sign::Verifier;

/// Verifies a SHA256 signature using RSA-PSS padding.
///
/// # Errors
///
/// - `Error::SignatureError` if there are issues with the inputs, verifier
/// setup, or configuration.
/// - `Error::VerificationError` if the signature verification fails.
///
/// # Notes
///
/// This function is only available when the `host-gcp-tdx` feature is enabled
/// because Google Cloud Platform uses a SHA256 with RSA PSS padding signature
/// scheme, so this is needed to verify GCP-signed data.
#[cfg(feature = "host-gcp-tdx")]
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
    let mut verifier = Verifier::new(MessageDigest::sha256(), public_key)
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
    verifier.update(data).map_err(|e| {
        Error::SignatureError(format!("Failed to update verifier with data: {}", e))
    })?;

    // Verify signature
    verifier
        .verify(signature)
        .map_err(|e| Error::VerificationError(format!("Signature verification failed: {}", e)))
}
