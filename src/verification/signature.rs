//! # Attestation Signature Utilities
//!
//! This module provides utilities for working with digital signatures
//! used in attestation verification.
//! It currently supports verification of SHA256 signatures that use RSA-PSS
//! padding.
//!
//! ## Example Usage
//!
//! ```compile_fail
//! use tdx_workload_attestation::verification::signature::verify_signature_sha256_rsa_pss;
//! use tdx_workload_attestation::verification::x509::{load_x509_der, get_x509_pubkey};
//!
//! // Load signing cert
//! let cert = load_x509_der("/path/to/cert.der")?;
//! let signing_key = get_x509_pubkey(&cert)?;
//!
//! // Get data and signature
//!
//! // Verify the digital `signature` on `data` with the `signing_key` found in the cert
//! match verify_signature_sha256_rsa_pss(&data, &signature, &signing_key) {
//!     Ok(true) => println!("Signature is valid."),
//!     Ok(false) => println!("Signature is not valid."),
//!     Err(e) => println!("Signature verification failed: {e}"),
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
///   setup, or configuration.
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

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::pkey::Private;
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;

    struct TestKeys {
        privkey: PKey<Private>,
        pubkey: PKey<Public>,
    }

    fn setup() -> TestKeys {
        let rsa = Rsa::generate(4096).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let privkey_der = &pkey.private_key_to_der().unwrap();
        let privkey = &PKey::private_key_from_der(privkey_der).unwrap();
        let pubkey_der = &pkey.public_key_to_der().unwrap();
        let pubkey = &PKey::public_key_from_der(pubkey_der).unwrap();

        TestKeys {
            privkey: privkey.clone(),
            pubkey: pubkey.clone(),
        }
    }

    #[test]
    fn test_verify_signature_sh256_rsa_pss() -> Result<()> {
        let test_keys = setup();
        let data = b"hello, world";

        // Create the signer with all the parameters
        let mut signer = Signer::new(MessageDigest::sha256(), &test_keys.privkey)
            .map_err(|e| Error::SignatureError(format!("Failed to create signer: {}", e)))?;

        // Set RSA-PSS parameters with error handling
        signer
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|e| Error::SignatureError(format!("Failed to set RSA padding: {}", e)))?;
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| Error::SignatureError(format!("Failed to set PSS salt length: {}", e)))?;
        signer
            .set_rsa_mgf1_md(MessageDigest::sha256())
            .map_err(|e| Error::SignatureError(format!("Failed to set MGF1 hash: {}", e)))?;

        signer.update(data).map_err(|e| {
            Error::SignatureError(format!("Failed to feed data into the signer: {}", e))
        })?;

        let signature = signer
            .sign_to_vec()
            .map_err(|e| Error::SignatureError(format!("Failed to sign data: {}", e)))?;

        assert!(
            verify_signature_sha256_rsa_pss(data, &signature, &test_keys.pubkey)
                .expect("signature should be valid")
        );
        Ok(())
    }

    #[test]
    fn test_verify_signature_sh256_rsa_pss_fail() -> Result<()> {
        let test_keys = setup();
        let data = b"hello, world";

        // Create the signer with all the parameters
        let mut signer = Signer::new(MessageDigest::sha256(), &test_keys.privkey)
            .map_err(|e| Error::SignatureError(format!("Failed to create signer: {}", e)))?;

        // Set RSA-PSS parameters with error handling
        signer
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(|e| Error::SignatureError(format!("Failed to set RSA padding: {}", e)))?;
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| Error::SignatureError(format!("Failed to set PSS salt length: {}", e)))?;
        signer
            .set_rsa_mgf1_md(MessageDigest::sha256())
            .map_err(|e| Error::SignatureError(format!("Failed to set MGF1 hash: {}", e)))?;

        signer.update(data).map_err(|e| {
            Error::SignatureError(format!("Failed to feed data into the signer: {}", e))
        })?;

        let signature = signer
            .sign_to_vec()
            .map_err(|e| Error::SignatureError(format!("Failed to sign data: {}", e)))?;

        let data2 = b"hola, mundo";

        assert!(
            !verify_signature_sha256_rsa_pss(data2, &signature, &test_keys.pubkey)
                .expect("signature should be invalid")
        );
        Ok(())
    }
}
