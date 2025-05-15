//! # Attestation X.509 Certificate Utilities
//!
//! This module provides utilities for working with X.509 certificates
//! used in attestation verification.
//! It includes functions for extracting public keys, parsing certificates
//! from DER-encoded bytes, loading certificates from files, and verifying
//! certificate signatures.
//!
//! ## Example Usage
//!
//! ```rust
//! use x509::{load_x509_der, get_x509_pubkey, verify_x509_cert};
//!
//! // Load DER formatted certificate from file
//! let cert = load_x509_der("path/to/certificate.der").expect("Failed to load certificate");
//!
//! // Extract public key from loaded cert
//! let pubkey = get_x509_pubkey(&cert).expect("Failed to extract public key");
//! println!("Public Key: {:?}", pubkey);
//!
//! // Verify cert's issuer
//! let issuer_cert = load_x509_der("path/to/isser_certificate.der").expect("Failed to load issuer certificate");
//! match verify_x509_cert(&cert, &issuer_cert) {
//!     Ok(true) => println!("Certificate is valid."),
//!     Err(e) => eprintln!("Certificate verification failed: {}", e),
//! }
//! ```

use crate::error::{Error, Result};
use openssl::pkey::{PKey, Public};
use openssl::x509::{X509, X509VerifyResult};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Extracts the public key from an X.509 certificate.
///
/// # Returns
///
/// A an OpenSSL `PKey<Public>` object representing the public key.
///
/// # Errors
///
/// Returns an `Error::SignatureError` if the public key cannot be extracted.
pub fn get_x509_pubkey(cert: &X509) -> Result<PKey<Public>> {
    cert.public_key()
        .map_err(|e| Error::SignatureError(e.to_string()))
}

/// Parses an X.509 certificate from DER-encoded bytes.
///
/// # Returns
///
/// An OpenSSL `X509` object representing the parsed certificate.
///
/// # Errors
///
/// Returns an `Error::ParseError` if the certificate cannot be parsed.
pub fn x509_from_der_bytes(der_bytes: &[u8]) -> Result<X509> {
    X509::from_der(&der_bytes).map_err(|e| Error::ParseError(e.to_string()))
}

/// Loads an X.509 certificate from a file in DER format.
///
/// # Returns
///
/// An OpenSSL `X509` object representing the parsed certificate.
///
/// # Errors
///
/// - `Error::NotSupported` if the file is a symbolic link.
/// - `Error::IoError` if the file cannot be read.
/// - `Error::ParseError` if the certificate cannot be parsed.
pub fn load_x509_der(cert_path: &str) -> Result<X509> {
    let path = Path::new(cert_path);

    // throw an error if the cert is a symlink
    if path.exists() && path.is_symlink() {
        return Err(Error::NotSupported(format!(
            "Path {} is a symlink",
            path.display()
        )));
    }

    let mut cert_file = File::open(path)?;
    let mut cert_bytes = Vec::new();
    cert_file.read_to_end(&mut cert_bytes)?;

    x509_from_der_bytes(&cert_bytes)
}

/// Verifies an X.509 certificate's signature.
///
/// This function performs two checks to verify the validity of the certificate:
/// 1. It checks whether the provided `issuer_cert` is the issuer of the `cert`.
/// 2. It verifies the signature of the `cert` using the public key from the
/// `issuer_cert`.
///
/// # Errors
///
/// - `Error::VerificationError` if the issuer verification fails.
/// - `Error::SignatureError` if the signature verification fails.
pub fn verify_x509_cert(cert: &X509, issuer_cert: &X509) -> Result<bool> {
    // First, check the issuer
    match issuer_cert.issued(&cert) {
        X509VerifyResult::OK => {} // valid issuer so pass through
        _ => {
            return Err(Error::VerificationError(
                "Cert issuer verification failed".to_string(),
            ));
        }
    };

    // Then, check the signature
    let issuer_pkey = get_x509_pubkey(&issuer_cert)?;

    cert.verify(&issuer_pkey)
        .map_err(|e| Error::VerificationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKeyRef, Private, Public};
    use openssl::rsa::Rsa;

    struct TestCerts {
        root: X509,
        interm: X509,
    }

    fn make_cert(pubkey: &PKeyRef<Public>, sign_key: &PKeyRef<Private>) -> X509 {
        let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
        x509_name.append_entry_by_text("C", "US").unwrap();
        x509_name.append_entry_by_text("ST", "CA").unwrap();
        x509_name
            .append_entry_by_text("O", "Some organization")
            .unwrap();
        x509_name
            .append_entry_by_text("CN", "www.example.com")
            .unwrap();
        let x509_name = x509_name.build();

        let now = Asn1Time::days_from_now(0).unwrap();
        let end = Asn1Time::days_from_now(5).unwrap();

        let mut cert = openssl::x509::X509::builder().unwrap();
        cert.set_subject_name(&x509_name).unwrap();
        cert.set_issuer_name(&x509_name).unwrap();
        cert.set_not_before(&now).unwrap();
        cert.set_not_after(&end).unwrap();

        cert.set_pubkey(pubkey).unwrap();
        cert.sign(sign_key, MessageDigest::sha256()).unwrap();

        cert.build()
    }

    fn setup() -> TestCerts {
        let rsa = Rsa::generate(4096).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let privkey_der = &pkey.private_key_to_der().unwrap();
        let privkey = &PKey::private_key_from_der(&privkey_der).unwrap();
        let pubkey_der = &pkey.public_key_to_der().unwrap();
        let pubkey = &PKey::public_key_from_der(&pubkey_der).unwrap();

        let rsa2 = Rsa::generate(4096).unwrap();
        let pkey2 = PKey::from_rsa(rsa2).unwrap();
        let pubkey_der2 = &pkey2.public_key_to_der().unwrap();
        let pubkey2 = &PKey::public_key_from_der(&pubkey_der2).unwrap();

        TestCerts {
            root: make_cert(&pubkey, &privkey),
            interm: make_cert(&pubkey2, &privkey),
        }
    }

    #[test]
    fn test_x509_from_der_bytes() -> Result<()> {
        let test_certs = setup();
        match test_certs.root.to_der() {
            Ok(der_bytes) => {
                // this will return an error if it fails
                match x509_from_der_bytes(&der_bytes) {
                    Ok(_c) => Ok(()),
                    // Any error type is unexpected
                    Err(e) => Err(e),
                }
            }
            _ => Err(Error::SerializationError(
                "something went wrong serializing the test cert".to_string(),
            )),
        }
    }

    #[test]
    fn test_verify_x509_cert() -> Result<()> {
        let test_certs = setup();
        assert!(
            verify_x509_cert(&test_certs.interm, &test_certs.root)
                .expect("certificate signature should be valid")
        );
        Ok(())
    }
}
