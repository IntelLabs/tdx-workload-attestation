//! # Attestation Verification Utilities
//!
//! This module implements utilities for performing cryptographic operations
//! needed for Intel TDX-based attestation verification.
//! It currently supports digital signature and X.509 certificate utilities.
//!
//! ## Example Usage
//!
//! ```rust
//! use verification::x509::{load_x509_der, get_x509_pubkey};
//! use verification::signature::verify_signature_sha256_rsa_pss;
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

pub mod signature;
pub mod x509;
