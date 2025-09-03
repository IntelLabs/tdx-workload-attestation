//! # TDX Workload Attestation Errors
//!
//! This module defines custom error types and a result type alias for the TDX
//! workload attestation library.
//!
//! The `Error` enum provides a comprehensive set of error variants to represent
//! different kinds of errors that can occur in the application, such as I/O errors,
//! parsing errors, serialization errors, and cryptographic verification errors.
//!
//! The `Result` type alias simplifies function signatures by using the custom `Error` type
//! as the error variant in `std::result::Result`.
//!
//! ## Example Usage
//!
//! ```
//! use tdx_workload_attestation::error::{Error, Result};
//!
//! fn example_function() -> Result<()> {
//!     Err(Error::NotSupported("This operation is not supported".to_string()))
//! }
//!
//! match example_function() {
//!     Ok(_) => println!("Operation succeeded"),
//!     Err(e) => eprintln!("Error occurred: {}", e),
//! }
//! ```

use thiserror::Error;

/// Represents the various errors that can occur in the application.
///
/// # Variants
///
/// - `IoError`: Represents an I/O error, wrapping a `std::io::Error`.
/// - `NotSupported`: Represents an operation or feature that is not supported.
/// - `ParseError`: Represents an error that occurs during parsing of serialized data.
/// - `QuoteError`: Represents an error related to quote generation or processing.
/// - `RtmrExtendError`: Represents an error related to RTMR extension.
/// - `AddressError`: Represents an error related to addressing.
/// - `SerializationError`: Represents an error that occurs during data serialization.
/// - `SignatureError`: Represents an error related to cryptographic signature verification.
/// - `VerificationError`: Represents a general verification error.
#[derive(Debug, Error)]
pub enum Error {
    /// Represents an I/O error.
    ///
    /// This variant wraps a `std::io::Error` and provides additional context.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Represents an operation or feature that is not supported.
    ///
    /// This variant includes a string describing the unsupported operation.
    #[error("Not supported: {0}")]
    NotSupported(String),

    /// Represents an error that occurs during parsing of serialized data.
    ///
    /// This variant includes a string describing the parsing error.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Represents an error related to quote generation or processing.
    ///
    /// This variant includes a string describing the quote error.
    #[error("Quote error: {0}")]
    QuoteError(String),

    /// Represents an error related to RTMR extension.
    ///
    /// This variant includes a string describing the RTMR extend error.
    #[error("RTMR extend error: {0}")]
    RtmrExtendError(String),

    /// Represents an error related to addressing.
    ///
    /// This variant includes a string describing the addressing error.
    #[error("Address error: {0}")]
    AddressError(String),

    /// Represents an error that occurs during data serialization.
    ///
    /// This variant includes a string describing the serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Represents an error related to cryptographic signature verification.
    ///
    /// This variant includes a string describing the signature error.
    #[error("Signature error: {0}")]
    SignatureError(String),

    /// Represents a general verification error.
    ///
    /// This variant includes a string describing the verification error.
    #[error("Verification error: {0}")]
    VerificationError(String),
}

/// A type alias for results that use the custom `Error` type.
///
/// This alias simplifies function signatures by using the `Error` enum as the
/// error type in `std::result::Result`.
pub type Result<T> = std::result::Result<T, Error>;
