use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Not supported: {0}")]
    NotSupported(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Quote error: {0}")]
    QuoteError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("Verification error: {0}")]
    VerificationError(String),
}

pub type Result<T> = std::result::Result<T, Error>;
