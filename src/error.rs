use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
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
}

pub type Result<T> = std::result::Result<T, Error>;
