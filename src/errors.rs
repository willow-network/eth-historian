//! Errors surfaced by [`crate::Verifier`] and the data sources.
//!
//! Single error type intentionally — easier to consume from FFI bindings
//! than a deeply structured error hierarchy.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("no data source configured on Verifier; call `.data_source(..)` on the builder")]
    NoDataSource,

    #[error("data source returned no header for block {0}")]
    BlockNotFound(u64),

    #[error("data source error: {0}")]
    DataSource(String),

    #[error("failed to SSZ-decode HeaderWithProof for block {block}: {reason}")]
    SszDecode { block: u64, reason: String },

    #[error("Portal proof verification failed for block {block}: {reason}")]
    VerificationFailed { block: u64, reason: String },

    #[error("Portal returned a header for block {actual} but {expected} was requested")]
    BlockNumberMismatch { expected: u64, actual: u64 },

    #[error("HTTP request failed: {0}")]
    Http(String),

    #[error("JSON parse error: {0}")]
    Json(String),

    #[error("hex decode error: {0}")]
    Hex(String),

    #[error("post-Capella verification requires a `HistoricalSummaries` snapshot; call `Verifier::with_historical_summaries(..)` or use a data source that supplies one")]
    HistoricalSummariesUnavailable,

    #[error("proof-construction error: {0}")]
    ProofConstruction(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::DataSource(e.to_string())
    }
}

#[cfg(feature = "archive-rpc")]
impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e.to_string())
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::Hex(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
