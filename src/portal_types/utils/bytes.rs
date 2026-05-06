//! `0x`-prefixed hex helpers used by the vendored consensus types.
//!
//! Source: trin `30aeef8`, `crates/ethportal-api/src/utils/bytes.rs`,
//! reduced to the two functions actually used by the vendored types
//! (`hex_encode`, `hex_decode`).

use hex::FromHexError;
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ByteUtilsError {
    #[error("Hex string starts with {first_two}, expected 0x")]
    WrongPrefix { first_two: String },

    #[error("Unable to decode hex string {data} due to {source}")]
    HexDecode { source: FromHexError, data: String },

    #[error("Hex string is '{data}', expected to start with 0x")]
    NoPrefix { data: String },
}

/// Encode `data` as `0x`-prefixed hex.
pub fn hex_encode<T: AsRef<[u8]>>(data: T) -> String {
    format!("0x{}", hex::encode(data))
}

/// Decode a `0x`-prefixed hex string.
pub fn hex_decode(data: &str) -> Result<Vec<u8>, ByteUtilsError> {
    let first_two = data.get(..2).ok_or_else(|| ByteUtilsError::NoPrefix {
        data: data.to_string(),
    })?;

    if first_two.to_lowercase() != "0x" {
        return Err(ByteUtilsError::WrongPrefix {
            first_two: first_two.to_string(),
        });
    }

    let post_prefix = data.get(2..).unwrap_or("");

    hex::decode(post_prefix).map_err(|e| ByteUtilsError::HexDecode {
        source: e,
        data: data.to_string(),
    })
}
