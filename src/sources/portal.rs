//! Portal Network sidecar source — talks JSON-RPC to a separately-running
//! Portal client (typically `trin`) that resolves content via the
//! Portal History DHT.
//!
//! The sidecar is treated as a content router only; cryptographic
//! verification of what it returns happens in [`crate::Verifier`]
//! against the canonized accumulators.
//!
//! ## Caveat — trin is unmaintained
//!
//! As of 2026, `trin` is the only Portal client that serves block
//! headers via the Legacy History sub-network (`0x500B`), and its README
//! says "no longer actively maintained." The actively-maintained
//! alternative (Fluffy in `nimbus-eth1`) implements a newer revision
//! of the spec and does **not** serve headers. Pin the trin version
//! you run; expect this source to require operational care.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::debug;

use crate::{
    errors::{Error, Result},
    sources::DataSource,
};

/// History Network content-key selectors per Portal Network legacy
/// history spec (`history-network.md`).
const SELECTOR_BLOCK_HEADER_BY_HASH: u8 = 0x00;
const SELECTOR_BLOCK_HEADER_BY_NUMBER: u8 = 0x03;

#[derive(Debug, Clone)]
pub struct PortalSidecarSource {
    rpc_url: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    result: Option<GetContentResult>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct GetContentResult {
    content: String,
    #[serde(default, rename = "utpTransfer")]
    _utp_transfer: bool,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl PortalSidecarSource {
    /// Construct a Portal sidecar source pointed at `rpc_url` (e.g.
    /// `http://localhost:8545`).
    pub fn new(rpc_url: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            rpc_url: rpc_url.into(),
            http,
        })
    }

    async fn get_content(&self, content_key: &[u8]) -> Result<Vec<u8>> {
        let key_hex = format!("0x{}", hex::encode(content_key));
        debug!(target: "eth_historian::portal", "portal_legacyHistoryGetContent({})", key_hex);

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "portal_legacyHistoryGetContent",
            "params": [key_hex.clone()],
        });

        let response = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        let parsed: JsonRpcResponse = response.json().await?;

        if let Some(err) = parsed.error {
            return Err(Error::DataSource(format!(
                "Portal RPC error {}: {}",
                err.code, err.message
            )));
        }

        let result = parsed.result.ok_or_else(|| {
            Error::DataSource(format!("Portal returned no result for {}", key_hex))
        })?;

        let bytes = hex::decode(result.content.trim_start_matches("0x"))?;
        Ok(bytes)
    }
}

#[async_trait]
impl DataSource for PortalSidecarSource {
    async fn fetch_header_with_proof_by_number(&self, block_number: u64) -> Result<Vec<u8>> {
        let mut key = Vec::with_capacity(9);
        key.push(SELECTOR_BLOCK_HEADER_BY_NUMBER);
        key.extend_from_slice(&block_number.to_le_bytes());
        self.get_content(&key).await
    }

    async fn fetch_header_with_proof_by_hash(&self, block_hash: [u8; 32]) -> Result<Vec<u8>> {
        let mut key = Vec::with_capacity(33);
        key.push(SELECTOR_BLOCK_HEADER_BY_HASH);
        key.extend_from_slice(&block_hash);
        self.get_content(&key).await
    }

    fn name(&self) -> &'static str {
        "portal-sidecar"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_by_number_content_key_format() {
        // Block 12,345,678 = 0xbc614e:
        //   key = [0x03, 0x4e, 0x61, 0xbc, 0x00, 0x00, 0x00, 0x00, 0x00]
        let block: u64 = 12_345_678;
        let mut key = Vec::with_capacity(9);
        key.push(SELECTOR_BLOCK_HEADER_BY_NUMBER);
        key.extend_from_slice(&block.to_le_bytes());
        assert_eq!(
            hex::encode(&key),
            "034e61bc0000000000",
            "BlockHeaderByNumber content key encoding regressed"
        );
    }

    #[test]
    fn header_by_hash_content_key_format() {
        let hash = [0xaa; 32];
        let mut key = Vec::with_capacity(33);
        key.push(SELECTOR_BLOCK_HEADER_BY_HASH);
        key.extend_from_slice(&hash);
        assert_eq!(key.len(), 33);
        assert_eq!(key[0], 0x00);
    }
}
