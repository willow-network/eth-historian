//! Portal Beacon Network sidecar source — fetches
//! `HistoricalSummariesWithProof` over Portal's Beacon sub-network
//! (protocol id `0x500C`) so post-Capella verification can refresh its
//! `historical_summaries` snapshot from a live source instead of a
//! baked-in constant.
//!
//! Same shape as [`PortalSidecarSource`][crate::sources::PortalSidecarSource]
//! — talks JSON-RPC to a separately-running Portal client (typically
//! `trin`, but Fluffy supports the Beacon network too) — and is
//! likewise treated as a **content router only**. The bytes it returns
//! are SSZ-decoded into a [`HistoricalSummariesWithProof`] in this
//! process; the proof inside that container is what makes the
//! `historical_summaries` BFT-equivalent.
//!
//! Spec: [`portal-network-specs/beacon/beacon-network.md`](https://github.com/ethereum/portal-network-specs/blob/master/beacon/beacon-network.md).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use ssz::{Decode, Encode};
use tracing::debug;

use crate::{
    errors::{Error, Result},
    portal_types::consensus::constants::{SECONDS_PER_SLOT, SLOTS_PER_EPOCH},
    portal_types::consensus::historical_summaries::{
        HistoricalSummaries, HistoricalSummariesWithProof,
    },
};

/// Beacon network selector for `HistoricalSummariesWithProof`. Spec:
/// `portal-network-specs/beacon/beacon-network.md`.
const SELECTOR_HISTORICAL_SUMMARIES_WITH_PROOF: u8 = 0x14;

/// Beacon-chain mainnet genesis (Dec 1, 2020 12:00:23 UTC).
const MAINNET_BEACON_GENESIS_TIMESTAMP: u64 = 1_606_824_023;

#[derive(Debug, Clone)]
pub struct PortalBeaconSidecarSource {
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

impl PortalBeaconSidecarSource {
    /// Construct a Beacon-network source pointed at `rpc_url`.
    /// Typically the same trin instance you use for [`PortalSidecarSource`][crate::sources::PortalSidecarSource]
    /// (trin serves both legacy History and Beacon sub-networks from
    /// the same JSON-RPC endpoint).
    pub fn new(rpc_url: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self {
            rpc_url: rpc_url.into(),
            http,
        })
    }

    /// Fetch the `HistoricalSummariesWithProof` for `epoch` and verify
    /// only the SSZ envelope. The actual `historical_summaries` field
    /// is BFT-equivalent — its proof chains to a sync-committee-signed
    /// `BeaconState`. Note: this method does **not** verify that proof
    /// here; the caller is expected to either (a) trust their Portal
    /// sidecar's content validation, or (b) feed the result through a
    /// separate `BeaconState`-anchor verifier (out of scope for v0.1).
    pub async fn fetch_historical_summaries_with_proof(
        &self,
        epoch: u64,
    ) -> Result<HistoricalSummariesWithProof> {
        let mut content_key = Vec::with_capacity(9);
        content_key.push(SELECTOR_HISTORICAL_SUMMARIES_WITH_PROOF);
        content_key.extend_from_slice(&epoch.as_ssz_bytes());

        let bytes = self.get_content(&content_key).await?;

        HistoricalSummariesWithProof::from_ssz_bytes(&bytes).map_err(|e| {
            Error::SszDecode {
                block: 0, // placeholder; this isn't a block decode
                reason: format!("HistoricalSummariesWithProof at epoch {}: {:?}", epoch, e),
            }
        })
    }

    /// Convenience: fetch the `HistoricalSummaries` for the most-recent
    /// `HistoricalRoot` boundary covered by the chain. Computes the
    /// target epoch from current wall-clock time (mainnet beacon
    /// genesis + 12 s/slot) and asks the sidecar for the latest
    /// rollover.
    pub async fn fetch_latest_historical_summaries(&self) -> Result<HistoricalSummaries> {
        let epoch = current_historical_summaries_epoch();
        let with_proof = self.fetch_historical_summaries_with_proof(epoch).await?;
        Ok(with_proof.historical_summaries)
    }

    async fn get_content(&self, content_key: &[u8]) -> Result<Vec<u8>> {
        let key_hex = format!("0x{}", hex::encode(content_key));
        debug!(target: "eth_historian::portal_beacon", "portal_beaconGetContent({})", key_hex);

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "portal_beaconGetContent",
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
                "Portal beacon RPC error {}: {}",
                err.code, err.message
            )));
        }

        let result = parsed.result.ok_or_else(|| {
            Error::DataSource(format!("Portal beacon returned no result for {}", key_hex))
        })?;

        let bytes = hex::decode(result.content.trim_start_matches("0x"))?;
        Ok(bytes)
    }
}

/// Current beacon-chain epoch, computed from wall-clock time.
fn current_beacon_epoch() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(MAINNET_BEACON_GENESIS_TIMESTAMP);
    let elapsed = now.saturating_sub(MAINNET_BEACON_GENESIS_TIMESTAMP);
    let slot = elapsed / SECONDS_PER_SLOT.as_secs();
    slot / SLOTS_PER_EPOCH
}

/// Epoch of the most recent `historical_summaries` rollover. The
/// Portal Beacon network publishes `HistoricalSummariesWithProof` at
/// each rollover (every 256 epochs ≈ 27 hours).
pub fn current_historical_summaries_epoch() -> u64 {
    // Rollover every SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH = 256 epochs.
    // Round down so the result is the latest *complete* rollover.
    const HISTORICAL_ROOT_BOUNDARY: u64 = 256;
    (current_beacon_epoch() / HISTORICAL_ROOT_BOUNDARY) * HISTORICAL_ROOT_BOUNDARY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_summaries_content_key_format() {
        // Spec: 0x14 || ssz(u64 epoch) — SSZ u64 is little-endian.
        // Reference vector: epoch 450_508_969_718_611_630 (a trin test).
        let epoch: u64 = 450_508_969_718_611_630;
        let mut key = Vec::with_capacity(9);
        key.push(SELECTOR_HISTORICAL_SUMMARIES_WITH_PROOF);
        key.extend_from_slice(&epoch.as_ssz_bytes());
        assert_eq!(key.len(), 9);
        assert_eq!(key[0], 0x14);
        // SSZ u64 == little-endian u64.
        assert_eq!(&key[1..], &epoch.to_le_bytes()[..]);
    }

    #[test]
    fn rollover_epoch_alignment() {
        // The "latest rollover" must be a multiple of 256.
        let e = current_historical_summaries_epoch();
        assert_eq!(
            e % 256,
            0,
            "rollover epoch must align to 256-epoch boundary"
        );
    }
}
