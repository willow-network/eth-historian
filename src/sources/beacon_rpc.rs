//! Beacon-node RPC source — fetches the consensus-layer data that
//! [`crate::sources::archive_rpc::ArchiveRpcSource`] needs to construct
//! post-merge proofs locally.
//!
//! For each post-merge execution block, the proof construction code
//! requires:
//!
//! 1. The `SignedBeaconBlock` at the slot containing the execution
//!    payload (~MB-scale).
//! 2. The `HistoricalBatch` (or just `block_roots`) for the era
//!    containing that slot — i.e. the era's full set of beacon-block
//!    roots.
//!
//! Item (2) is cheap to extract from a beacon `BeaconState` fetched at
//! the era's last slot, but the full state is heavy (hundreds of MB).
//! A real-world deployment will want to cache; for v0.1 of this source
//! we just refetch every time.
//!
//! This source requires an **archive** beacon node — i.e. one that
//! retains historical states. Most public beacon-API endpoints don't,
//! so operators typically run their own.

use async_trait::async_trait;

use crate::errors::{Error, Result};
use crate::portal_types::consensus::{
    beacon_block::SignedBeaconBlock, beacon_state::HistoricalBatch, fork::ForkName,
};

/// Provides beacon-chain inputs needed to construct historical post-merge
/// proofs. Concrete impls might talk to a beacon archive RPC, an Era file,
/// a pre-computed cache, or a hybrid.
#[async_trait]
pub trait BeaconDataProvider: Send + Sync {
    /// Fetch the `SignedBeaconBlock` at `slot`. Errors if the slot is
    /// empty (no proposer that slot) or the source can't reach it.
    async fn fetch_signed_beacon_block(&self, slot: u64) -> Result<SignedBeaconBlock>;

    /// Fetch the `HistoricalBatch` (block_roots + state_roots) covering
    /// the era that contains `slot`. The batch's `block_roots[i]` is
    /// the beacon-block root at slot `era_start + i` where
    /// `era_start = (slot / SLOTS_PER_HISTORICAL_ROOT) * SLOTS_PER_HISTORICAL_ROOT`.
    async fn fetch_historical_batch(&self, slot: u64) -> Result<HistoricalBatch>;

    fn name(&self) -> &'static str {
        "BeaconDataProvider"
    }
}

/// Beacon-API HTTP client. Talks the standard Ethereum beacon-API
/// endpoints (`/eth/v2/beacon/blocks/{slot}`,
/// `/eth/v2/debug/beacon/states/{state_id}`).
///
/// **Operator note:** the `debug/beacon/states/{state_id}` endpoint must
/// be enabled (it's gated behind a `--http-allow-origin` /
/// `--debug-endpoints` flag on most clients) AND the node must be in
/// archive mode for historical-era queries. Lighthouse's
/// `--reconstruct-historic-states`, Nimbus's `--history=archive`, and
/// Lodestar's archive build all qualify.
pub struct BeaconRpcSource {
    base_url: String,
    client: reqwest::Client,
}

impl BeaconRpcSource {
    /// Construct from a beacon-API base URL (e.g. `http://localhost:5052`).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Override the HTTP client (e.g. with custom timeouts / headers).
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    async fn fetch_block_ssz(&self, slot: u64) -> Result<Vec<u8>> {
        let url = format!("{}/eth/v2/beacon/blocks/{}", self.base_url, slot);
        let res = self
            .client
            .get(&url)
            .header("accept", "application/octet-stream")
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        if !res.status().is_success() {
            return Err(Error::DataSource(format!(
                "beacon block at slot {slot}: HTTP {}",
                res.status()
            )));
        }
        res.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| Error::Http(e.to_string()))
    }

    async fn fetch_state_ssz(&self, state_id: u64) -> Result<Vec<u8>> {
        let url = format!("{}/eth/v2/debug/beacon/states/{}", self.base_url, state_id);
        let res = self
            .client
            .get(&url)
            .header("accept", "application/octet-stream")
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        if !res.status().is_success() {
            return Err(Error::DataSource(format!(
                "beacon state at slot {state_id}: HTTP {}",
                res.status()
            )));
        }
        res.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| Error::Http(e.to_string()))
    }
}

/// Pick the consensus fork active at `slot` on mainnet.
///
/// Bellatrix → Capella → Deneb → Electra. Boundaries hard-coded
/// from the spec; mainnet is the only network supported in v0.1.
pub fn fork_for_slot(slot: u64) -> ForkName {
    use crate::portal_types::consensus::constants::{
        CAPELLA_FORK_EPOCH, DENEB_FORK_EPOCH, ELECTRA_FORK_EPOCH, SLOTS_PER_EPOCH,
    };
    let epoch = slot / SLOTS_PER_EPOCH;
    if epoch >= ELECTRA_FORK_EPOCH {
        ForkName::Electra
    } else if epoch >= DENEB_FORK_EPOCH {
        ForkName::Deneb
    } else if epoch >= CAPELLA_FORK_EPOCH {
        ForkName::Capella
    } else {
        ForkName::Bellatrix
    }
}

#[async_trait]
impl BeaconDataProvider for BeaconRpcSource {
    async fn fetch_signed_beacon_block(&self, slot: u64) -> Result<SignedBeaconBlock> {
        let bytes = self.fetch_block_ssz(slot).await?;
        let fork = fork_for_slot(slot);
        SignedBeaconBlock::from_ssz_bytes(&bytes, fork).map_err(|e| {
            Error::DataSource(format!(
                "decoding SignedBeaconBlock at slot {slot} (fork={fork:?}): {e:?}"
            ))
        })
    }

    async fn fetch_historical_batch(&self, slot: u64) -> Result<HistoricalBatch> {
        use crate::portal_types::consensus::{
            beacon_state::BeaconState, constants::SLOTS_PER_HISTORICAL_ROOT,
        };

        // The HistoricalBatch for the era containing `slot` lives in the
        // BeaconState at the era's last slot, where state.block_roots and
        // state.state_roots are circular-buffer-aligned with the era.
        let era_start = (slot / SLOTS_PER_HISTORICAL_ROOT) * SLOTS_PER_HISTORICAL_ROOT;
        let era_end = era_start + SLOTS_PER_HISTORICAL_ROOT - 1;

        let bytes = self.fetch_state_ssz(era_end).await?;
        let state_fork = fork_for_slot(era_end);
        let state = BeaconState::from_ssz_bytes(&bytes, state_fork).map_err(|e| {
            Error::DataSource(format!(
                "decoding BeaconState at slot {era_end} (fork={state_fork:?}): {e:?}"
            ))
        })?;

        Ok(HistoricalBatch {
            block_roots: state.block_roots().clone(),
            state_roots: state.state_roots().clone(),
        })
    }

    fn name(&self) -> &'static str {
        "BeaconRpcSource"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal_types::consensus::constants::SLOTS_PER_EPOCH;

    #[test]
    fn fork_dispatch_lines_up_with_mainnet_boundaries() {
        // Just before Capella (Bellatrix domain).
        assert_eq!(fork_for_slot(0), ForkName::Bellatrix);
        // Capella fork epoch ≈ 194048 → slot 6209536. Just before:
        assert_eq!(fork_for_slot(6_209_535), ForkName::Bellatrix);
        // First Capella slot:
        assert_eq!(fork_for_slot(6_209_536), ForkName::Capella);
        // First Deneb slot (epoch 269568):
        assert_eq!(fork_for_slot(269_568 * SLOTS_PER_EPOCH), ForkName::Deneb);
        // First Electra slot (epoch 364032):
        assert_eq!(fork_for_slot(364_032 * SLOTS_PER_EPOCH), ForkName::Electra);
    }
}
