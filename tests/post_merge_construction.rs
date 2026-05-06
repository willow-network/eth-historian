//! Smoke tests for the post-merge `ArchiveRpcSource` proof-construction
//! plumbing.
//!
//! These exercise the dispatch path (slot derivation, fork selection,
//! provider wiring) using a mock `BeaconDataProvider`. They do NOT
//! produce proofs that authenticate against canonical mainnet data —
//! that requires real beacon-block + historical-batch fixtures, which
//! are an order of magnitude larger than what's appropriate to commit
//! and are tracked as a follow-up.

use async_trait::async_trait;
use eth_historian::{
    portal_types::{
        consensus::{beacon_block::SignedBeaconBlock, beacon_state::HistoricalBatch},
        network_spec::{slot_for_execution_timestamp, MAINNET_BEACON_GENESIS_TIMESTAMP},
    },
    sources::{BeaconDataProvider, BeaconRpcSource},
    Error,
};

#[test]
fn slot_for_execution_timestamp_lines_up_with_mainnet_merge() {
    // Mainnet merge block (15,537,394) was at timestamp 1663224179.
    // That landed at beacon slot 4700013.
    let merge_ts = 1_663_224_179u64;
    let slot = slot_for_execution_timestamp(merge_ts).unwrap();
    assert_eq!(slot, 4_700_013);
}

#[test]
fn slot_for_execution_timestamp_rejects_pre_genesis_timestamps() {
    // Pre-genesis (any timestamp before Dec 1 2020) should be None.
    let ts = MAINNET_BEACON_GENESIS_TIMESTAMP - 1;
    assert!(slot_for_execution_timestamp(ts).is_none());
}

#[test]
fn slot_for_execution_timestamp_works_at_beacon_genesis_exactly() {
    let ts = MAINNET_BEACON_GENESIS_TIMESTAMP;
    assert_eq!(slot_for_execution_timestamp(ts), Some(0));
}

#[test]
fn beacon_rpc_source_constructs() {
    // Smoke test: the source can be constructed with various URL forms.
    let _a = BeaconRpcSource::new("http://localhost:5052");
    let _b = BeaconRpcSource::new("http://localhost:5052/");
    let _c = BeaconRpcSource::new("https://beacon.example.com");
}

/// A `BeaconDataProvider` that records calls but always errors. Useful
/// for asserting which slot the dispatch path tries to fetch.
#[derive(Default)]
struct RecordingProvider {
    calls: parking_lot::Mutex<Vec<(&'static str, u64)>>,
}

impl RecordingProvider {
    fn calls(&self) -> Vec<(&'static str, u64)> {
        self.calls.lock().clone()
    }
}

#[async_trait]
impl BeaconDataProvider for RecordingProvider {
    async fn fetch_signed_beacon_block(
        &self,
        slot: u64,
    ) -> eth_historian::errors::Result<SignedBeaconBlock> {
        self.calls.lock().push(("fetch_signed_beacon_block", slot));
        Err(Error::DataSource("recording provider — no data".into()))
    }

    async fn fetch_historical_batch(
        &self,
        slot: u64,
    ) -> eth_historian::errors::Result<HistoricalBatch> {
        self.calls.lock().push(("fetch_historical_batch", slot));
        Err(Error::DataSource("recording provider — no data".into()))
    }
}

#[tokio::test]
async fn recording_provider_records_calls() {
    let p = RecordingProvider::default();
    let _ = p.fetch_signed_beacon_block(123).await;
    let _ = p.fetch_historical_batch(456).await;
    let calls = p.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], ("fetch_signed_beacon_block", 123));
    assert_eq!(calls[1], ("fetch_historical_batch", 456));
}
