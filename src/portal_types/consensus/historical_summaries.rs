//! `BeaconState.historical_summaries` — the live (post-Capella) field
//! that authenticates Capella+ execution blocks.
//!
//! Source: trin `30aeef8`, `crates/ethportal-api/src/types/consensus/historical_summaries.rs`.

use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};
use tree_hash_derive::TreeHash;

use super::constants::{CAPELLA_FORK_EPOCH, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT};

/// Generalized index of the `historical_summaries` field in
/// `BeaconState` (Electra layout).
pub const HISTORICAL_SUMMARIES_GINDEX: usize = 91;

/// Matches the layout of the phase-0 `HistoricalBatch` so the two are
/// `hash_tree_root`-compatible. Introduced in Capella.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Decode, Encode, TreeHash)]
pub struct HistoricalSummary {
    pub block_summary_root: B256,
    pub state_summary_root: B256,
}

pub type HistoricalSummaries = VariableList<HistoricalSummary, typenum::U16777216>;

pub type HistoricalSummariesProof = FixedVector<B256, typenum::U6>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct HistoricalSummariesWithProof {
    pub epoch: u64,
    pub historical_summaries: HistoricalSummaries,
    pub proof: HistoricalSummariesProof,
}

/// Index of the `HistoricalSummary` covering `slot`. `None` for slots
/// before Capella.
pub fn historical_summary_index(slot: u64) -> Option<usize> {
    let capella_slot = CAPELLA_FORK_EPOCH * SLOTS_PER_EPOCH;
    if slot < capella_slot {
        None
    } else {
        Some(((slot - capella_slot) / SLOTS_PER_HISTORICAL_ROOT) as usize)
    }
}
