//! Pre-merge `EpochAccumulator` — the per-epoch SSZ list of
//! (block_hash, total_difficulty) records that hashes to one entry of
//! the canonized `HistoricalHashesAccumulator`.
//!
//! Source: trin `30aeef8`, `crates/ethportal-api/src/types/execution/accumulator.rs`.

use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use tree_hash_derive::TreeHash;

/// 8,192 [`HeaderRecord`]s per pre-merge epoch.
pub type EpochAccumulator = VariableList<HeaderRecord, typenum::U8192>;

/// Per-block record committed by an `EpochAccumulator`. 64 bytes wire
/// size (32 hash + 32 difficulty).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Decode, Encode, Deserialize, Serialize, TreeHash)]
pub struct HeaderRecord {
    pub block_hash: tree_hash::Hash256,
    pub total_difficulty: U256,
}
