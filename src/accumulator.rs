//! Pre-merge double-batched-merkle-log accumulator over the entire pre-PoS
//! mainnet header chain (block 0 .. 15,537,393).
//!
//! The actual binary blob lives in `assets/merge_macc.bin` and is embedded
//! at build time. Its tree-hash root is asserted equal to
//! [`crate::constants::DEFAULT_PRE_MERGE_ACC_HASH`] in `lib.rs::canonized_fingerprints_match`.
//!
//! Source: trin commit `30aeef8`, `crates/validation/src/accumulator.rs`.
//! Reduced to verifier-only — `try_from_file` and `construct_proof` are
//! intentionally not vendored (we only verify, not produce, proofs).

use alloy::consensus::Header;
use ethportal_api::consensus::constants::SLOTS_PER_HISTORICAL_ROOT;
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use tree_hash_derive::TreeHash;

use crate::EmbeddedAssets;

/// SSZ List[Hash256, max_length = MAX_HISTORICAL_EPOCHS].
pub type HistoricalEpochRoots = VariableList<tree_hash::Hash256, typenum::U131072>;

/// SSZ Container holding the canonized historical-epoch merkle roots.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Deserialize, Serialize, TreeHash)]
pub struct PreMergeAccumulator {
    pub historical_epochs: HistoricalEpochRoots,
}

impl Default for PreMergeAccumulator {
    fn default() -> Self {
        let raw = EmbeddedAssets::get("validation_assets/merge_macc.bin")
            .expect("embedded merge_macc.bin missing — build broken");
        PreMergeAccumulator::from_ssz_bytes(raw.data.as_ref())
            .expect("embedded merge_macc.bin failed SSZ decode — vendored asset corrupted")
    }
}

impl PreMergeAccumulator {
    pub(crate) fn get_epoch_index_of_header(&self, header: &Header) -> u64 {
        header.number / SLOTS_PER_HISTORICAL_ROOT
    }
}
