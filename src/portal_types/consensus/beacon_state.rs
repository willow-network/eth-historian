//! `BeaconState`-derived type aliases.
//!
//! Only the fields the historical-block verifier actually consumes.
//! Source: trin `30aeef8`, `crates/ethportal-api/src/types/consensus/beacon_state.rs`.

use ssz_types::{typenum, VariableList};
use tree_hash::Hash256;

/// `BeaconState.historical_roots` — the SSZ list of historical-batch
/// roots that was frozen at the Capella fork. Used to verify
/// post-merge / pre-Capella execution-block proofs.
pub type HistoricalRoots = VariableList<Hash256, typenum::U16777216>;
