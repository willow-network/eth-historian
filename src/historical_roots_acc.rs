//! Frozen `BeaconState.historical_roots` snapshot at the Capella fork
//! boundary — used to verify post-merge / pre-Capella execution headers.
//!
//! The raw SSZ blob lives in `assets/historical_roots.ssz`.
//!
//! Source: trin commit `30aeef8`, `crates/validation/src/historical_roots_acc.rs`.

use ethportal_api::consensus::beacon_state::HistoricalRoots;
use ssz::{Decode, Encode};
use tree_hash::{Hash256, PackedEncoding, TreeHash, TreeHashType};

use crate::EmbeddedAssets;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricalRootsAccumulator {
    pub historical_roots: HistoricalRoots,
}

impl HistoricalRootsAccumulator {
    fn new() -> Self {
        let raw_bytes = EmbeddedAssets::get("validation_assets/historical_roots.ssz")
            .expect("embedded historical_roots.ssz missing — build broken");
        let historical_roots = HistoricalRoots::from_ssz_bytes(raw_bytes.data.as_ref())
            .expect("embedded historical_roots.ssz failed SSZ decode — vendored asset corrupted");

        Self { historical_roots }
    }
}

impl Default for HistoricalRootsAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for HistoricalRootsAccumulator {
    fn is_ssz_fixed_len() -> bool {
        <HistoricalRoots as Decode>::is_ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let historical_roots = HistoricalRoots::from_ssz_bytes(bytes)?;
        Ok(Self { historical_roots })
    }
}

impl Encode for HistoricalRootsAccumulator {
    fn is_ssz_fixed_len() -> bool {
        <HistoricalRoots as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.historical_roots.ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        self.historical_roots.ssz_bytes_len()
    }
}

impl TreeHash for HistoricalRootsAccumulator {
    fn tree_hash_type() -> TreeHashType {
        <HistoricalRoots as TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        <HistoricalRoots as TreeHash>::tree_hash_packed_encoding(&self.historical_roots)
    }

    fn tree_hash_packing_factor() -> usize {
        <HistoricalRoots as TreeHash>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Hash256 {
        self.historical_roots.tree_hash_root()
    }
}
