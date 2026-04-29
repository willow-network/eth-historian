//! # eth-historian
//!
//! Trustless cryptographic authentication of historical Ethereum
//! execution-layer blocks for off-chain consumers.
//!
//! Given a block number or hash, [`Verifier`] returns a
//! [`VerifiedBlock`] whose contents are authenticated against:
//!
//! * **pre-merge blocks** — the canonized
//!   [`HistoricalHashesAccumulator`][hh] embedded in this crate
//!   (a constant; trust assumption documented in `ARCHITECTURE.md`).
//! * **post-merge / pre-Capella blocks** — the canonized
//!   [`HistoricalRootsAccumulator`][hr] (also a constant).
//! * **post-Capella blocks** — the live `historical_summaries` field of
//!   beacon `BeaconState`, which chains to a current sync-committee
//!   BLS signature. **BFT-equivalent.**
//!
//! [hh]: https://github.com/ethereum/portal-network-specs/blob/master/legacy/history/history-network.md
//! [hr]: https://github.com/ethereum/portal-network-specs/blob/master/legacy/history/history-network.md
//!
//! ## Quick start
//!
//! ```no_run
//! # #[cfg(feature = "archive-rpc")]
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use eth_historian::{Verifier, sources::ArchiveRpcSource};
//!
//! let verifier = Verifier::builder()
//!     .data_source(ArchiveRpcSource::new("https://eth.llamarpc.com"))
//!     .build();
//!
//! // Uniswap V2 deployment (May 4, 2020), pre-merge.
//! let block = verifier.verify_block_by_number(10_000_835).await?;
//! println!("state_root:        {:?}", block.header.state_root);
//! println!("authenticated via: {:?}", block.auth_path);
//! # Ok(())
//! # }
//! ```
//!
//! See `ARCHITECTURE.md` for the full trust model, supported eras, and
//! data-source semantics.

pub mod accumulator;
pub mod api;
pub mod constants;
pub mod errors;
pub mod header_validator;
pub mod historical_roots_acc;
pub mod historical_summaries_provider;
pub mod merkle;
pub mod proof_construction;
pub mod sources;

pub use api::{AuthPath, VerifiedBlock, Verifier, VerifierBuilder};
pub use errors::Error;
pub use header_validator::HeaderValidator;

// Re-export ethportal-api types we accept on our public API so callers
// don't need a direct dep just to construct/inspect a `HeaderWithProof`.
pub use ethportal_api::types::execution::header_with_proof::{
    BlockHeaderProof, BlockProofHistoricalHashesAccumulator, BlockProofHistoricalRoots,
    BlockProofHistoricalSummariesCapella, BlockProofHistoricalSummariesDeneb, HeaderWithProof,
};

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "src/assets/"]
#[prefix = "validation_assets/"]
pub(crate) struct EmbeddedAssets;

/// Asserts that the embedded canonized accumulator binaries hash to the
/// values published in [`constants`]. Call once at process startup;
/// panics if either has been tampered with.
///
/// This is the integrity guard for the canonized-accumulator trust path:
/// if these constants ever drift from what trin's `crates/validation`
/// canonized at commit `30aeef8`, historical header verification
/// silently breaks. Failing loudly here is the right behavior. Cheap
/// (~few ms) — no reason not to call it.
pub fn assert_canonized_accumulator_fingerprints() {
    use sha2::Digest;
    use tree_hash::TreeHash;

    use crate::{
        accumulator::PreMergeAccumulator,
        constants::{
            DEFAULT_HISTORICAL_ROOTS_HASH, DEFAULT_PRE_MERGE_ACC_HASH, HISTORICAL_ROOTS_SSZ_SHA256,
            MERGE_MACC_BIN_SHA256,
        },
        historical_roots_acc::HistoricalRootsAccumulator,
    };

    let merge_macc_bytes = EmbeddedAssets::get("validation_assets/merge_macc.bin")
        .expect("merge_macc.bin missing from embedded assets");
    let merge_macc_sha = sha2::Sha256::digest(merge_macc_bytes.data.as_ref());
    assert_eq!(
        merge_macc_sha.as_slice(),
        &MERGE_MACC_BIN_SHA256[..],
        "merge_macc.bin SHA-256 mismatch — embedded asset has been altered"
    );

    let historical_roots_bytes = EmbeddedAssets::get("validation_assets/historical_roots.ssz")
        .expect("historical_roots.ssz missing from embedded assets");
    let historical_roots_sha = sha2::Sha256::digest(historical_roots_bytes.data.as_ref());
    assert_eq!(
        historical_roots_sha.as_slice(),
        &HISTORICAL_ROOTS_SSZ_SHA256[..],
        "historical_roots.ssz SHA-256 mismatch — embedded asset has been altered"
    );

    assert_eq!(
        PreMergeAccumulator::default().tree_hash_root(),
        DEFAULT_PRE_MERGE_ACC_HASH,
        "PreMergeAccumulator tree-hash root mismatch — vendored binary inconsistent with trin's canonized hash"
    );
    assert_eq!(
        HistoricalRootsAccumulator::default().tree_hash_root(),
        DEFAULT_HISTORICAL_ROOTS_HASH,
        "HistoricalRootsAccumulator tree-hash root mismatch — vendored binary inconsistent with trin's canonized hash"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_match_canonized_constants() {
        assert_canonized_accumulator_fingerprints();
    }
}
