//! Portal Network type definitions vendored from `ethportal-api`.
//!
//! Vendored from [`trin`](https://github.com/ethereum/trin) commit `30aeef8`,
//! `crates/ethportal-api/src/types/`. We carry our own copy because:
//!
//! 1. The published `ethportal-api 0.12.0` crate has a build-script
//!    bug (vergen `~9.0` pin needed; trin is no longer maintained so
//!    no fix is coming).
//! 2. Its transitive dep tree (`jsonrpsee`, `c-kzg`, `discv5`,
//!    `secp256k1`, `validator`, `rs_merkle`, ~30 others) is hostile
//!    to wasm32 builds and bloats compile time for downstream
//!    consumers who only need the verifier types.
//!
//! Only the subset of types this crate actually uses is vendored.
//! Bigger-picture proof-construction helpers (`build_historical_roots_proof`,
//! `build_capella_historical_summaries_proof`, etc.) and beacon-block
//! types are intentionally omitted; they re-enter scope via
//! [issue #2](https://github.com/willow-network/eth-historian/issues/2).
//!
//! Source attribution preserved in each module. Apache-2.0 / MIT.

pub mod byte_list;
pub mod consensus;
pub mod execution;
pub mod network_spec;

pub use consensus::beacon_state::HistoricalRoots;
pub use consensus::constants::{
    CAPELLA_FORK_EPOCH, DENEB_FORK_EPOCH, ELECTRA_FORK_EPOCH, SECONDS_PER_SLOT, SLOTS_PER_EPOCH,
    SLOTS_PER_HISTORICAL_ROOT,
};
pub use consensus::historical_summaries::{
    historical_summary_index, HistoricalSummaries, HistoricalSummariesProof,
    HistoricalSummariesWithProof, HistoricalSummary, HISTORICAL_SUMMARIES_GINDEX,
};
pub use execution::accumulator::{EpochAccumulator, HeaderRecord};
pub use execution::header_with_proof::{
    BeaconBlockProofHistoricalRoots, BeaconBlockProofHistoricalSummaries, BlockHeaderProof,
    BlockProofHistoricalHashesAccumulator, BlockProofHistoricalRoots,
    BlockProofHistoricalSummariesCapella, BlockProofHistoricalSummariesDeneb,
    ExecutionBlockProofBellatrix, ExecutionBlockProofDeneb, HeaderWithProof,
};
