//! Data sources — pluggable backends that fetch SSZ-encoded
//! `HeaderWithProof` bytes for a given block.
//!
//! The verifier itself doesn't care where the bytes came from; whatever
//! a source returns is verified against the canonized accumulators
//! before being trusted. This means a source can be:
//!
//! * a Portal Network sidecar (the bytes were stored in a P2P DHT)
//! * an Era1 file on local disk
//! * an archive RPC + locally-constructed proof
//! * something custom — just implement [`DataSource`]
//!
//! Multiple sources can be registered on a [`Verifier`][crate::Verifier];
//! they're tried in order until one returns bytes that pass.

use async_trait::async_trait;

use crate::errors::Result;

/// Returns SSZ-encoded `HeaderWithProof` bytes for a requested block.
/// Implementations are queried by [`Verifier`][crate::Verifier], which
/// then SSZ-decodes and verifies what they return.
#[async_trait]
pub trait DataSource: Send + Sync {
    /// Fetch by block number. Most sources support this directly.
    async fn fetch_header_with_proof_by_number(&self, block_number: u64) -> Result<Vec<u8>>;

    /// Fetch by block hash. Optional — sources that index by number can
    /// return [`crate::errors::Error::DataSource`] if they don't support
    /// hash lookups.
    async fn fetch_header_with_proof_by_hash(&self, block_hash: [u8; 32]) -> Result<Vec<u8>>;

    /// Human-readable label for diagnostics.
    fn name(&self) -> &'static str;
}

#[cfg(feature = "portal-sidecar")]
pub mod portal;
#[cfg(feature = "portal-sidecar")]
pub use portal::PortalSidecarSource;

#[cfg(feature = "portal-sidecar")]
pub mod portal_beacon;
#[cfg(feature = "portal-sidecar")]
pub use portal_beacon::{current_historical_summaries_epoch, PortalBeaconSidecarSource};

#[cfg(feature = "archive-rpc")]
pub mod archive_rpc;
#[cfg(feature = "archive-rpc")]
pub use archive_rpc::ArchiveRpcSource;

#[cfg(feature = "archive-rpc")]
pub mod beacon_rpc;
#[cfg(feature = "archive-rpc")]
pub use beacon_rpc::{BeaconDataProvider, BeaconRpcSource};

// `era1` feature currently disabled — see `Cargo.toml` for details.
// The scaffold is preserved at `src/sources/era1.rs` for v0.2.
