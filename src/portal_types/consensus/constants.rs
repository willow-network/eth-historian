//! Beacon-chain consensus-specs constants used by the verifier.
//!
//! Source: trin `30aeef8`, `crates/ethportal-api/src/types/consensus/constants.rs`.

use std::time::Duration;

/// 2^5 = 32 slots per epoch (~6.4 minutes).
pub const SLOTS_PER_EPOCH: u64 = 32;

/// 2^13 = 8,192 slots per `HistoricalRoot` / `HistoricalSummary` (~27 hours).
pub const SLOTS_PER_HISTORICAL_ROOT: u64 = 8192;

/// 12 seconds per slot.
pub const SECONDS_PER_SLOT: Duration = Duration::from_secs(12);

/// Mainnet Capella fork epoch — April 12, 2023 22:27:35 UTC.
pub const CAPELLA_FORK_EPOCH: u64 = 194_048;

/// Mainnet Deneb fork epoch — March 13, 2024 13:55:35 UTC.
pub const DENEB_FORK_EPOCH: u64 = 269_568;

/// Mainnet Electra fork epoch — May 7, 2025 10:05:11 UTC.
pub const ELECTRA_FORK_EPOCH: u64 = 364_032;
