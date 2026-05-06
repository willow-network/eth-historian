//! Mainnet fork-activation predicates.
//!
//! `ethportal-api` exposes these via a runtime-configurable
//! `NetworkSpec` struct that pulls in `alloy_hardforks` for full
//! `EthereumChainHardforks` coverage. We don't need the configurability
//! (mainnet-only canonized-accumulator verification) and we don't want
//! the alloy_hardforks transitive deps, so we vendor as bare constants.
//!
//! Mainnet timestamps:
//! * Paris (merge): block 15,537,394 — Sept 15, 2022
//! * Shanghai (Capella): timestamp 1,681,338,455 — April 12, 2023
//! * Cancun (Deneb): timestamp 1,710,338,135 — March 13, 2024
//!
//! These are immutable historical values; if any new EL fork activates
//! we'd need to add another predicate here, but the validator only
//! cares about the three transitions where the proof shape changes.

/// Mainnet block number at which the merge / Paris fork activated.
pub const MAINNET_PARIS_BLOCK: u64 = 15_537_394;

/// Mainnet timestamp at which the Shanghai (Capella) fork activated.
pub const MAINNET_SHANGHAI_TIMESTAMP: u64 = 1_681_338_455;

/// Mainnet timestamp at which the Cancun (Deneb) fork activated.
pub const MAINNET_CANCUN_TIMESTAMP: u64 = 1_710_338_135;

/// Mainnet beacon-chain genesis timestamp (slot 0). Dec 1, 2020 12:00:23 UTC.
pub const MAINNET_BEACON_GENESIS_TIMESTAMP: u64 = 1_606_824_023;

/// Seconds per beacon slot on mainnet.
pub const MAINNET_SECONDS_PER_SLOT: u64 = 12;

/// Map a post-merge execution block timestamp to its consensus slot.
///
/// Returns `None` if the timestamp is before beacon genesis (in which
/// case the block isn't post-merge and shouldn't be passed here).
#[inline]
pub fn slot_for_execution_timestamp(timestamp: u64) -> Option<u64> {
    timestamp
        .checked_sub(MAINNET_BEACON_GENESIS_TIMESTAMP)
        .map(|secs_since_genesis| secs_since_genesis / MAINNET_SECONDS_PER_SLOT)
}

/// `true` if `block_number` is at or after the merge.
#[inline]
pub fn is_paris_active_at_block(block_number: u64) -> bool {
    block_number >= MAINNET_PARIS_BLOCK
}

/// `true` if `timestamp` is at or after the Shanghai (Capella) fork.
#[inline]
pub fn is_shanghai_active_at_timestamp(timestamp: u64) -> bool {
    timestamp >= MAINNET_SHANGHAI_TIMESTAMP
}

/// `true` if `timestamp` is at or after the Cancun (Deneb) fork.
#[inline]
pub fn is_cancun_active_at_timestamp(timestamp: u64) -> bool {
    timestamp >= MAINNET_CANCUN_TIMESTAMP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_boundaries_lock_to_known_values() {
        // Last pre-merge block: 15_537_393. First post-merge: 15_537_394.
        assert!(!is_paris_active_at_block(15_537_393));
        assert!(is_paris_active_at_block(15_537_394));

        // Capella activated at Apr 12 2023 22:27:35 UTC = 1_681_338_455.
        assert!(!is_shanghai_active_at_timestamp(1_681_338_454));
        assert!(is_shanghai_active_at_timestamp(1_681_338_455));

        // Deneb activated at Mar 13 2024 13:55:35 UTC = 1_710_338_135.
        assert!(!is_cancun_active_at_timestamp(1_710_338_134));
        assert!(is_cancun_active_at_timestamp(1_710_338_135));
    }
}
