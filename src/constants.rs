use alloy::primitives::{b256, B256};

/// Tree-hash root of [`PreMergeAccumulator::default()`] — the canonized
/// double-batched-merkle-log accumulator over every pre-merge mainnet
/// header (block 0 through 15,537,393). Asserted at every load via
/// [`assert_canonized_accumulator_fingerprints`] (`accumulator.rs`).
///
/// Source: trin commit `30aeef8`, `crates/validation/src/constants.rs`.
pub const DEFAULT_PRE_MERGE_ACC_HASH: B256 =
    b256!("0x8eac399e24480dce3cfe06f4bdecba51c6e5d0c46200e3e8611a0b44a3a69ff9");

/// Tree-hash root of [`HistoricalRootsAccumulator::default()`] — the
/// frozen `BeaconState.historical_roots` snapshot at the Capella fork
/// boundary, used to verify post-merge / pre-Capella execution headers.
///
/// Source: trin commit `30aeef8`, `crates/validation/src/historical_roots_acc.rs:92`.
pub const DEFAULT_HISTORICAL_ROOTS_HASH: B256 =
    b256!("0x4df6b89755125d4f6c5575039a04e22301a5a49ee893c1d27e559e3eeab73da7");

/// SHA-256 of the embedded `merge_macc.bin` asset. Asserted at startup so a
/// silently swapped binary fails loudly instead of silently breaking
/// verification.
pub const MERGE_MACC_BIN_SHA256: [u8; 32] = [
    0xa2, 0x36, 0x8b, 0xfa, 0x82, 0xa8, 0x9a, 0x89, 0x8b, 0x31, 0xdc, 0xa6, 0xf3, 0x7a, 0xa2, 0x87,
    0x91, 0x8b, 0xd6, 0x71, 0xbd, 0x74, 0x05, 0x89, 0x12, 0xbc, 0x44, 0x0c, 0x22, 0x88, 0xd7, 0x91,
];

/// SHA-256 of the embedded `historical_roots.ssz` asset.
pub const HISTORICAL_ROOTS_SSZ_SHA256: [u8; 32] = [
    0x64, 0xed, 0x2c, 0xbe, 0xd1, 0x3a, 0x65, 0xc2, 0x24, 0xb4, 0x71, 0xf5, 0x3b, 0x5f, 0x83, 0x20,
    0x30, 0xc1, 0x1e, 0x73, 0x71, 0x0e, 0x27, 0x02, 0x12, 0x1e, 0x7b, 0x1a, 0x50, 0x82, 0xa3, 0x16,
];
