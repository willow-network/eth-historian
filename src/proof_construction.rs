//! Construct `BlockProofHistoricalHashesAccumulator` proofs locally from
//! a header + the relevant `EpochAccumulator` blob.
//!
//! Use this when you have a raw header from any source (archive RPC,
//! local cache, etc.) and need to produce a proof you can hand to
//! [`crate::Verifier::verify`]. Removes the dependency on Portal Network
//! at runtime — the only requirement is that you can load the
//! ~524 KB `EpochAccumulator` for the era covering the block.
//!
//! Source: ported from [`trin`](https://github.com/ethereum/trin)
//! commit `30aeef8`, `crates/validation/src/accumulator.rs`. trin's
//! `construct_proof` was for the proof-bridge that uploaded content to
//! the Portal History network; here we reuse the same code locally.
//!
//! ## Operator burden
//!
//! Per-epoch `EpochAccumulator` blobs total ~995 MB across the full
//! pre-merge range (1,896 epochs × 524 KB). This crate does **not**
//! ship them embedded — they're too large, and most users only need
//! a handful of epochs. Caller is responsible for sourcing them; one
//! place is the `epoch_accs/` directory in trin's
//! `portal-spec-tests` submodule, but those checked-in files cover only
//! a few sample epochs. For full coverage, regenerate from a beacon
//! archive node (out of scope here).

use alloy::{
    consensus::Header,
    primitives::{B256, U256},
};
use ssz::Decode;

use crate::{
    errors::{Error, Result},
    merkle::proof::MerkleTree,
    portal_types::{
        BlockProofHistoricalHashesAccumulator, EpochAccumulator, SLOTS_PER_HISTORICAL_ROOT,
    },
};

/// Decode an `EpochAccumulator` from raw SSZ bytes (e.g. read from a
/// `0x{root}.bin` file).
pub fn decode_epoch_accumulator(bytes: &[u8]) -> Result<EpochAccumulator> {
    EpochAccumulator::from_ssz_bytes(bytes).map_err(|e| {
        Error::ProofConstruction(format!("EpochAccumulator SSZ decode failed: {:?}", e))
    })
}

/// Construct a `BlockProofHistoricalHashesAccumulator` for `header`
/// using the `EpochAccumulator` that covers it. Returns an error if the
/// header's hash doesn't match the corresponding entry in the epoch
/// accumulator (which would mean the wrong epoch was supplied or the
/// header is non-canonical).
///
/// Caller is responsible for supplying the right `EpochAccumulator` —
/// the function does not reach out to fetch it. See
/// [`epoch_index_of_block`] to compute which epoch you need.
pub fn construct_pre_merge_proof(
    header: &Header,
    epoch_acc: &EpochAccumulator,
) -> Result<BlockProofHistoricalHashesAccumulator> {
    let hr_index = (header.number % SLOTS_PER_HISTORICAL_ROOT) as usize;
    let header_record = epoch_acc[hr_index];
    if header_record.block_hash != header.hash_slow() {
        return Err(Error::ProofConstruction(format!(
            "header hash {:?} doesn't match epoch accumulator entry {:?} at index {}",
            header.hash_slow(),
            header_record.block_hash,
            hr_index
        )));
    }

    // Header record leaf = hash(block_hash || total_difficulty_le).
    let header_difficulty = B256::from(header_record.total_difficulty.to_le_bytes());
    let header_record_hash = B256::from_slice(&ethereum_hashing::hash32_concat(
        header_record.block_hash.as_slice(),
        header_difficulty.as_slice(),
    ));

    let leaves = epoch_acc
        .iter()
        .map(|record| {
            B256::from_slice(&ethereum_hashing::hash32_concat(
                record.block_hash.as_slice(),
                record.total_difficulty.as_le_slice(),
            ))
        })
        .collect::<Vec<B256>>();

    let merkle_tree = MerkleTree::create(&leaves, 13);

    let (leaf, mut proof) = merkle_tree.generate_proof(hr_index, 13).map_err(|e| {
        Error::ProofConstruction(format!("merkle proof generation failed: {:?}", e))
    })?;

    if leaf != header_record_hash {
        return Err(Error::ProofConstruction(
            "internal: leaf mismatch after merkle construction".into(),
        ));
    }

    // Re-insert total_difficulty as the first proof element so the verifier
    // can recompute the leaf, then append the EPOCH_SIZE encoding to comply
    // with the SSZ object-to-index spec.
    proof.insert(0, header_difficulty);
    let epoch_size = B256::from(U256::from(epoch_acc.len()).to_le_bytes());
    proof.push(epoch_size);

    let final_proof: [B256; 15] = proof
        .try_into()
        .map_err(|_| Error::ProofConstruction("proof length != 15".into()))?;

    BlockProofHistoricalHashesAccumulator::new(final_proof.to_vec()).map_err(|e| {
        Error::ProofConstruction(format!(
            "FixedVector<B256, U15> construction failed: {:?}",
            e
        ))
    })
}

/// Compute which epoch index covers `block_number` in the pre-merge era.
/// Multiply by `SLOTS_PER_HISTORICAL_ROOT` (8192) for the start block of
/// that epoch; the corresponding `EpochAccumulator` file is conventionally
/// named `0x{epoch_root}.bin`.
pub fn epoch_index_of_block(block_number: u64) -> u64 {
    block_number / SLOTS_PER_HISTORICAL_ROOT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_index_for_known_blocks() {
        // Block 0: epoch 0
        assert_eq!(epoch_index_of_block(0), 0);
        // Block 8191: epoch 0 (last block of first epoch)
        assert_eq!(epoch_index_of_block(8_191), 0);
        // Block 8192: epoch 1
        assert_eq!(epoch_index_of_block(8_192), 1);
        // Uniswap V2 deployment (10,000,835): epoch 1220
        assert_eq!(epoch_index_of_block(10_000_835), 1220);
        // Last pre-merge block (15,537,393): epoch 1896 (the partial epoch)
        assert_eq!(epoch_index_of_block(15_537_393), 1896);
    }
}
