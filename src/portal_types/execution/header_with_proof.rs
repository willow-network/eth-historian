//! `HeaderWithProof` and the four era-specific proof variants.
//!
//! Source: trin `30aeef8`,
//! `crates/ethportal-api/src/types/execution/header_with_proof.rs`.
//! Trimmed to **type definitions + SSZ codecs only** — the
//! `build_historical_roots_proof` / `build_capella_historical_summaries_proof`
//! / `build_deneb_historical_summaries_proof` /
//! `build_electra_historical_summaries_proof` proof-construction
//! helpers from upstream are intentionally not vendored here. They
//! pull in the full BeaconBlock type hierarchy and aren't part of the
//! v0.1 verification surface; tracked under
//! [issue #2](https://github.com/willow-network/eth-historian/issues/2)
//! when post-merge `ArchiveRpcSource` proof construction lands.

use alloy::{consensus::Header, primitives::B256};
use serde::{Deserialize, Serialize};
use ssz::SszDecoderBuilder;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector};

use crate::portal_types::{
    byte_list::ByteList1024,
    execution::ssz_header,
    network_spec::{
        is_cancun_active_at_timestamp, is_paris_active_at_block, is_shanghai_active_at_timestamp,
    },
};

/// Pre-merge accumulator proof for an EL `BlockHeader`.
pub type BlockProofHistoricalHashesAccumulator = FixedVector<B256, typenum::U15>;

/// Proof that EL `block_hash` is in BeaconBlock → BeaconBlockBody →
/// ExecutionPayload, for Bellatrix .. Deneb (exclusive).
pub type ExecutionBlockProofBellatrix = FixedVector<B256, typenum::U11>;

/// Proof that EL `block_hash` is in BeaconBlock → BeaconBlockBody →
/// ExecutionPayload, for Deneb and onwards.
pub type ExecutionBlockProofDeneb = FixedVector<B256, typenum::U12>;

/// Proof that BeaconBlock root is part of `historical_roots`, for
/// merge .. Capella (exclusive).
pub type BeaconBlockProofHistoricalRoots = FixedVector<B256, typenum::U14>;

/// Proof that BeaconBlock root is part of `historical_summaries`,
/// Capella onwards.
pub type BeaconBlockProofHistoricalSummaries = FixedVector<B256, typenum::U13>;

/// Block header + the appropriate-era proof of canonicality.
///
/// Wire format (SSZ Container):
/// ```text
/// {
///   header: ByteList[2048] (RLP-encoded alloy::consensus::Header),
///   proof:  ByteList[1024] (one of the BlockProofHistorical* variants
///                            chosen by the verifier from the header's
///                            number/timestamp)
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Encode, Deserialize, Serialize)]
pub struct HeaderWithProof {
    #[ssz(with = "ssz_header")]
    pub header: Header,
    pub proof: BlockHeaderProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum BlockHeaderProof {
    HistoricalHashes(BlockProofHistoricalHashesAccumulator),
    HistoricalRoots(BlockProofHistoricalRoots),
    HistoricalSummariesCapella(BlockProofHistoricalSummariesCapella),
    HistoricalSummariesDeneb(BlockProofHistoricalSummariesDeneb),
}

impl ssz::Decode for HeaderWithProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);

        builder.register_anonymous_variable_length_item()?;
        builder.register_anonymous_variable_length_item()?;

        let mut decoder = builder.build()?;

        let header = decoder.decode_next_with(ssz_header::decode::from_ssz_bytes)?;
        let proof = decoder.decode_next::<ByteList1024>()?;
        let proof = if is_cancun_active_at_timestamp(header.timestamp) {
            BlockHeaderProof::HistoricalSummariesDeneb(
                BlockProofHistoricalSummariesDeneb::from_ssz_bytes(&proof)?,
            )
        } else if is_shanghai_active_at_timestamp(header.timestamp) {
            BlockHeaderProof::HistoricalSummariesCapella(
                BlockProofHistoricalSummariesCapella::from_ssz_bytes(&proof)?,
            )
        } else if is_paris_active_at_block(header.number) {
            BlockHeaderProof::HistoricalRoots(BlockProofHistoricalRoots::from_ssz_bytes(&proof)?)
        } else {
            BlockHeaderProof::HistoricalHashes(
                BlockProofHistoricalHashesAccumulator::from_ssz_bytes(&proof)?,
            )
        };

        Ok(Self { header, proof })
    }
}

impl ssz::Encode for BlockHeaderProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            BlockHeaderProof::HistoricalHashes(proof) => proof.ssz_append(buf),
            BlockHeaderProof::HistoricalRoots(proof) => proof.ssz_append(buf),
            BlockHeaderProof::HistoricalSummariesCapella(proof) => proof.ssz_append(buf),
            BlockHeaderProof::HistoricalSummariesDeneb(proof) => proof.ssz_append(buf),
        }
    }

    fn ssz_bytes_len(&self) -> usize {
        match self {
            BlockHeaderProof::HistoricalHashes(proof) => proof.ssz_bytes_len(),
            BlockHeaderProof::HistoricalRoots(proof) => proof.ssz_bytes_len(),
            BlockHeaderProof::HistoricalSummariesCapella(proof) => proof.ssz_bytes_len(),
            BlockHeaderProof::HistoricalSummariesDeneb(proof) => proof.ssz_bytes_len(),
        }
    }
}

/// Proof that an EL block belongs to the canonical chain, merge → Capella.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct BlockProofHistoricalRoots {
    pub beacon_block_proof: BeaconBlockProofHistoricalRoots,
    pub beacon_block_root: B256,
    pub execution_block_proof: ExecutionBlockProofBellatrix,
    pub slot: u64,
}

/// Proof that an EL block belongs to the canonical chain, Capella → Deneb.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct BlockProofHistoricalSummariesCapella {
    pub beacon_block_proof: BeaconBlockProofHistoricalSummaries,
    pub beacon_block_root: B256,
    pub execution_block_proof: ExecutionBlockProofBellatrix,
    pub slot: u64,
}

/// Proof that an EL block belongs to the canonical chain, Deneb onwards.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct BlockProofHistoricalSummariesDeneb {
    pub beacon_block_proof: BeaconBlockProofHistoricalSummaries,
    pub beacon_block_root: B256,
    pub execution_block_proof: ExecutionBlockProofDeneb,
    pub slot: u64,
}
