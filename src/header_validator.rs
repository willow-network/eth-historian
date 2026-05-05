//! Verifies an [`HeaderWithProof`] against the canonized Portal Network
//! accumulators (pre-merge / merge-to-Capella) or against an in-memory
//! [`HistoricalSummaries`] snapshot (Capella+).
//!
//! Source: trin commit `30aeef8`, `crates/validation/src/header_validator.rs`.
//! Reduced to drop `new_with_header_oracle` (we do not vendor the
//! cross-overlay JSON-RPC HeaderOracle), and tests (they require the
//! `portal-spec-tests` git submodule).

use alloy::{consensus::Header, primitives::B256};
use anyhow::bail;
use tracing::error;
use tree_hash::TreeHash;

use crate::{
    accumulator::PreMergeAccumulator,
    historical_roots_acc::HistoricalRootsAccumulator,
    historical_summaries_provider::HistoricalSummariesProvider,
    merkle::proof::verify_merkle_proof,
    portal_types::{
        network_spec::{
            is_cancun_active_at_timestamp, is_paris_active_at_block,
            is_shanghai_active_at_timestamp,
        },
        BeaconBlockProofHistoricalRoots, BeaconBlockProofHistoricalSummaries, BlockHeaderProof,
        BlockProofHistoricalHashesAccumulator, BlockProofHistoricalRoots,
        BlockProofHistoricalSummariesCapella, BlockProofHistoricalSummariesDeneb, HeaderWithProof,
        HistoricalSummaries, SLOTS_PER_HISTORICAL_ROOT,
    },
};

#[derive(Debug, Clone)]
pub struct HeaderValidator {
    pub pre_merge_acc: PreMergeAccumulator,
    pub historical_roots_acc: HistoricalRootsAccumulator,
    pub historical_summaries_provider: HistoricalSummariesProvider,
}

impl Default for HeaderValidator {
    /// Construct with empty `HistoricalSummaries`. Pre-Capella verification
    /// works out of the box; Capella+ verification will fail until
    /// [`HistoricalSummariesProvider::set_summaries`] supplies a snapshot.
    fn default() -> Self {
        Self::new_with_historical_summaries(HistoricalSummaries::default())
    }
}

impl HeaderValidator {
    pub fn new_with_historical_summaries(historical_summaries: HistoricalSummaries) -> Self {
        let pre_merge_acc = PreMergeAccumulator::default();
        tracing::info!(
            hash_tree_root = %pre_merge_acc.tree_hash_root(),
            "Loaded pre-merge accumulator."
        );
        Self {
            pre_merge_acc,
            historical_roots_acc: HistoricalRootsAccumulator::default(),
            historical_summaries_provider: HistoricalSummariesProvider::new(historical_summaries),
        }
    }

    pub async fn validate_header_with_proof(
        &self,
        header_with_proof: &HeaderWithProof,
    ) -> anyhow::Result<()> {
        let HeaderWithProof { header, proof } = header_with_proof;
        match proof {
            BlockHeaderProof::HistoricalHashes(proof) => {
                self.verify_pre_merge_header(header, proof)
            }
            BlockHeaderProof::HistoricalRoots(proof) => self.verify_merge_to_capella_header(
                header.number,
                header.timestamp,
                header.hash_slow(),
                proof,
            ),
            BlockHeaderProof::HistoricalSummariesCapella(proof) => {
                self.verify_capella_to_deneb_header(header.timestamp, header.hash_slow(), proof)
                    .await
            }
            BlockHeaderProof::HistoricalSummariesDeneb(proof) => {
                self.verify_post_deneb_header(header.timestamp, header.hash_slow(), proof)
                    .await
            }
        }
    }

    fn verify_pre_merge_header(
        &self,
        header: &Header,
        proof: &BlockProofHistoricalHashesAccumulator,
    ) -> anyhow::Result<()> {
        if is_paris_active_at_block(header.number) {
            bail!("Invalid proof type found for post-merge header.");
        }

        let header_index = header.number % SLOTS_PER_HISTORICAL_ROOT;
        let gen_index = (SLOTS_PER_HISTORICAL_ROOT * 2 * 2) + (header_index * 2);

        let epoch_index = self.pre_merge_acc.get_epoch_index_of_header(header) as usize;
        let epoch_hash = self.pre_merge_acc.historical_epochs[epoch_index];

        if !verify_merkle_proof(
            header.hash_slow(),
            proof,
            15,
            gen_index as usize,
            epoch_hash,
        ) {
            bail!("Execution block proof verification failed for pre-Merge header");
        }
        Ok(())
    }

    fn verify_merge_to_capella_header(
        &self,
        block_number: u64,
        block_timestamp: u64,
        header_hash: B256,
        proof: &BlockProofHistoricalRoots,
    ) -> anyhow::Result<()> {
        if !is_paris_active_at_block(block_number) {
            bail!("Invalid BlockProofHistoricalRoots found for pre-Merge header.");
        }
        if is_shanghai_active_at_timestamp(block_timestamp) {
            bail!("Invalid BlockProofHistoricalRoots found for post-Shanghai header.");
        }

        if !self.verify_bellatrix_to_deneb_execution_block_proof(
            header_hash,
            &proof.execution_block_proof,
            proof.beacon_block_root,
        ) {
            bail!("Execution block proof verification failed for Merge-Capella header");
        }

        if !self.verify_historical_roots_beacon_block_proof(
            proof.slot,
            proof.beacon_block_root,
            &proof.beacon_block_proof,
        ) {
            bail!("Beacon block proof verification failed for Merge-Capella header");
        }

        Ok(())
    }

    async fn verify_capella_to_deneb_header(
        &self,
        block_timestamp: u64,
        header_hash: B256,
        proof: &BlockProofHistoricalSummariesCapella,
    ) -> anyhow::Result<()> {
        if !is_shanghai_active_at_timestamp(block_timestamp) {
            bail!("Invalid BlockProofHistoricalSummariesCapella found for pre-Shanghai header.");
        }
        if is_cancun_active_at_timestamp(block_timestamp) {
            bail!("Invalid BlockProofHistoricalSummariesCapella found for post-Cancun header.");
        }

        if !self.verify_bellatrix_to_deneb_execution_block_proof(
            header_hash,
            &proof.execution_block_proof,
            proof.beacon_block_root,
        ) {
            bail!("Execution block proof verification failed for Capella-Deneb header");
        }

        if !self
            .verify_historical_summaries_beacon_block_proof(
                proof.slot,
                proof.beacon_block_root,
                &proof.beacon_block_proof,
            )
            .await
        {
            bail!("Beacon block proof verification failed for Capella-Deneb header");
        }

        Ok(())
    }

    async fn verify_post_deneb_header(
        &self,
        block_timestamp: u64,
        header_hash: B256,
        proof: &BlockProofHistoricalSummariesDeneb,
    ) -> anyhow::Result<()> {
        if !is_cancun_active_at_timestamp(block_timestamp) {
            bail!("Invalid BlockProofHistoricalSummariesDeneb found for pre-Cancun header.");
        }

        if !self.verify_post_deneb_execution_block_proof(
            header_hash,
            &proof.execution_block_proof,
            proof.beacon_block_root,
        ) {
            bail!("Execution block proof verification failed for post-Deneb header");
        }

        if !self
            .verify_historical_summaries_beacon_block_proof(
                proof.slot,
                proof.beacon_block_root,
                &proof.beacon_block_proof,
            )
            .await
        {
            bail!("Beacon block proof verification failed for post-Deneb header");
        }

        Ok(())
    }

    #[must_use]
    fn verify_bellatrix_to_deneb_execution_block_proof(
        &self,
        execution_header_hash: B256,
        execution_block_proof: &[B256],
        block_body_root: B256,
    ) -> bool {
        // Generalized index 3228 — see trin's accumulator.rs for derivation.
        let gen_index = 3228;

        verify_merkle_proof(
            execution_header_hash,
            execution_block_proof,
            execution_block_proof.len(),
            gen_index,
            block_body_root,
        )
    }

    #[must_use]
    fn verify_post_deneb_execution_block_proof(
        &self,
        execution_header_hash: B256,
        execution_block_proof: &[B256],
        block_body_root: B256,
    ) -> bool {
        // Generalized index 6444 — Deneb/Electra ExecutionPayload has 17 fields.
        let gen_index = 6444;

        verify_merkle_proof(
            execution_header_hash,
            execution_block_proof,
            execution_block_proof.len(),
            gen_index,
            block_body_root,
        )
    }

    #[must_use]
    fn verify_historical_roots_beacon_block_proof(
        &self,
        slot: u64,
        beacon_block_root: B256,
        beacon_block_proof: &BeaconBlockProofHistoricalRoots,
    ) -> bool {
        let block_root_index = slot % SLOTS_PER_HISTORICAL_ROOT;
        let gen_index = 2 * SLOTS_PER_HISTORICAL_ROOT + block_root_index;
        let historical_root_index = slot / SLOTS_PER_HISTORICAL_ROOT;
        let historical_root =
            self.historical_roots_acc.historical_roots[historical_root_index as usize];

        verify_merkle_proof(
            beacon_block_root,
            beacon_block_proof,
            14,
            gen_index as usize,
            historical_root,
        )
    }

    #[must_use]
    async fn verify_historical_summaries_beacon_block_proof(
        &self,
        slot: u64,
        beacon_block_root: B256,
        beacon_block_proof: &BeaconBlockProofHistoricalSummaries,
    ) -> bool {
        let Ok(historical_summary) = self
            .historical_summaries_provider
            .get_historical_summary(slot)
            .await
        else {
            error!("Failed to get historical summary for slot {slot}");
            return false;
        };

        verify_merkle_proof(
            beacon_block_root,
            beacon_block_proof,
            13,
            (SLOTS_PER_HISTORICAL_ROOT + (slot % SLOTS_PER_HISTORICAL_ROOT)) as usize,
            historical_summary.block_summary_root,
        )
    }
}
