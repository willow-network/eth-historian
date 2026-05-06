//! End-to-end fixture tests for `build_*_proof` against real mainnet
//! `SignedBeaconBlock` fixtures across all four post-merge forks.
//!
//! Each test:
//! 1. Decodes a real mainnet `SignedBeaconBlock` SSZ fixture.
//! 2. Synthesizes a `block_roots` slice (or `HistoricalBatch` for
//!    Bellatrix) holding the block's tree-hash root at the right
//!    intra-era index.
//! 3. Calls the era-appropriate `build_*_proof` helper.
//! 4. Walks the resulting `beacon_block_proof` Merkle path through
//!    SHA-256 — confirms it lands on the expected anchor
//!    (`HistoricalBatch.tree_hash_root()` for Bellatrix,
//!    `block_roots.tree_hash_root()` for Capella+).
//! 5. Walks the `execution_block_proof` from
//!    `execution_payload.block_hash` up to `beacon_block.tree_hash_root()`
//!    using the per-fork `block_hash` generalized index.
//!
//! Together these prove the constructed proof bytes are the canonical
//! SSZ Merkle path, validated end-to-end against real mainnet data —
//! across Bellatrix, Capella, Deneb, and Electra.
//!
//! Fixture sources:
//! * Bellatrix slot 4,700,016 (block 15,537,397) — trin@30aeef8 test_assets
//! * Capella slot 6,209,538 — ChainSafe Lodestar mainnet RPC
//! * Deneb slot 8,626,180 — ChainSafe Lodestar mainnet RPC
//! * Electra slot 11,649,030 — ChainSafe Lodestar mainnet RPC

use alloy::primitives::B256;
use eth_historian::portal_types::{
    build_capella_historical_summaries_proof, build_deneb_historical_summaries_proof,
    build_electra_historical_summaries_proof, build_historical_roots_proof,
    consensus::{
        beacon_block::{SignedBeaconBlock, SignedBeaconBlockBellatrix},
        beacon_state::HistoricalBatch,
        constants::SLOTS_PER_HISTORICAL_ROOT,
        fork::ForkName,
    },
};
use sha2::{Digest, Sha256};
use ssz_types::FixedVector;
use tree_hash::TreeHash;

const FIXTURE_BELLATRIX: &[u8] = include_bytes!("fixtures/beacon/signed_beacon_block_15537397.ssz");
const FIXTURE_CAPELLA: &[u8] =
    include_bytes!("fixtures/beacon/signed_beacon_block_capella_6209538.ssz");
const FIXTURE_DENEB: &[u8] =
    include_bytes!("fixtures/beacon/signed_beacon_block_deneb_8626180.ssz");
const FIXTURE_ELECTRA: &[u8] =
    include_bytes!("fixtures/beacon/signed_beacon_block_electra_11649030.ssz");

// Generalized-index leaf-level position of `execution_payload.block_hash`
// within `BeaconBlock.message`, per fork. Tree depth at leaf = log2 of
// the bottom-level tree width.
//
//   - BeaconBlock.body              field 4 of 5  → depth 3,  gindex 12
//   - BeaconBlockBody.execution_payload field 9   → depth 4,  gindex 201
//
// The ExecutionPayload inner shape diverges:
//   - Bellatrix: 14 fields → depth 4, gindex 3228 → leaf-index 1180
//   - Capella:   15 fields → depth 4, gindex 3228 → leaf-index 1180
//   - Deneb:     17 fields → depth 5, gindex 6444 → leaf-index 2348
//   - Electra:   17 fields → depth 5, gindex 6444 → leaf-index 2348
const BLOCK_HASH_INDEX_BELLATRIX_OR_CAPELLA: usize = 1180;
const BLOCK_HASH_INDEX_DENEB_OR_ELECTRA: usize = 2348;

/// Walk a Merkle path: hash `leaf` with each sibling in `proof`,
/// folding sibling-side based on `index`'s bit at each level.
/// Returns the resulting root.
fn verify_merkle_path_sha256(leaf: B256, proof: &[B256], index: usize) -> B256 {
    let mut current = leaf;
    let mut idx = index;
    for sibling in proof {
        let mut hasher = Sha256::new();
        if idx % 2 == 0 {
            hasher.update(current.as_slice());
            hasher.update(sibling.as_slice());
        } else {
            hasher.update(sibling.as_slice());
            hasher.update(current.as_slice());
        }
        current = B256::from_slice(&hasher.finalize());
        idx /= 2;
    }
    current
}

#[test]
fn build_historical_roots_proof_path_is_consistent_for_real_bellatrix_block() {
    // 1. Decode the real mainnet beacon block.
    let signed_block = SignedBeaconBlock::from_ssz_bytes(FIXTURE_BELLATRIX, ForkName::Bellatrix)
        .expect("fixture should decode as Bellatrix SignedBeaconBlock");
    let bellatrix: &SignedBeaconBlockBellatrix = match &signed_block {
        SignedBeaconBlock::Bellatrix(b) => b,
        other => panic!("expected Bellatrix variant, got {other:?}"),
    };
    let block = &bellatrix.message;
    let slot = block.slot;
    let beacon_block_root = block.tree_hash_root();

    assert!(
        slot >= 4_700_013,
        "fixture slot {slot} should be ≥ merge slot 4_700_013"
    );

    // 2. Construct a synthetic `HistoricalBatch` whose entry at this
    //    block's intra-era index holds the block's tree-hash root.
    //    Other slots are zero. This is enough to test the structural
    //    correctness of the Merkle path: the proof we build should
    //    walk back to the synthetic batch's tree-hash root.
    let intra_era_idx = (slot % SLOTS_PER_HISTORICAL_ROOT) as usize;
    let mut block_roots = vec![B256::ZERO; SLOTS_PER_HISTORICAL_ROOT as usize];
    block_roots[intra_era_idx] = beacon_block_root;
    let historical_batch = HistoricalBatch {
        block_roots: FixedVector::new(block_roots).expect("8192 entries"),
        state_roots: FixedVector::default(),
    };

    // 3. Build the proof.
    let proof = build_historical_roots_proof(slot, &historical_batch, block);

    // 4. Sanity-check the proof's metadata.
    assert_eq!(proof.beacon_block_root, beacon_block_root);
    assert_eq!(proof.slot, slot);
    assert_eq!(
        proof.beacon_block_proof.len(),
        14,
        "beacon_block_proof must be 14 hashes for HistoricalRoots"
    );
    assert_eq!(
        proof.execution_block_proof.len(),
        11,
        "execution_block_proof must be 11 hashes for Bellatrix"
    );

    // 5. Verify the beacon-block Merkle path: walk up from the leaf
    //    using the proof siblings and the intra-era index. The result
    //    must equal the synthetic `HistoricalBatch`'s tree-hash root.
    let beacon_proof: Vec<B256> = proof.beacon_block_proof.iter().copied().collect();
    let recovered_batch_root =
        verify_merkle_path_sha256(beacon_block_root, &beacon_proof, intra_era_idx);
    assert_eq!(
        recovered_batch_root,
        historical_batch.tree_hash_root(),
        "Merkle path should reconstruct historical_batch.tree_hash_root()"
    );

    // 6. Verify the execution-block Merkle path: walk up from
    //    `execution_payload.block_hash` to the beacon-block root.
    let exec_block_hash = block.body.execution_payload.block_hash;
    let exec_proof: Vec<B256> = proof.execution_block_proof.iter().copied().collect();
    let recovered_block_root = verify_merkle_path_sha256(
        exec_block_hash,
        &exec_proof,
        BLOCK_HASH_INDEX_BELLATRIX_OR_CAPELLA,
    );
    assert_eq!(
        recovered_block_root, beacon_block_root,
        "execution Merkle path should reconstruct beacon_block.tree_hash_root()"
    );
}

#[test]
fn build_capella_historical_summaries_proof_path_is_consistent_for_real_capella_block() {
    let signed_block = SignedBeaconBlock::from_ssz_bytes(FIXTURE_CAPELLA, ForkName::Capella)
        .expect("fixture should decode as Capella SignedBeaconBlock");
    let capella = match &signed_block {
        SignedBeaconBlock::Capella(b) => b,
        other => panic!("expected Capella variant, got {other:?}"),
    };
    let block = &capella.message;
    let slot = block.slot;
    let beacon_block_root = block.tree_hash_root();

    let intra_era_idx = (slot % SLOTS_PER_HISTORICAL_ROOT) as usize;
    let mut block_roots_vec = vec![B256::ZERO; SLOTS_PER_HISTORICAL_ROOT as usize];
    block_roots_vec[intra_era_idx] = beacon_block_root;
    let block_roots = FixedVector::new(block_roots_vec).expect("8192 entries");

    let proof = build_capella_historical_summaries_proof(slot, &block_roots, block);

    assert_eq!(proof.beacon_block_root, beacon_block_root);
    assert_eq!(proof.slot, slot);
    assert_eq!(proof.beacon_block_proof.len(), 13);
    assert_eq!(proof.execution_block_proof.len(), 11);

    // beacon_block_proof anchors at block_roots.tree_hash_root() (post-Capella
    // historical_summaries binds the era's block_roots, not a HistoricalBatch).
    let beacon_proof: Vec<B256> = proof.beacon_block_proof.iter().copied().collect();
    let recovered = verify_merkle_path_sha256(beacon_block_root, &beacon_proof, intra_era_idx);
    assert_eq!(
        recovered,
        block_roots.tree_hash_root(),
        "Capella beacon_block_proof should reconstruct block_roots.tree_hash_root()"
    );

    let exec_proof: Vec<B256> = proof.execution_block_proof.iter().copied().collect();
    let recovered_block_root = verify_merkle_path_sha256(
        block.body.execution_payload.block_hash,
        &exec_proof,
        BLOCK_HASH_INDEX_BELLATRIX_OR_CAPELLA,
    );
    assert_eq!(recovered_block_root, beacon_block_root);
}

#[test]
fn build_deneb_historical_summaries_proof_path_is_consistent_for_real_deneb_block() {
    let signed_block = SignedBeaconBlock::from_ssz_bytes(FIXTURE_DENEB, ForkName::Deneb)
        .expect("fixture should decode as Deneb SignedBeaconBlock");
    let deneb = match &signed_block {
        SignedBeaconBlock::Deneb(b) => b,
        other => panic!("expected Deneb variant, got {other:?}"),
    };
    let block = &deneb.message;
    let slot = block.slot;
    let beacon_block_root = block.tree_hash_root();

    let intra_era_idx = (slot % SLOTS_PER_HISTORICAL_ROOT) as usize;
    let mut block_roots_vec = vec![B256::ZERO; SLOTS_PER_HISTORICAL_ROOT as usize];
    block_roots_vec[intra_era_idx] = beacon_block_root;
    let block_roots = FixedVector::new(block_roots_vec).expect("8192 entries");

    let proof = build_deneb_historical_summaries_proof(slot, &block_roots, block);

    assert_eq!(proof.beacon_block_root, beacon_block_root);
    assert_eq!(proof.slot, slot);
    assert_eq!(proof.beacon_block_proof.len(), 13);
    assert_eq!(proof.execution_block_proof.len(), 12);

    let beacon_proof: Vec<B256> = proof.beacon_block_proof.iter().copied().collect();
    let recovered = verify_merkle_path_sha256(beacon_block_root, &beacon_proof, intra_era_idx);
    assert_eq!(recovered, block_roots.tree_hash_root());

    let exec_proof: Vec<B256> = proof.execution_block_proof.iter().copied().collect();
    let recovered_block_root = verify_merkle_path_sha256(
        block.body.execution_payload.block_hash,
        &exec_proof,
        BLOCK_HASH_INDEX_DENEB_OR_ELECTRA,
    );
    assert_eq!(recovered_block_root, beacon_block_root);
}

#[test]
fn build_electra_historical_summaries_proof_path_is_consistent_for_real_electra_block() {
    let signed_block = SignedBeaconBlock::from_ssz_bytes(FIXTURE_ELECTRA, ForkName::Electra)
        .expect("fixture should decode as Electra SignedBeaconBlock");
    let electra = match &signed_block {
        SignedBeaconBlock::Electra(b) => b,
        other => panic!("expected Electra variant, got {other:?}"),
    };
    let block = &electra.message;
    let slot = block.slot;
    let beacon_block_root = block.tree_hash_root();

    let intra_era_idx = (slot % SLOTS_PER_HISTORICAL_ROOT) as usize;
    let mut block_roots_vec = vec![B256::ZERO; SLOTS_PER_HISTORICAL_ROOT as usize];
    block_roots_vec[intra_era_idx] = beacon_block_root;
    let block_roots = FixedVector::new(block_roots_vec).expect("8192 entries");

    let proof = build_electra_historical_summaries_proof(slot, &block_roots, block);

    assert_eq!(proof.beacon_block_root, beacon_block_root);
    assert_eq!(proof.slot, slot);
    assert_eq!(proof.beacon_block_proof.len(), 13);
    assert_eq!(proof.execution_block_proof.len(), 12);

    let beacon_proof: Vec<B256> = proof.beacon_block_proof.iter().copied().collect();
    let recovered = verify_merkle_path_sha256(beacon_block_root, &beacon_proof, intra_era_idx);
    assert_eq!(recovered, block_roots.tree_hash_root());

    let exec_proof: Vec<B256> = proof.execution_block_proof.iter().copied().collect();
    let recovered_block_root = verify_merkle_path_sha256(
        block.body.execution_payload.block_hash,
        &exec_proof,
        BLOCK_HASH_INDEX_DENEB_OR_ELECTRA,
    );
    assert_eq!(recovered_block_root, beacon_block_root);
}

#[test]
fn build_historical_roots_proof_rejects_wrong_index() {
    // Sanity: if we verify with the wrong index, the recovered root
    // should NOT match — proves the verification is index-sensitive
    // and the proof actually binds the block to its slot.
    let signed_block = SignedBeaconBlock::from_ssz_bytes(FIXTURE_BELLATRIX, ForkName::Bellatrix)
        .expect("fixture decodes");
    let block = match &signed_block {
        SignedBeaconBlock::Bellatrix(b) => &b.message,
        _ => unreachable!(),
    };
    let slot = block.slot;
    let intra_era_idx = (slot % SLOTS_PER_HISTORICAL_ROOT) as usize;

    let mut block_roots = vec![B256::ZERO; SLOTS_PER_HISTORICAL_ROOT as usize];
    block_roots[intra_era_idx] = block.tree_hash_root();
    let historical_batch = HistoricalBatch {
        block_roots: FixedVector::new(block_roots).unwrap(),
        state_roots: FixedVector::default(),
    };

    let proof = build_historical_roots_proof(slot, &historical_batch, block);
    let proof_hashes: Vec<B256> = proof.beacon_block_proof.iter().copied().collect();

    // Walk the proof from the WRONG index. The recovered root should
    // not match.
    let wrong_idx = intra_era_idx ^ 1; // flip the bottom bit
    let recovered = verify_merkle_path_sha256(block.tree_hash_root(), &proof_hashes, wrong_idx);
    assert_ne!(
        recovered,
        historical_batch.tree_hash_root(),
        "wrong-index walk must not reproduce the batch root"
    );
}
