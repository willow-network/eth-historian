//! End-to-end fixture test for `build_historical_roots_proof` against
//! a real mainnet `SignedBeaconBlock`.
//!
//! Validates that the proof eth-historian constructs is internally
//! consistent: walking up from the beacon-block root through the
//! Merkle path lands on the synthetic `HistoricalBatch.tree_hash_root()`
//! we built around the block.
//!
//! This is the structural validation that was missing from the wiring
//! PR (#8) — it proves that for a real mainnet Bellatrix-era beacon
//! block, the constructed proof is the canonical SSZ Merkle path.
//!
//! The fixture (~76 KB) is a real `SignedBeaconBlockBellatrix` covering
//! mainnet execution block 15,537,397 (slot 4,700,016, three slots
//! after the merge). Sourced from
//! [`trin@30aeef8`'s `test_assets/beacon/bellatrix/`](https://github.com/ethereum/trin/blob/30aeef8/test_assets/beacon/bellatrix/ValidSignedBeaconBlock/signed_beacon_block_15537397.ssz).
//!
//! Capella / Deneb / Electra equivalents need their own `SignedBeaconBlock`
//! fixtures from real mainnet — tracked as a follow-up; the verification
//! helper here is fork-agnostic so adding them is mechanical.

use alloy::primitives::B256;
use eth_historian::portal_types::{
    build_historical_roots_proof,
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
    //
    //    Generalized index of `block_hash` within `BeaconBlockBellatrix`:
    //      - BeaconBlock.body            field 4 of 5 (padded to 8) — gindex 8 + 4 = 12
    //      - BeaconBlockBody.execution_payload  field 9 of 10 (padded to 16) — gindex 12*16 + 9 = 201
    //      - ExecutionPayload.block_hash field 12 of 14 (padded to 16) — gindex 201*16 + 12 = 3228
    //    Tree depth at leaf level: 3 + 4 + 4 = 11; index = 3228 − 2^11 = 1180.
    const BLOCK_HASH_INDEX_BELLATRIX: usize = 1180;
    let exec_block_hash = block.body.execution_payload.block_hash;
    let exec_proof: Vec<B256> = proof.execution_block_proof.iter().copied().collect();
    let recovered_block_root =
        verify_merkle_path_sha256(exec_block_hash, &exec_proof, BLOCK_HASH_INDEX_BELLATRIX);
    assert_eq!(
        recovered_block_root, beacon_block_root,
        "execution Merkle path should reconstruct beacon_block.tree_hash_root()"
    );
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
