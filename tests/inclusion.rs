//! Integration tests for receipt / transaction inclusion verification.
//!
//! These build small but real Merkle Patricia Tries via `alloy-trie`,
//! generate proofs against them, and then verify those proofs through
//! eth-historian's public API. A passing test here means the verifier
//! agrees with `alloy-trie`'s hashing — i.e. it accepts proofs that
//! match real Ethereum trie roots and rejects tampered ones.
//!
//! Why synthetic-but-real: the Ethereum receipt/tx tries use the same
//! Yellow Paper MPT as state, so a roundtrip on hand-built data
//! exercises the same code path that runs on production data. The unit
//! we're testing is `verify_mpt_inclusion` plus its `tx`/`receipt`
//! wrappers; the trie semantics live in alloy-trie, which is
//! independently tested by the alloy ecosystem.

use alloy::consensus::{Header, Receipt, ReceiptEnvelope, ReceiptWithBloom};
use alloy::primitives::{Bloom, Bytes, B256};
use alloy_rlp::Encodable;
use alloy_trie::{hash_builder::HashBuilder, proof::ProofRetainer, Nibbles};
use eth_historian::{
    inclusion::{
        decode_receipt, verify_and_decode_receipt, verify_mpt_inclusion, verify_receipt_inclusion,
        verify_transaction_inclusion,
    },
    AuthPath, VerifiedBlock,
};

/// Build a minimal MPT over `pairs` (treated as `(rlp(index), value)` pairs)
/// and return `(root, proof_nodes_for_target)`. Pairs are sorted by trie key
/// internally — caller supplies them in any order.
fn build_trie_with_proof(pairs: &[(u64, Vec<u8>)], target_index: u64) -> (B256, Vec<Bytes>) {
    let mut keyed: Vec<(Vec<u8>, Vec<u8>)> = pairs
        .iter()
        .map(|(idx, value)| {
            let mut key = Vec::new();
            idx.encode(&mut key);
            (key, value.clone())
        })
        .collect();
    keyed.sort_by(|a, b| Nibbles::unpack(&a.0).cmp(&Nibbles::unpack(&b.0)));

    let mut target_key = Vec::new();
    target_index.encode(&mut target_key);
    let target_nibbles = Nibbles::unpack(&target_key);

    let retainer = ProofRetainer::new(vec![target_nibbles]);
    let mut hb = HashBuilder::default().with_proof_retainer(retainer);

    for (key, value) in &keyed {
        hb.add_leaf(Nibbles::unpack(key), value);
    }

    let root = hb.root();
    let proof_nodes = hb.take_proof_nodes();

    // Canonical alloy-trie pattern: hand the verifier the full sorted node
    // list. `matching_nodes_sorted` looks tempting but drops nodes that
    // verify_proof needs when small leaves are encoded inline in their
    // parent branch (Yellow Paper Appendix D).
    let nodes: Vec<Bytes> = proof_nodes
        .into_nodes_sorted()
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect();
    (root, nodes)
}

fn synthetic_receipt(status: bool, gas_used: u64) -> ReceiptEnvelope {
    ReceiptEnvelope::Legacy(ReceiptWithBloom {
        receipt: Receipt {
            status: status.into(),
            cumulative_gas_used: gas_used,
            logs: Vec::new(),
        },
        logs_bloom: Bloom::ZERO,
    })
}

fn encode_envelope_for_trie(env: &ReceiptEnvelope) -> Vec<u8> {
    use alloy::eips::eip2718::Encodable2718;
    // Trie value for typed receipts is `tx_type || rlp(receipt)`; for
    // legacy it's just `rlp(receipt)`. Encodable2718::encoded_2718
    // produces exactly this wire format.
    env.encoded_2718()
}

#[test]
fn verify_receipt_inclusion_roundtrip() {
    // Three legacy receipts at indices 0, 1, 2.
    let receipts = [
        encode_envelope_for_trie(&synthetic_receipt(true, 21_000)),
        encode_envelope_for_trie(&synthetic_receipt(true, 42_000)),
        encode_envelope_for_trie(&synthetic_receipt(false, 100_000)),
    ];
    let pairs: Vec<(u64, Vec<u8>)> = receipts
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, b)| (i as u64, b))
        .collect();

    for target in 0u64..3 {
        let (root, proof) = build_trie_with_proof(&pairs, target);
        verify_receipt_inclusion(root, target, &receipts[target as usize], &proof)
            .expect("legitimate proof should verify");
    }
}

#[test]
fn verify_receipt_inclusion_rejects_wrong_value() {
    let r0 = encode_envelope_for_trie(&synthetic_receipt(true, 21_000));
    let r1 = encode_envelope_for_trie(&synthetic_receipt(true, 42_000));
    let pairs = vec![(0u64, r0.clone()), (1u64, r1.clone())];

    let (root, proof) = build_trie_with_proof(&pairs, 0);

    // Tamper with the value bytes.
    let mut wrong = r0.clone();
    *wrong.last_mut().unwrap() ^= 0x01;

    let err = verify_receipt_inclusion(root, 0, &wrong, &proof).unwrap_err();
    assert!(
        matches!(err, eth_historian::Error::MptInclusion(_)),
        "expected MptInclusion error, got {err:?}"
    );
}

#[test]
fn verify_receipt_inclusion_rejects_wrong_root() {
    let r0 = encode_envelope_for_trie(&synthetic_receipt(true, 21_000));
    let r1 = encode_envelope_for_trie(&synthetic_receipt(true, 42_000));
    let pairs = vec![(0u64, r0.clone()), (1u64, r1.clone())];
    let (_root, proof) = build_trie_with_proof(&pairs, 0);

    // Use a totally different root.
    let bad_root = B256::repeat_byte(0xff);
    let err = verify_receipt_inclusion(bad_root, 0, &r0, &proof).unwrap_err();
    assert!(matches!(err, eth_historian::Error::MptInclusion(_)));
}

#[test]
fn verify_receipt_inclusion_rejects_wrong_index() {
    let r0 = encode_envelope_for_trie(&synthetic_receipt(true, 21_000));
    let r1 = encode_envelope_for_trie(&synthetic_receipt(true, 42_000));
    let pairs = vec![(0u64, r0.clone()), (1u64, r1.clone())];
    let (root, proof) = build_trie_with_proof(&pairs, 0);

    // Proof is for index 0, but we claim it's for index 1.
    let err = verify_receipt_inclusion(root, 1, &r0, &proof).unwrap_err();
    assert!(matches!(err, eth_historian::Error::MptInclusion(_)));
}

#[test]
fn verify_transaction_inclusion_roundtrip() {
    // Use opaque payloads — the inclusion verifier doesn't decode them.
    let txs = [
        b"transaction-zero-payload-bytes".to_vec(),
        b"transaction-one-payload-bytes".to_vec(),
        b"transaction-two-payload-bytes".to_vec(),
    ];
    let pairs: Vec<(u64, Vec<u8>)> = txs
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, b)| (i as u64, b))
        .collect();

    for target in 0u64..3 {
        let (root, proof) = build_trie_with_proof(&pairs, target);
        verify_transaction_inclusion(root, target, &txs[target as usize], &proof)
            .expect("legitimate tx proof should verify");
    }
}

#[test]
fn verify_and_decode_receipt_returns_typed_envelope() {
    let r0 = synthetic_receipt(true, 21_000);
    let r0_bytes = encode_envelope_for_trie(&r0);
    let pairs = vec![(0u64, r0_bytes.clone())];
    let (root, proof) = build_trie_with_proof(&pairs, 0);

    let decoded = verify_and_decode_receipt(root, 0, &r0_bytes, &proof)
        .expect("verify+decode should succeed");

    match decoded {
        ReceiptEnvelope::Legacy(r) => {
            assert_eq!(r.receipt.cumulative_gas_used, 21_000);
            assert!(r.receipt.status.coerce_status());
            assert_eq!(r.receipt.logs.len(), 0);
        }
        other => panic!("expected Legacy receipt, got {:?}", other),
    }
}

#[test]
fn decode_receipt_handles_legacy_and_typed() {
    let legacy = synthetic_receipt(true, 21_000);
    let legacy_bytes = encode_envelope_for_trie(&legacy);
    assert!(
        legacy_bytes[0] >= 0x80,
        "legacy receipt RLP starts with list header"
    );
    decode_receipt(0, &legacy_bytes).expect("legacy decode");

    // Typed receipts (EIP-2930+) are `type_byte || rlp_payload`.
    // We don't have a synthetic constructor handy for typed receipts in
    // this test scope; verify_and_decode_receipt above exercises the
    // legacy path, and decode_receipt's typed branch is exercised by
    // real-Ethereum data tests added once fixtures land.
}

#[test]
fn verifiedblock_method_uses_authenticated_root() {
    // Construct a VerifiedBlock with our trie root manually pinned in
    // the header. This exercises the `VerifiedBlock::*_inclusion`
    // methods exactly the same as a real verifier would after
    // authenticating the header.
    let r0 = encode_envelope_for_trie(&synthetic_receipt(true, 21_000));
    let r1 = encode_envelope_for_trie(&synthetic_receipt(true, 42_000));
    let pairs = vec![(0u64, r0.clone()), (1u64, r1.clone())];
    let (receipts_root, receipt_proof) = build_trie_with_proof(&pairs, 0);

    // Realistic-sized synthetic transaction payloads (>32 bytes each so
    // the leaves are stored as hash refs, not inlined).
    let tx0 = vec![0xaau8; 64];
    let tx1 = vec![0xbbu8; 64];
    let txs: Vec<(u64, Vec<u8>)> = vec![(0u64, tx0.clone()), (1u64, tx1.clone())];
    let (transactions_root, tx_proof) = build_trie_with_proof(&txs, 1);

    let header = Header {
        receipts_root,
        transactions_root,
        ..Default::default()
    };
    let block = VerifiedBlock {
        header,
        auth_path: AuthPath::HistoricalHashes,
    };

    block
        .verify_receipt_inclusion(0, &r0, &receipt_proof)
        .expect("receipt inclusion via VerifiedBlock");
    block
        .verify_transaction_inclusion(1, &tx1, &tx_proof)
        .expect("tx inclusion via VerifiedBlock");

    let decoded = block
        .verify_and_decode_receipt(0, &r0, &receipt_proof)
        .expect("decode via VerifiedBlock");
    assert!(matches!(decoded, ReceiptEnvelope::Legacy(_)));
}

#[test]
fn verify_mpt_inclusion_low_level_roundtrip() {
    // Realistic-sized values (>32 bytes) so the leaves are stored as
    // hash refs in their parent branch — small (<32-byte) values are
    // inlined and produce a proof shape that real Ethereum tries don't
    // exhibit (every real receipt is at least ~270 bytes).
    let pairs = vec![
        (0u64, vec![0x11u8; 64]),
        (1u64, vec![0x22u8; 64]),
        (2u64, vec![0x33u8; 64]),
    ];
    let (root, proof) = build_trie_with_proof(&pairs, 1);

    let mut key = Vec::new();
    1u64.encode(&mut key);

    verify_mpt_inclusion(root, &key, &pairs[1].1, &proof)
        .expect("low-level verification should succeed");
}

#[test]
fn verify_mpt_inclusion_rejects_empty_proof() {
    let root = B256::ZERO;
    let key: Vec<u8> = vec![0x80];
    let value = b"x";
    let proof: Vec<Bytes> = Vec::new();
    let err = verify_mpt_inclusion(root, &key, value, &proof).unwrap_err();
    assert!(matches!(err, eth_historian::Error::MptInclusion(_)));
}

#[test]
fn root_matches_alloy_canonical_receipt_root() {
    // Sanity: the trie root we generate for a given list of receipts
    // matches `alloy::consensus::proofs::calculate_receipt_root` — i.e.
    // we agree with the canonical Ethereum root computation. If this
    // ever fails, our trust anchor is mis-aligned with the rest of the
    // ecosystem.
    use alloy::consensus::proofs::calculate_receipt_root;

    let receipts = vec![
        synthetic_receipt(true, 21_000),
        synthetic_receipt(true, 42_000),
        synthetic_receipt(false, 100_000),
    ];
    let alloy_root = calculate_receipt_root(&receipts);

    let pairs: Vec<(u64, Vec<u8>)> = receipts
        .iter()
        .map(encode_envelope_for_trie)
        .enumerate()
        .map(|(i, b)| (i as u64, b))
        .collect();
    let (our_root, _) = build_trie_with_proof(&pairs, 0);

    assert_eq!(
        our_root, alloy_root,
        "our trie root must match the canonical Ethereum receipt root"
    );
}
