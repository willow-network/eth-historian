//! Arbitrum-family (Orbit) receipts: three REAL receipts from Robinhood Chain
//! (chainId 4663, Arbitrum Nitro) block 69,562,157 — the block's whole receipt
//! set: 0x6a ArbitrumInternal (the ArbOS block-opening tx), 0x69
//! ArbitrumSubmitRetryable, 0x68 ArbitrumRetry. Fetched 2026-09-22 from
//! `https://robinhood-rpc.publicnode.com` (`eth_getBlockReceipts`) and encoded
//! with the standard consensus form `type || rlp([status, cumulativeGasUsed,
//! logsBloom, logs])`. The block header's `receiptsRoot` is
//! `0x262094c8f2fcff7ad0a63165e288b658adf2d702381b483c1fcde5fa4c45e987`, which
//! the ordered trie over these three values reproduces — so these are the exact
//! bytes the chain committed.

use alloy::primitives::B256;
use eth_historian::inclusion::{
    decode_receipt, verify_and_decode_receipt, DecodedReceipt, ARBITRUM_TX_TYPE_MAX,
    ARBITRUM_TX_TYPE_MIN,
};

const RECEIPTS_ROOT: &str = "262094c8f2fcff7ad0a63165e288b658adf2d702381b483c1fcde5fa4c45e987";

/// (type, wire hex) in tx_index order.
const RECEIPTS: [(u8, &str); 3] = [
    (0x6a, "6af901060180b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0"),
    (0x69, "69f9028601826b77b9010000004000000000000000000000008000800000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000010000000000020000000000000000000000000000000000000000000000000000000020000200000000000000800000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000080000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000029000000000000000000000000200000000000002000000000000000000000000000f9017cf85a94000000000000000000000000000000000000006ef842a07c793cced5743dc5f531bbe2bfb5a9fa3f40adef29231e6ab165c08a29e3dd89a096e542d4dd3a38ca2043ce78033631a2323d07aaa539e006018ec47171f1093580f9011d94000000000000000000000000000000000000006ef884a05ccd009502509cf28762c67858994d85b163bb6e451f5e9df7c5e18c9c2e123ea096e542d4dd3a38ca2043ce78033631a2323d07aaa539e006018ec47171f10935a01b864de6e972b8f022b498f6a069f690bab8aec1041ab952ff67fbbb8edb7ea7a00000000000000000000000000000000000000000000000000000000000000000b8800000000000000000000000000000000000000000000000000000000000006b7700000000000000000000000076ea0c0e54e5bb874a104e66be34cfa2418715010000000000000000000000000000000000000000000000000000016ffda3a3180000000000000000000000000000000000000000000000000000001b7e08bf08"),
    (0x68, "68f901080182bd7fb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0"),
];

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn values() -> Vec<Vec<u8>> {
    RECEIPTS.iter().map(|(_, h)| unhex(h)).collect()
}

#[test]
fn the_three_receipts_are_the_block_receipts_root() {
    let root = alloy_trie::root::ordered_trie_root_encoded(&values());
    assert_eq!(root, B256::from_slice(&unhex(RECEIPTS_ROOT)));
}

#[test]
fn arbitrum_receipts_decode_with_their_real_type_and_round_trip_byte_for_byte() {
    let expected_logs = [0usize, 2, 0];
    for (i, ((ty, _), raw)) in RECEIPTS.iter().zip(values()).enumerate() {
        assert!((ARBITRUM_TX_TYPE_MIN..=ARBITRUM_TX_TYPE_MAX).contains(ty));
        let decoded = decode_receipt(i as u64, &raw).expect("real Orbit receipt decodes");
        assert_eq!(
            decoded.tx_type(),
            *ty,
            "receipt {i}: the REAL type byte, not a stand-in"
        );
        assert!(
            decoded.as_envelope().is_none(),
            "receipt {i}: not smuggled through an Ethereum variant"
        );
        assert_eq!(
            decoded.logs().len(),
            expected_logs[i],
            "receipt {i}: log count"
        );
        assert_eq!(
            decoded.to_wire_bytes(),
            raw,
            "receipt {i}: re-encode is the exact wire bytes"
        );
        match decoded {
            DecodedReceipt::Arbitrum {
                tx_type,
                ref receipt,
            } => {
                assert_eq!(tx_type, *ty);
                assert!(receipt.receipt.status.coerce_status());
            }
            DecodedReceipt::Ethereum(_) | DecodedReceipt::OpDeposit { .. } => {
                panic!("receipt {i}: must be the Arbitrum variant")
            }
        }
    }
    // The SubmitRetryable's two logs come from the ArbRetryableTx precompile (0x…6e).
    let sub = decode_receipt(1, &values()[1]).unwrap();
    for log in sub.logs() {
        assert_eq!(log.address.as_slice()[19], 0x6e);
        assert_eq!(log.address.as_slice()[..19], [0u8; 19]);
    }
    assert_eq!(sub.cumulative_gas_used(), 0x6b77);
}

#[test]
fn arbitrum_receipts_verify_inclusion_against_the_real_root() {
    // Build the block's receipts trie and a proof for each receipt, the same way
    // the crate's own inclusion tests do, then verify + decode through the
    // public API.
    use alloy_rlp::Encodable;
    use alloy_trie::{hash_builder::HashBuilder, proof::ProofRetainer, Nibbles};

    let vals = values();
    let root = B256::from_slice(&unhex(RECEIPTS_ROOT));
    for target in 0..vals.len() {
        let mut keyed: Vec<(Nibbles, Vec<u8>)> = vals
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let mut k = Vec::new();
                (i as u64).encode(&mut k);
                (Nibbles::unpack(&k), v.clone())
            })
            .collect();
        keyed.sort_by_key(|(k, _)| *k);
        let mut tk = Vec::new();
        (target as u64).encode(&mut tk);
        let retainer = ProofRetainer::new(vec![Nibbles::unpack(&tk)]);
        let mut hb = HashBuilder::default().with_proof_retainer(retainer);
        for (k, v) in &keyed {
            hb.add_leaf(*k, v);
        }
        let got_root = hb.root();
        assert_eq!(got_root, root, "trie root over the three receipts");
        let proof: Vec<Vec<u8>> = hb
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, n)| n.to_vec())
            .collect();
        let decoded = verify_and_decode_receipt(root, target as u64, &vals[target], &proof)
            .expect("inclusion + decode of a real Orbit receipt");
        assert_eq!(decoded.tx_type(), RECEIPTS[target].0);
    }
}

#[test]
fn unknown_types_and_trailing_bytes_are_refused_by_name() {
    let raw = values()[0].clone();
    // 0x7e is the OP-stack deposit type, admitted since the OP-deposit arm (a 4-field body
    // behind it decodes as a pre-Canyon deposit), so it is no longer in the refused set.
    for bad in [0x05u8, 0x63, 0x6b, 0x70, 0x7f] {
        let mut v = raw.clone();
        v[0] = bad;
        let e = decode_receipt(0, &v)
            .expect_err("must be refused")
            .to_string();
        assert!(
            e.contains(&format!("unsupported EIP-2718 receipt type 0x{bad:02x}")),
            "0x{bad:02x}: {e}"
        );
    }
    let mut long = raw;
    long.push(0x00);
    let e = decode_receipt(0, &long)
        .expect_err("trailing byte")
        .to_string();
    assert!(e.contains("trailing bytes"), "{e}");
}
