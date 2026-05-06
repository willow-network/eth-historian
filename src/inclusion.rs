//! Verify inclusion of transactions, receipts, and logs in an authenticated
//! Ethereum block via Merkle Patricia Trie proofs.
//!
//! Once a block has been authenticated by [`crate::Verifier::verify`], its
//! `transactions_root` and `receipts_root` are trustworthy. This module
//! turns them into a usable trust anchor: given an MPT proof, you can
//! verify a specific transaction or receipt was actually in the block.
//!
//! # Trust model
//!
//! These helpers do **no** independent header verification — they bind a
//! `(key, value)` pair to a root you supply. Pair them with a
//! [`crate::VerifiedBlock`] (whose roots are authenticated via
//! eth-historian's canonized accumulators / `historical_summaries`) for
//! end-to-end trustless inclusion proofs.
//!
//! # Quick start
//!
//! ```no_run
//! # use eth_historian::{Verifier, sources::ArchiveRpcSource};
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let verifier = Verifier::builder()
//!     .data_source(ArchiveRpcSource::new("https://eth.llamarpc.com"))
//!     .build();
//!
//! let block = verifier.verify_block_by_number(10_000_835).await?;
//!
//! // Caller-supplied: receipt at index 3 in this block, plus its MPT proof.
//! let raw_receipt: Vec<u8> = fetch_raw_receipt();
//! let proof_nodes: Vec<Vec<u8>> = fetch_receipt_proof();
//!
//! block.verify_receipt_inclusion(3, &raw_receipt, &proof_nodes)?;
//! # Ok(())
//! # }
//! # fn fetch_raw_receipt() -> Vec<u8> { unimplemented!() }
//! # fn fetch_receipt_proof() -> Vec<Vec<u8>> { unimplemented!() }
//! ```

use alloy::consensus::ReceiptEnvelope;
use alloy::eips::eip2718::Decodable2718;
use alloy::primitives::{Bytes, B256};
use alloy_rlp::{Decodable, Encodable};
use alloy_trie::{proof::verify_proof, Nibbles};

use crate::errors::{Error, Result};

/// Verify a Merkle Patricia Trie proof that `value` is stored at `key`
/// under a trie whose root is `root`.
///
/// Low-level — most callers should use [`verify_transaction_inclusion`],
/// [`verify_receipt_inclusion`], or the convenience methods on
/// [`crate::VerifiedBlock`].
///
/// `key` is the raw key bytes (e.g. `rlp(tx_index)`); they're unpacked
/// into nibbles internally. `proof_nodes` is the ordered list of
/// RLP-encoded trie nodes from the root down to the leaf.
pub fn verify_mpt_inclusion(
    root: B256,
    key: &[u8],
    value: &[u8],
    proof_nodes: &[impl AsRef<[u8]>],
) -> Result<()> {
    if proof_nodes.is_empty() {
        return Err(Error::MptInclusion("empty proof".into()));
    }

    let nibbles = Nibbles::unpack(key);
    let proof_bytes: Vec<Bytes> = proof_nodes
        .iter()
        .map(|n| Bytes::copy_from_slice(n.as_ref()))
        .collect();

    verify_proof(root, nibbles, Some(value.to_vec()), proof_bytes.iter())
        .map_err(|e| Error::MptInclusion(e.to_string()))
}

/// Verify a transaction is in a block at the given index, against an
/// authenticated `transactions_root`.
///
/// `raw_tx` is the EIP-2718 wire-format bytes (legacy transactions are
/// just RLP; typed transactions have a 1-byte type prefix). They are
/// compared as-is to the trie value — this function does not decode the
/// transaction, that's a separate concern.
pub fn verify_transaction_inclusion(
    transactions_root: B256,
    tx_index: u64,
    raw_tx: &[u8],
    proof_nodes: &[impl AsRef<[u8]>],
) -> Result<()> {
    let key = rlp_encode_index(tx_index);
    verify_mpt_inclusion(transactions_root, &key, raw_tx, proof_nodes)
}

/// Verify a receipt is in a block at the given index, against an
/// authenticated `receipts_root`.
///
/// `raw_receipt` is the value as stored in the receipt trie. For typed
/// (EIP-2718) receipts that's `tx_type_byte || rlp(receipt)`; for legacy
/// receipts it's just `rlp(receipt)`.
pub fn verify_receipt_inclusion(
    receipts_root: B256,
    receipt_index: u64,
    raw_receipt: &[u8],
    proof_nodes: &[impl AsRef<[u8]>],
) -> Result<()> {
    let key = rlp_encode_index(receipt_index);
    verify_mpt_inclusion(receipts_root, &key, raw_receipt, proof_nodes)
}

/// Verify a receipt's inclusion and decode it into a typed
/// [`ReceiptEnvelope`] (handling legacy / EIP-2930 / EIP-1559 / EIP-4844
/// / EIP-7702 variants).
pub fn verify_and_decode_receipt(
    receipts_root: B256,
    receipt_index: u64,
    raw_receipt: &[u8],
    proof_nodes: &[impl AsRef<[u8]>],
) -> Result<ReceiptEnvelope> {
    verify_receipt_inclusion(receipts_root, receipt_index, raw_receipt, proof_nodes)?;
    decode_receipt(receipt_index, raw_receipt)
}

/// Decode a wire-format receipt (handles both legacy and EIP-2718 typed).
pub fn decode_receipt(receipt_index: u64, raw_receipt: &[u8]) -> Result<ReceiptEnvelope> {
    if raw_receipt.is_empty() {
        return Err(Error::ReceiptDecode {
            index: receipt_index,
            reason: "empty receipt bytes".into(),
        });
    }

    // EIP-2718: typed receipts start with a single-byte type tag in 0x00..0x7f.
    // Legacy receipts start with an RLP list header (0xc0..0xff).
    let mut buf: &[u8] = raw_receipt;
    if raw_receipt[0] >= 0x80 {
        // Legacy. ReceiptEnvelope::decode handles plain RLP.
        ReceiptEnvelope::decode(&mut buf).map_err(|e| Error::ReceiptDecode {
            index: receipt_index,
            reason: e.to_string(),
        })
    } else {
        // Typed. Decode2718 expects the type byte + payload.
        ReceiptEnvelope::decode_2718(&mut buf).map_err(|e| Error::ReceiptDecode {
            index: receipt_index,
            reason: e.to_string(),
        })
    }
}

// Ethereum trie keys for the transaction/receipt tries are RLP-encoded
// integer indexes (`rlp(tx_index)`). alloy-rlp's `Encodable` for `u64`
// produces the canonical RLP of a non-negative integer.
fn rlp_encode_index(index: u64) -> Vec<u8> {
    let mut out = Vec::new();
    index.encode(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_proof_rejected() {
        let root = B256::ZERO;
        let key = rlp_encode_index(0);
        let value = b"anything";
        let proof: Vec<Vec<u8>> = Vec::new();
        let err = verify_mpt_inclusion(root, &key, value, &proof).unwrap_err();
        assert!(matches!(err, Error::MptInclusion(_)));
    }

    #[test]
    fn rlp_encode_index_matches_alloy() {
        // Sanity: `rlp(0)` is `0x80` (empty string), `rlp(1)` is `0x01`.
        // These are canonical Ethereum trie keys for the first two indices.
        assert_eq!(rlp_encode_index(0), vec![0x80]);
        assert_eq!(rlp_encode_index(1), vec![0x01]);
        assert_eq!(rlp_encode_index(127), vec![0x7f]);
        assert_eq!(rlp_encode_index(128), vec![0x81, 0x80]);
    }

    #[test]
    fn decode_receipt_rejects_empty() {
        let err = decode_receipt(0, &[]).unwrap_err();
        assert!(matches!(err, Error::ReceiptDecode { index: 0, .. }));
    }
}
