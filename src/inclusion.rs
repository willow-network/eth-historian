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

use alloy::consensus::{Receipt, ReceiptEnvelope, ReceiptWithBloom};
use alloy::eips::eip2718::{Decodable2718, Encodable2718};
use alloy::primitives::{Bytes, Log, B256};
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

/// Arbitrum-family (Nitro / Orbit) EIP-2718 receipt types, inclusive range:
/// 0x64 ArbitrumDeposit · 0x65 ArbitrumUnsigned · 0x66 ArbitrumContract ·
/// 0x67 ArbitrumLegacy · 0x68 ArbitrumRetry · 0x69 ArbitrumSubmitRetryable ·
/// 0x6A ArbitrumInternal (every Nitro block's receipt 0). Their receipt body
/// is the standard 4-field `[status, cumulativeGasUsed, logsBloom, logs]`
/// behind the type byte; only the tag is chain-specific.
pub const ARBITRUM_TX_TYPE_MIN: u8 = 0x64;
/// See [`ARBITRUM_TX_TYPE_MIN`].
pub const ARBITRUM_TX_TYPE_MAX: u8 = 0x6A;

/// A decoded wire-format receipt.
///
/// Ethereum receipts (legacy and EIP-2718 types 0x01..=0x04) decode into
/// alloy's [`ReceiptEnvelope`]. Arbitrum-family receipts (types
/// [`ARBITRUM_TX_TYPE_MIN`]..=[`ARBITRUM_TX_TYPE_MAX`]) have no alloy
/// envelope variant, and are carried with their REAL type byte rather than
/// smuggled through a body-identical Ethereum variant: a caller that asks
/// [`DecodedReceipt::tx_type`] or re-encodes with
/// [`DecodedReceipt::to_wire_bytes`] gets the truth, byte for byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedReceipt {
    /// Legacy or EIP-2718 type 0x01..=0x04.
    Ethereum(ReceiptEnvelope),
    /// EIP-2718 type 0x64..=0x6A (Arbitrum Nitro / Orbit chains).
    Arbitrum {
        /// The wire type byte, 0x64..=0x6A.
        tx_type: u8,
        /// The 4-field receipt body.
        receipt: ReceiptWithBloom<Receipt<Log>>,
    },
}

impl DecodedReceipt {
    /// The receipt's logs, in emission order.
    pub fn logs(&self) -> &[Log] {
        match self {
            Self::Ethereum(env) => env.logs(),
            Self::Arbitrum { receipt, .. } => &receipt.receipt.logs,
        }
    }

    /// The EIP-2718 type byte (`0x00` for legacy).
    pub fn tx_type(&self) -> u8 {
        match self {
            Self::Ethereum(env) => env.tx_type() as u8,
            Self::Arbitrum { tx_type, .. } => *tx_type,
        }
    }

    /// Cumulative gas used, from the receipt body.
    pub fn cumulative_gas_used(&self) -> u64 {
        match self {
            Self::Ethereum(env) => env.cumulative_gas_used(),
            Self::Arbitrum { receipt, .. } => receipt.receipt.cumulative_gas_used,
        }
    }

    /// The alloy envelope, for Ethereum receipts only.
    pub fn as_envelope(&self) -> Option<&ReceiptEnvelope> {
        match self {
            Self::Ethereum(env) => Some(env),
            Self::Arbitrum { .. } => None,
        }
    }

    /// Re-encode to the exact wire bytes the receipts trie hashes
    /// (`type || rlp(body)` for typed, `rlp(body)` for legacy). Round-trips
    /// [`decode_receipt`] byte for byte for every admitted type.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ethereum(env) => env.encoded_2718(),
            Self::Arbitrum { tx_type, receipt } => {
                let mut out = vec![*tx_type];
                receipt.encode(&mut out);
                out
            }
        }
    }
}

/// Verify a receipt's inclusion and decode it into a typed
/// [`DecodedReceipt`] (legacy / EIP-2930 / EIP-1559 / EIP-4844 / EIP-7702
/// Ethereum receipts, and Arbitrum-family 0x64..=0x6A receipts).
pub fn verify_and_decode_receipt(
    receipts_root: B256,
    receipt_index: u64,
    raw_receipt: &[u8],
    proof_nodes: &[impl AsRef<[u8]>],
) -> Result<DecodedReceipt> {
    verify_receipt_inclusion(receipts_root, receipt_index, raw_receipt, proof_nodes)?;
    decode_receipt(receipt_index, raw_receipt)
}

/// Decode a wire-format receipt: legacy, EIP-2718 typed 0x01..=0x04, or
/// Arbitrum-family 0x64..=0x6A. Any other type tag in 0x00..=0x7f is refused
/// with [`Error::ReceiptDecode`] naming the tag — never guessed.
pub fn decode_receipt(receipt_index: u64, raw_receipt: &[u8]) -> Result<DecodedReceipt> {
    if raw_receipt.is_empty() {
        return Err(Error::ReceiptDecode {
            index: receipt_index,
            reason: "empty receipt bytes".into(),
        });
    }
    let decode_err = |reason: String| Error::ReceiptDecode {
        index: receipt_index,
        reason,
    };

    // EIP-2718: typed receipts start with a single-byte type tag in 0x00..0x7f.
    // Legacy receipts start with an RLP list header (0xc0..0xff).
    let mut buf: &[u8] = raw_receipt;
    match raw_receipt[0] {
        // Legacy. ReceiptEnvelope::decode handles plain RLP.
        0x80..=0xff => ReceiptEnvelope::decode(&mut buf)
            .map(DecodedReceipt::Ethereum)
            .map_err(|e| decode_err(e.to_string())),
        // Arbitrum-family: the standard 4-field body behind the type byte.
        tx_type @ ARBITRUM_TX_TYPE_MIN..=ARBITRUM_TX_TYPE_MAX => {
            let mut body: &[u8] = &raw_receipt[1..];
            let receipt: ReceiptWithBloom<Receipt<Log>> = Decodable::decode(&mut body)
                .map_err(|e| decode_err(format!("arbitrum type 0x{tx_type:02x}: {e}")))?;
            if !body.is_empty() {
                return Err(decode_err(format!(
                    "arbitrum type 0x{tx_type:02x}: {} trailing bytes after the receipt body",
                    body.len()
                )));
            }
            Ok(DecodedReceipt::Arbitrum { tx_type, receipt })
        }
        // Typed Ethereum. Decode2718 expects the type byte + payload.
        0x00..=0x04 => ReceiptEnvelope::decode_2718(&mut buf)
            .map(DecodedReceipt::Ethereum)
            .map_err(|e| decode_err(e.to_string())),
        other => Err(decode_err(format!(
            "unsupported EIP-2718 receipt type 0x{other:02x} \
             (admitted: 0x00-0x04 Ethereum, 0x64-0x6a Arbitrum)"
        ))),
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
