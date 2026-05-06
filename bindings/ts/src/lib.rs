//! WebAssembly bindings for eth-historian.
//!
//! Exposes a single async function `verify_header_with_proof(bytes)` that
//! takes SSZ-encoded `HeaderWithProof` bytes (e.g. fetched from a Portal
//! sidecar or Era1 file in JS) and returns a `VerifiedBlock`-shaped JS
//! object on success, or throws a `VerificationError` on failure.
//!
//! All trust-critical work — SHA-256 fingerprint check, accumulator
//! tree-hash assertion, SSZ decode, Merkle proof verification — happens
//! inside the wasm module. The JS caller is responsible for fetching the
//! bytes only; it is not trusted to verify them.

use eth_historian::{HeaderWithProof, Verifier};
use serde::Serialize;
use ssz::Decode;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn _wasm_init() {
    console_error_panic_hook::set_once();
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedBlockJs {
    block_number: u64,
    block_hash: String,
    state_root: String,
    receipts_root: String,
    transactions_root: String,
    parent_hash: String,
    timestamp: u64,
    auth_path: String,
}

/// Verify a SSZ-encoded `HeaderWithProof` byte payload.
///
/// On success, returns a JS object: `{ blockNumber, blockHash,
/// stateRoot, receiptsRoot, transactionsRoot, parentHash, timestamp,
/// authPath }`. All hashes are hex-encoded with `0x` prefix.
///
/// On failure, throws an `Error` with a human-readable message.
#[wasm_bindgen(js_name = verifyHeaderWithProof)]
pub async fn verify_header_with_proof(bytes: Vec<u8>) -> Result<JsValue, JsError> {
    // Verifier construction asserts the canonized accumulator
    // fingerprints; if our wasm bundle was tampered with mid-flight, this
    // panics here.
    let verifier = Verifier::new();

    let hwp = HeaderWithProof::from_ssz_bytes(&bytes)
        .map_err(|e| JsError::new(&format!("SSZ decode failed: {:?}", e)))?;

    let verified = verifier
        .verify(&hwp)
        .await
        .map_err(|e| JsError::new(&format!("verification failed: {}", e)))?;

    let h = &verified.header;
    let out = VerifiedBlockJs {
        block_number: h.number,
        block_hash: format!("0x{}", hex::encode(h.hash_slow().as_slice())),
        state_root: format!("0x{}", hex::encode(h.state_root.as_slice())),
        receipts_root: format!("0x{}", hex::encode(h.receipts_root.as_slice())),
        transactions_root: format!("0x{}", hex::encode(h.transactions_root.as_slice())),
        parent_hash: format!("0x{}", hex::encode(h.parent_hash.as_slice())),
        timestamp: h.timestamp,
        auth_path: format!("{:?}", verified.auth_path),
    };

    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsError::new(&format!("serialization failed: {}", e)))
}

/// Verify a transaction is in a block at the given index, against an
/// authenticated `transactionsRoot`.
///
/// Inputs:
/// * `transactionsRoot` — 32-byte authenticated root from a `VerifiedBlock`.
/// * `txIndex` — position of the transaction in the block.
/// * `rawTx` — EIP-2718 wire-format bytes (legacy: RLP; typed: type-byte || RLP).
/// * `proofNodes` — RLP-encoded MPT trie nodes from root down to the leaf,
///   passed as a JS array of `Uint8Array`.
///
/// Throws on verification failure.
#[wasm_bindgen(js_name = verifyTransactionInclusion)]
pub fn verify_transaction_inclusion(
    transactions_root: Vec<u8>,
    tx_index: u64,
    raw_tx: Vec<u8>,
    proof_nodes: js_sys::Array,
) -> Result<(), JsError> {
    let root = parse_root(&transactions_root, "transactionsRoot")?;
    let proof = parse_proof_nodes(&proof_nodes)?;
    eth_historian::inclusion::verify_transaction_inclusion(root, tx_index, &raw_tx, &proof)
        .map_err(|e| JsError::new(&format!("verifyTransactionInclusion: {}", e)))
}

/// Verify a receipt is in a block at the given index, against an
/// authenticated `receiptsRoot`.
///
/// Inputs match [`verifyTransactionInclusion`] except the value is the
/// receipt's wire-format bytes (legacy: RLP; typed: type-byte || RLP).
///
/// Throws on verification failure.
#[wasm_bindgen(js_name = verifyReceiptInclusion)]
pub fn verify_receipt_inclusion(
    receipts_root: Vec<u8>,
    receipt_index: u64,
    raw_receipt: Vec<u8>,
    proof_nodes: js_sys::Array,
) -> Result<(), JsError> {
    let root = parse_root(&receipts_root, "receiptsRoot")?;
    let proof = parse_proof_nodes(&proof_nodes)?;
    eth_historian::inclusion::verify_receipt_inclusion(root, receipt_index, &raw_receipt, &proof)
        .map_err(|e| JsError::new(&format!("verifyReceiptInclusion: {}", e)))
}

fn parse_root(bytes: &[u8], field: &str) -> Result<alloy_primitives::B256, JsError> {
    if bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "{} must be 32 bytes, got {}",
            field,
            bytes.len()
        )));
    }
    Ok(alloy_primitives::B256::from_slice(bytes))
}

fn parse_proof_nodes(array: &js_sys::Array) -> Result<Vec<Vec<u8>>, JsError> {
    let mut out = Vec::with_capacity(array.length() as usize);
    for value in array.iter() {
        let bytes = js_sys::Uint8Array::new(&value).to_vec();
        out.push(bytes);
    }
    Ok(out)
}

/// Returns the SHA-256 fingerprints of the embedded canonized accumulator
/// binaries, as hex-encoded strings. Useful for clients that want to
/// double-check the wasm bundle they loaded ships the constants they
/// expect.
#[wasm_bindgen(js_name = canonizedFingerprints)]
pub fn canonized_fingerprints() -> JsValue {
    use eth_historian::constants::{HISTORICAL_ROOTS_SSZ_SHA256, MERGE_MACC_BIN_SHA256};

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Fingerprints {
        merge_macc_bin_sha256: String,
        historical_roots_ssz_sha256: String,
    }

    let fp = Fingerprints {
        merge_macc_bin_sha256: format!("0x{}", hex::encode(MERGE_MACC_BIN_SHA256)),
        historical_roots_ssz_sha256: format!("0x{}", hex::encode(HISTORICAL_ROOTS_SSZ_SHA256)),
    };

    serde_wasm_bindgen::to_value(&fp).unwrap()
}
