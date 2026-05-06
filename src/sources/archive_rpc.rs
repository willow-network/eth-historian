//! Archive RPC source — fetch raw headers from any Ethereum execution
//! JSON-RPC, then construct the canonized accumulator proof locally.
//!
//! Removes the runtime dependency on Portal Network at the cost of
//! requiring the caller to supply `EpochAccumulator` blobs for the
//! pre-merge era. Workflow:
//!
//! 1. RPC call: `eth_getBlockByNumber(N, false)` returns the raw block
//!    header.
//! 2. Caller (or an [`EpochProvider`] impl) supplies the
//!    `EpochAccumulator` covering block N.
//! 3. We construct a `BlockProofHistoricalHashesAccumulator` via
//!    [`crate::proof_construction`] and assemble a `HeaderWithProof`.
//! 4. We SSZ-encode and return — the verifier then decodes and verifies
//!    against the canonized constant.
//!
//! Trust: the RPC is **not** trusted. Any header it returns is
//! authenticated against the canonized accumulator before being
//! accepted. A lying RPC just produces a header whose proof construction
//! fails (block_hash mismatch in the epoch accumulator) or that fails
//! the merkle proof check.
//!
//! Supports both pre-merge and post-merge eras:
//!
//! * Pre-merge (blocks 0..15,537,393): construct
//!   `BlockProofHistoricalHashesAccumulator` from an `EpochProvider`.
//! * Post-merge (Bellatrix → Electra): construct the appropriate
//!   `BlockProof*` variant from a [`crate::sources::BeaconDataProvider`]
//!   that fetches the relevant `SignedBeaconBlock` + `HistoricalBatch`.
//!   The default beacon provider talks the standard Ethereum
//!   beacon-API; operators provide a beacon node URL to enable this
//!   path.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use ssz::Encode;

use crate::{
    errors::{Error, Result},
    portal_types::{
        build_capella_historical_summaries_proof, build_deneb_historical_summaries_proof,
        build_electra_historical_summaries_proof, build_historical_roots_proof,
        consensus::beacon_block::SignedBeaconBlock, network_spec::slot_for_execution_timestamp,
        BlockHeaderProof, EpochAccumulator, HeaderWithProof,
    },
    proof_construction::{
        construct_pre_merge_proof, decode_epoch_accumulator, epoch_index_of_block,
    },
    sources::{beacon_rpc::BeaconDataProvider, DataSource},
};

/// Provides the `EpochAccumulator` covering a given block number. Implement
/// this to plug in your own epoch-data storage (filesystem, IPFS, S3,
/// HTTP, in-memory cache, etc.).
#[async_trait]
pub trait EpochProvider: Send + Sync {
    async fn get_epoch_accumulator(&self, epoch_index: u64) -> Result<EpochAccumulator>;
}

/// Reads `EpochAccumulator` blobs from a local filesystem directory.
///
/// Expected filename convention: `0x{epoch_root}.bin` (matches trin's
/// `crates/validation/src/assets/epoch_accs/` layout). The directory may
/// optionally also be indexed by `epoch_{index}.bin` filenames.
pub struct FilesystemEpochProvider {
    root: std::path::PathBuf,
}

impl FilesystemEpochProvider {
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

#[async_trait]
impl EpochProvider for FilesystemEpochProvider {
    async fn get_epoch_accumulator(&self, epoch_index: u64) -> Result<EpochAccumulator> {
        let candidate = self.root.join(format!("epoch_{}.bin", epoch_index));
        let bytes = std::fs::read(&candidate).map_err(|e| {
            Error::DataSource(format!(
                "no EpochAccumulator at {}: {}",
                candidate.display(),
                e
            ))
        })?;
        decode_epoch_accumulator(&bytes)
    }
}

/// Reads raw headers from an Ethereum execution-layer JSON-RPC and
/// constructs proofs locally. Constructed via
/// [`ArchiveRpcSource::new`].
pub struct ArchiveRpcSource {
    rpc_url: String,
    http: reqwest::Client,
    epoch_provider: Option<Arc<dyn EpochProvider>>,
    beacon_provider: Option<Arc<dyn BeaconDataProvider>>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct RawBlock {
    number: String,
    // Returned by `eth_getBlockByNumber`; not currently consumed (we
    // recompute via `header.hash_slow()` after parsing) but kept here so
    // the deserializer accepts the full RPC response shape.
    #[allow(dead_code)]
    hash: String,
    #[serde(rename = "parentHash")]
    parent_hash: String,
    #[serde(rename = "sha3Uncles")]
    uncles_hash: String,
    miner: String,
    #[serde(rename = "stateRoot")]
    state_root: String,
    #[serde(rename = "transactionsRoot")]
    transactions_root: String,
    #[serde(rename = "receiptsRoot")]
    receipts_root: String,
    #[serde(rename = "logsBloom")]
    logs_bloom: String,
    difficulty: String,
    #[serde(rename = "gasLimit")]
    gas_limit: String,
    #[serde(rename = "gasUsed")]
    gas_used: String,
    timestamp: String,
    #[serde(rename = "extraData")]
    extra_data: String,
    #[serde(rename = "mixHash")]
    mix_hash: String,
    nonce: String,
    #[serde(default, rename = "baseFeePerGas")]
    base_fee_per_gas: Option<String>,
    #[serde(default, rename = "withdrawalsRoot")]
    withdrawals_root: Option<String>,
    #[serde(default, rename = "blobGasUsed")]
    blob_gas_used: Option<String>,
    #[serde(default, rename = "excessBlobGas")]
    excess_blob_gas: Option<String>,
    #[serde(default, rename = "parentBeaconBlockRoot")]
    parent_beacon_block_root: Option<String>,
}

impl ArchiveRpcSource {
    /// Construct a source pointing at `rpc_url`. Without an epoch
    /// provider configured pre-merge blocks fail; without a beacon
    /// provider configured post-merge blocks fail. Most production setups
    /// chain both — call [`Self::with_epoch_provider`] and
    /// [`Self::with_beacon_provider`] before passing the source to a
    /// [`crate::Verifier`].
    pub fn new(rpc_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest::Client::builder default config should not fail");
        Self {
            rpc_url: rpc_url.into(),
            http,
            epoch_provider: None,
            beacon_provider: None,
        }
    }

    /// Attach an [`EpochProvider`] for pre-merge proof construction.
    pub fn with_epoch_provider<P: EpochProvider + 'static>(mut self, provider: P) -> Self {
        self.epoch_provider = Some(Arc::new(provider));
        self
    }

    /// Attach a [`BeaconDataProvider`] for post-merge proof construction.
    /// Without this, post-merge blocks return an error when fetched
    /// (caller should use a different source for those blocks, e.g.
    /// `PortalSidecarSource` or `Era1FileSource`).
    pub fn with_beacon_provider<P: BeaconDataProvider + 'static>(mut self, provider: P) -> Self {
        self.beacon_provider = Some(Arc::new(provider));
        self
    }

    /// Construct a post-merge `HeaderWithProof`. Fetches a beacon block +
    /// historical batch via the configured `BeaconDataProvider`, then
    /// dispatches on the consensus fork to pick the right proof shape.
    async fn build_post_merge_hwp(&self, header: alloy::consensus::Header) -> Result<Vec<u8>> {
        let provider = self.beacon_provider.as_ref().ok_or_else(|| {
            Error::DataSource(
                "ArchiveRpcSource: post-merge block requested but no BeaconDataProvider configured. Call .with_beacon_provider(..)".into(),
            )
        })?;

        let slot = slot_for_execution_timestamp(header.timestamp).ok_or_else(|| {
            Error::DataSource(format!(
                "post-merge block {} has timestamp {} before beacon genesis (mainnet only is supported)",
                header.number, header.timestamp
            ))
        })?;

        let signed_block = provider.fetch_signed_beacon_block(slot).await?;
        let historical_batch = provider.fetch_historical_batch(slot).await?;

        let proof = match signed_block {
            SignedBeaconBlock::Bellatrix(b) => BlockHeaderProof::HistoricalRoots(
                build_historical_roots_proof(slot, &historical_batch, &b.message),
            ),
            SignedBeaconBlock::Capella(b) => BlockHeaderProof::HistoricalSummariesCapella(
                build_capella_historical_summaries_proof(
                    slot,
                    &historical_batch.block_roots,
                    &b.message,
                ),
            ),
            SignedBeaconBlock::Deneb(b) => {
                BlockHeaderProof::HistoricalSummariesDeneb(build_deneb_historical_summaries_proof(
                    slot,
                    &historical_batch.block_roots,
                    &b.message,
                ))
            }
            SignedBeaconBlock::Electra(b) => BlockHeaderProof::HistoricalSummariesDeneb(
                build_electra_historical_summaries_proof(
                    slot,
                    &historical_batch.block_roots,
                    &b.message,
                ),
            ),
        };

        let hwp = HeaderWithProof { header, proof };
        Ok(hwp.as_ssz_bytes())
    }

    async fn fetch_raw_block_by_number(&self, block_number: u64) -> Result<RawBlock> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBlockByNumber",
            "params": [format!("0x{:x}", block_number), false],
        });

        let response = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        let parsed: JsonRpcResponse<RawBlock> = response.json().await?;

        if let Some(err) = parsed.error {
            return Err(Error::DataSource(format!(
                "RPC eth_getBlockByNumber error {}: {}",
                err.code, err.message
            )));
        }

        parsed.result.ok_or(Error::BlockNotFound(block_number))
    }
}

#[async_trait]
impl DataSource for ArchiveRpcSource {
    async fn fetch_header_with_proof_by_number(&self, block_number: u64) -> Result<Vec<u8>> {
        let raw = self.fetch_raw_block_by_number(block_number).await?;
        let header = raw_block_to_alloy_header(&raw)?;

        if header.number >= 15_537_394 {
            return self.build_post_merge_hwp(header).await;
        }

        let provider = self.epoch_provider.as_ref().ok_or_else(|| {
            Error::DataSource(
                "ArchiveRpcSource: pre-merge block requested but no EpochProvider configured. Call .with_epoch_provider(..)".into(),
            )
        })?;

        let epoch_index = epoch_index_of_block(header.number);
        let epoch_acc = provider.get_epoch_accumulator(epoch_index).await?;

        let proof = construct_pre_merge_proof(&header, &epoch_acc)?;
        let hwp = HeaderWithProof {
            header,
            proof: BlockHeaderProof::HistoricalHashes(proof),
        };
        Ok(hwp.as_ssz_bytes())
    }

    async fn fetch_header_with_proof_by_hash(&self, _block_hash: [u8; 32]) -> Result<Vec<u8>> {
        Err(Error::DataSource(
            "ArchiveRpcSource: lookup by hash not implemented (use eth_getBlockByHash if added)"
                .into(),
        ))
    }

    fn name(&self) -> &'static str {
        "archive-rpc"
    }
}

fn raw_block_to_alloy_header(raw: &RawBlock) -> Result<alloy::consensus::Header> {
    use alloy::primitives::{Address, Bloom, Bytes, B256, B64, U256};

    fn parse_b256(s: &str, field: &str) -> Result<B256> {
        let trimmed = s.trim_start_matches("0x");
        let bytes = hex::decode(trimmed)?;
        if bytes.len() != 32 {
            return Err(Error::DataSource(format!(
                "expected 32-byte hex for {}, got {} bytes",
                field,
                bytes.len()
            )));
        }
        Ok(B256::from_slice(&bytes))
    }

    fn parse_u64(s: &str, field: &str) -> Result<u64> {
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| Error::DataSource(format!("parsing u64 for {}: {}", field, e)))
    }

    fn parse_u256(s: &str) -> Result<U256> {
        let trimmed = s.trim_start_matches("0x");
        // U256 expects big-endian hex; if the string is empty or "0", default to zero.
        if trimmed.is_empty() {
            return Ok(U256::ZERO);
        }
        // Pad to multiple of 2 so hex::decode succeeds.
        let padded = if trimmed.len() % 2 == 1 {
            format!("0{}", trimmed)
        } else {
            trimmed.to_string()
        };
        let mut bytes = vec![0u8; 32];
        let raw = hex::decode(&padded)?;
        let offset = 32 - raw.len();
        bytes[offset..].copy_from_slice(&raw);
        Ok(U256::from_be_bytes::<32>(
            bytes.try_into().expect("bytes is len 32"),
        ))
    }

    fn parse_addr(s: &str) -> Result<Address> {
        let trimmed = s.trim_start_matches("0x");
        let bytes = hex::decode(trimmed)?;
        if bytes.len() != 20 {
            return Err(Error::DataSource(format!(
                "expected 20-byte hex for address, got {} bytes",
                bytes.len()
            )));
        }
        Ok(Address::from_slice(&bytes))
    }

    fn parse_bytes(s: &str) -> Result<Bytes> {
        Ok(Bytes::from(hex::decode(s.trim_start_matches("0x"))?))
    }

    fn parse_bloom(s: &str) -> Result<Bloom> {
        let trimmed = s.trim_start_matches("0x");
        let raw = hex::decode(trimmed)?;
        if raw.len() != 256 {
            return Err(Error::DataSource(format!(
                "expected 256-byte hex for logs_bloom, got {} bytes",
                raw.len()
            )));
        }
        let mut arr = [0u8; 256];
        arr.copy_from_slice(&raw);
        Ok(Bloom::from(arr))
    }

    fn parse_b64(s: &str) -> Result<B64> {
        let trimmed = s.trim_start_matches("0x");
        let raw = hex::decode(trimmed)?;
        if raw.len() != 8 {
            return Err(Error::DataSource(format!(
                "expected 8-byte hex for nonce, got {} bytes",
                raw.len()
            )));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&raw);
        Ok(B64::from(arr))
    }

    Ok(alloy::consensus::Header {
        parent_hash: parse_b256(&raw.parent_hash, "parent_hash")?,
        ommers_hash: parse_b256(&raw.uncles_hash, "uncles_hash")?,
        beneficiary: parse_addr(&raw.miner)?,
        state_root: parse_b256(&raw.state_root, "state_root")?,
        transactions_root: parse_b256(&raw.transactions_root, "transactions_root")?,
        receipts_root: parse_b256(&raw.receipts_root, "receipts_root")?,
        logs_bloom: parse_bloom(&raw.logs_bloom)?,
        difficulty: parse_u256(&raw.difficulty)?,
        number: parse_u64(&raw.number, "number")?,
        gas_limit: parse_u64(&raw.gas_limit, "gas_limit")?,
        gas_used: parse_u64(&raw.gas_used, "gas_used")?,
        timestamp: parse_u64(&raw.timestamp, "timestamp")?,
        extra_data: parse_bytes(&raw.extra_data)?,
        mix_hash: parse_b256(&raw.mix_hash, "mix_hash")?,
        nonce: parse_b64(&raw.nonce)?,
        base_fee_per_gas: raw
            .base_fee_per_gas
            .as_deref()
            .map(|s| parse_u64(s, "base_fee_per_gas"))
            .transpose()?,
        withdrawals_root: raw
            .withdrawals_root
            .as_deref()
            .map(|s| parse_b256(s, "withdrawals_root"))
            .transpose()?,
        blob_gas_used: raw
            .blob_gas_used
            .as_deref()
            .map(|s| parse_u64(s, "blob_gas_used"))
            .transpose()?,
        excess_blob_gas: raw
            .excess_blob_gas
            .as_deref()
            .map(|s| parse_u64(s, "excess_blob_gas"))
            .transpose()?,
        parent_beacon_block_root: raw
            .parent_beacon_block_root
            .as_deref()
            .map(|s| parse_b256(s, "parent_beacon_block_root"))
            .transpose()?,
        ..Default::default()
    })
}
