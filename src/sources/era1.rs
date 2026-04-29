//! Era1 file source — read SSZ-encoded `HeaderWithProof` content from
//! local Era1 files.
//!
//! Era1 is the standard offline-distribution format for pre-merge
//! Ethereum history. Each file covers ~8192 blocks (one historical
//! epoch) and bundles compressed headers, bodies, receipts, and an
//! accumulator proof per block.
//!
//! Files are conventionally fetched from
//! [`era1.ethportal.net`](https://era1.ethportal.net) with sha256
//! manifests at
//! [`eth-clients/history-endpoints`](https://eth-clients.github.io/history-endpoints/).
//!
//! ## Status
//!
//! This source is a scaffold. The actual Era1 parsing depends on the
//! published `e2store = "0.4"` crate's API surface. The wiring shape is
//! correct (DataSource impl, file resolution); end-to-end Era1 reading
//! is on the v0.2 roadmap.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::{
    errors::{Error, Result},
    sources::DataSource,
};

/// Reads `HeaderWithProof` content from Era1 files in a local directory.
pub struct Era1FileSource {
    root: PathBuf,
}

impl Era1FileSource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

#[async_trait]
impl DataSource for Era1FileSource {
    async fn fetch_header_with_proof_by_number(&self, _block_number: u64) -> Result<Vec<u8>> {
        Err(Error::DataSource(format!(
            "Era1FileSource at {} — Era1 file reading is not yet implemented; tracked for v0.2",
            self.root.display()
        )))
    }

    async fn fetch_header_with_proof_by_hash(&self, _block_hash: [u8; 32]) -> Result<Vec<u8>> {
        Err(Error::DataSource(
            "Era1FileSource: lookup by hash not implemented".into(),
        ))
    }

    fn name(&self) -> &'static str {
        "era1-file"
    }
}
