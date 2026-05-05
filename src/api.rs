//! Public API: [`Verifier`], [`VerifiedBlock`], [`AuthPath`].

use std::sync::Arc;

use alloy::consensus::Header;
use ssz::Decode;

use crate::{
    errors::{Error, Result},
    header_validator::HeaderValidator,
    portal_types::HistoricalSummaries,
    sources::DataSource,
    HeaderWithProof,
};

/// Which canonized commitment authenticated a [`VerifiedBlock`].
///
/// Read this on the result if you need to surface a per-block trust
/// label — e.g. UI badges, downstream filtering, "should I trust this
/// data" decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPath {
    /// Pre-merge block authenticated against the embedded
    /// `HistoricalHashesAccumulator` (canonized constant; trust assumes
    /// the accumulator binary shipped with this crate is honest).
    /// Covers blocks 0 .. 15,537,393.
    HistoricalHashes,

    /// Post-merge / pre-Capella block authenticated against the embedded
    /// `historical_roots` snapshot (canonized constant). Covers blocks
    /// 15,537,394 .. 17,034,869.
    HistoricalRoots,

    /// Post-Capella / pre-Deneb block authenticated against a
    /// `HistoricalSummaries` snapshot supplied by the caller (chains to
    /// a sync-committee-signed `BeaconState`). BFT-equivalent. Covers
    /// blocks 17,034,870 .. ~19,426,587.
    HistoricalSummariesCapella,

    /// Post-Deneb block authenticated against a `HistoricalSummaries`
    /// snapshot supplied by the caller. BFT-equivalent. Covers blocks
    /// ~19,426,587 onward.
    HistoricalSummariesDeneb,
}

/// A header that has been authenticated by [`Verifier`].
#[derive(Debug, Clone)]
pub struct VerifiedBlock {
    /// The full execution-layer header.
    pub header: Header,
    /// Which canonized commitment authenticated it.
    pub auth_path: AuthPath,
}

impl VerifiedBlock {
    /// Convenience: the block hash.
    pub fn block_hash(&self) -> alloy::primitives::B256 {
        self.header.hash_slow()
    }
}

/// Builder for [`Verifier`]. See module docs for usage.
pub struct VerifierBuilder {
    data_sources: Vec<Arc<dyn DataSource>>,
    historical_summaries: Option<HistoricalSummaries>,
    skip_fingerprint_check: bool,
}

impl VerifierBuilder {
    fn new() -> Self {
        Self {
            data_sources: Vec::new(),
            historical_summaries: None,
            skip_fingerprint_check: false,
        }
    }

    /// Add a data source. Multiple sources are tried in registration order
    /// until one returns a header that the validator accepts. Useful for
    /// fallback chains: e.g. local Era1 files first, then archive RPC.
    pub fn data_source<D>(mut self, source: D) -> Self
    where
        D: DataSource + 'static,
    {
        self.data_sources.push(Arc::new(source));
        self
    }

    /// Supply an in-memory `HistoricalSummaries` snapshot for post-Capella
    /// verification. Without this, post-Capella headers will fail with
    /// [`Error::HistoricalSummariesUnavailable`].
    pub fn historical_summaries(mut self, summaries: HistoricalSummaries) -> Self {
        self.historical_summaries = Some(summaries);
        self
    }

    /// Skip the canonized-accumulator SHA-256 / tree-hash fingerprint check
    /// at construction time. Default is to enforce it. Only useful for
    /// tests; **never disable in production** — it's the integrity guard
    /// for the canonized-constant trust path.
    pub fn skip_fingerprint_check(mut self) -> Self {
        self.skip_fingerprint_check = true;
        self
    }

    /// Build the [`Verifier`].
    pub fn build(self) -> Verifier {
        if !self.skip_fingerprint_check {
            crate::assert_canonized_accumulator_fingerprints();
        }

        let validator = match self.historical_summaries {
            Some(summaries) => HeaderValidator::new_with_historical_summaries(summaries),
            None => HeaderValidator::default(),
        };

        Verifier {
            validator: Arc::new(validator),
            data_sources: self.data_sources,
        }
    }
}

/// The main entry point. Authenticates historical Ethereum execution-layer
/// blocks against canonized accumulators and (optionally)
/// `HistoricalSummaries`. Construct via [`Verifier::builder`].
#[derive(Clone)]
pub struct Verifier {
    validator: Arc<HeaderValidator>,
    data_sources: Vec<Arc<dyn DataSource>>,
}

impl Verifier {
    /// Construct a [`Verifier`] with default settings (no data sources, no
    /// `HistoricalSummaries`). Most users want [`Verifier::builder`].
    pub fn new() -> Self {
        VerifierBuilder::new().build()
    }

    /// Builder for [`Verifier`].
    pub fn builder() -> VerifierBuilder {
        VerifierBuilder::new()
    }

    /// Verify a `HeaderWithProof` you already have. Use this when you've
    /// fetched the bytes yourself (Era1 file, Portal Network, etc.) and
    /// just need cryptographic verification.
    pub async fn verify(&self, hwp: &HeaderWithProof) -> Result<VerifiedBlock> {
        self.validator
            .validate_header_with_proof(hwp)
            .await
            .map_err(|e| Error::VerificationFailed {
                block: hwp.header.number,
                reason: e.to_string(),
            })?;

        Ok(VerifiedBlock {
            header: hwp.header.clone(),
            auth_path: auth_path_for(&hwp.proof),
        })
    }

    /// Verify a header by block number. Iterates configured data sources
    /// in order; the first one that returns SSZ-decodable bytes that pass
    /// verification wins.
    pub async fn verify_block_by_number(&self, block_number: u64) -> Result<VerifiedBlock> {
        if self.data_sources.is_empty() {
            return Err(Error::NoDataSource);
        }

        let mut last_err: Option<Error> = None;
        for source in &self.data_sources {
            match source.fetch_header_with_proof_by_number(block_number).await {
                Ok(bytes) => {
                    let hwp =
                        HeaderWithProof::from_ssz_bytes(&bytes).map_err(|e| Error::SszDecode {
                            block: block_number,
                            reason: format!("{:?}", e),
                        })?;
                    if hwp.header.number != block_number {
                        last_err = Some(Error::BlockNumberMismatch {
                            expected: block_number,
                            actual: hwp.header.number,
                        });
                        continue;
                    }
                    return self.verify(&hwp).await;
                }
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }
        Err(last_err.unwrap_or(Error::BlockNotFound(block_number)))
    }

    /// Verify a header by block hash.
    pub async fn verify_block_by_hash(
        &self,
        block_hash: alloy::primitives::B256,
    ) -> Result<VerifiedBlock> {
        if self.data_sources.is_empty() {
            return Err(Error::NoDataSource);
        }

        let mut last_err: Option<Error> = None;
        for source in &self.data_sources {
            match source.fetch_header_with_proof_by_hash(block_hash.0).await {
                Ok(bytes) => {
                    let hwp =
                        HeaderWithProof::from_ssz_bytes(&bytes).map_err(|e| Error::SszDecode {
                            block: 0,
                            reason: format!("{:?}", e),
                        })?;
                    if hwp.header.hash_slow() != block_hash {
                        last_err = Some(Error::VerificationFailed {
                            block: hwp.header.number,
                            reason: "returned header's hash does not match requested hash".into(),
                        });
                        continue;
                    }
                    return self.verify(&hwp).await;
                }
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| Error::DataSource("no source produced bytes".into())))
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

fn auth_path_for(proof: &crate::BlockHeaderProof) -> AuthPath {
    use crate::BlockHeaderProof::*;
    match proof {
        HistoricalHashes(_) => AuthPath::HistoricalHashes,
        HistoricalRoots(_) => AuthPath::HistoricalRoots,
        HistoricalSummariesCapella(_) => AuthPath::HistoricalSummariesCapella,
        HistoricalSummariesDeneb(_) => AuthPath::HistoricalSummariesDeneb,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_default_constructs_clean() {
        // The fingerprint check runs at build time; passing means the
        // canonized accumulator binaries are intact.
        let _v = Verifier::builder().build();
    }

    #[tokio::test]
    async fn verify_block_with_no_sources_errors() {
        let v = Verifier::new();
        let err = v.verify_block_by_number(10_000_835).await.unwrap_err();
        assert!(matches!(err, Error::NoDataSource));
    }
}
