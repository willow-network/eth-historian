//! Provides `HistoricalSummary` lookups by slot for post-Capella header
//! verification.
//!
//! Simplified from trin's two-source enum — we only support an in-process
//! [`HistoricalSummaries`] snapshot. The `HeaderOracle` source (trin's
//! cross-overlay JSON-RPC mechanism) is not vendored: a downstream that
//! wants live summaries should keep the snapshot fresh and call
//! [`HistoricalSummariesProvider::set_summaries`] when it advances.
//!
//! Source: trin commit `30aeef8`, `crates/validation/src/historical_summaries_provider.rs`.

use std::sync::Arc;

use anyhow::{anyhow, bail};
use tokio::sync::RwLock;

use crate::portal_types::{historical_summary_index, HistoricalSummaries, HistoricalSummary};

#[derive(Debug, Clone, Default)]
pub struct HistoricalSummariesProvider {
    summaries: Arc<RwLock<HistoricalSummaries>>,
}

impl HistoricalSummariesProvider {
    pub fn new(summaries: HistoricalSummaries) -> Self {
        Self {
            summaries: Arc::new(RwLock::new(summaries)),
        }
    }

    /// Replace the in-memory snapshot. Call this when a fresher
    /// `HistoricalSummaries` (typically every ~6 months) becomes available.
    pub async fn set_summaries(&self, summaries: HistoricalSummaries) {
        *self.summaries.write().await = summaries;
    }

    pub async fn get_historical_summary(&self, slot: u64) -> anyhow::Result<HistoricalSummary> {
        let historical_summary_index = historical_summary_index(slot).ok_or(anyhow!(
            "Can't provide Historical Summary for slot before Capella"
        ))?;

        let summaries = self.summaries.read().await;
        match summaries.get(historical_summary_index) {
            Some(historical_summary) => Ok(historical_summary.clone()),
            None => bail!("Historical summary index out of bounds: {historical_summary_index}"),
        }
    }
}
