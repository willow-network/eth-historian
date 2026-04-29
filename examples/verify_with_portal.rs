//! Example: verify a single historical Ethereum block via a running
//! `trin` Portal sidecar.
//!
//! Run with a trin sidecar listening on `localhost:8545`:
//!
//!   trin --web3-http-address http://0.0.0.0:8545 --web3-transport http
//!
//! Then:
//!
//!   cargo run --example verify_with_portal -- 10000835
//!
//! The argument is the block number to verify. Defaults to Uniswap V2
//! deployment (block 10,000,835, May 2020 — pre-merge, demonstrates the
//! `HistoricalHashes` auth path).

use eth_historian::{sources::PortalSidecarSource, Verifier};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let block_number: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000_835);

    let portal_url =
        std::env::var("PORTAL_RPC").unwrap_or_else(|_| "http://localhost:8545".to_string());

    println!("Verifier::builder() — asserting embedded canonized accumulator fingerprints …");
    let verifier = Verifier::builder()
        .data_source(PortalSidecarSource::new(&portal_url)?)
        .build();
    println!("  OK");

    println!(
        "Querying Portal sidecar at {} for block {} …",
        portal_url, block_number
    );
    let verified = verifier.verify_block_by_number(block_number).await?;

    println!();
    println!("Verified block {}", verified.header.number);
    println!("  block_hash:        {:?}", verified.block_hash());
    println!("  parent_hash:       {:?}", verified.header.parent_hash);
    println!("  state_root:        {:?}", verified.header.state_root);
    println!("  receipts_root:     {:?}", verified.header.receipts_root);
    println!(
        "  transactions_root: {:?}",
        verified.header.transactions_root
    );
    println!("  timestamp:         {}", verified.header.timestamp);
    println!("  authenticated via: {:?}", verified.auth_path);

    Ok(())
}
