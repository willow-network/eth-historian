# Examples

Runnable demonstrations of `eth-historian`'s API.

## `verify_with_portal.rs`

Verify a single historical block via a running `trin` Portal sidecar.

Prerequisites: a `trin` instance running on `localhost:8545`, e.g.

```bash
trin --web3-http-address http://0.0.0.0:8545 --web3-transport http
```

Then:

```bash
cargo run --example verify_with_portal -- 10000835
```

Default block is Uniswap V2's deployment (May 4, 2020), which demonstrates the pre-merge `HistoricalHashes` auth path. Try also: `15539558` (post-merge / pre-Capella, `HistoricalRoots`), `17050000` (post-Capella, `HistoricalSummariesCapella`), `19500000` (post-Deneb, `HistoricalSummariesDeneb`).

## More examples on the way

This release ships the full inclusion-verification + historical-block-authentication surface across all four post-merge forks. See the main repo README for a complete capability list.
