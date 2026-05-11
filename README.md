# eth-historian

> Trustless cryptographic authentication of historical Ethereum execution-layer blocks — and the receipts, transactions, and logs inside them — for off-chain consumers.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

Off-chain indexers, data pipelines, and AI agents that read historical Ethereum blocks have been stuck choosing between (a) trusting an archive RPC, (b) running their own archive node (terabytes), or (c) trusting an indexer's reputation/slashing. **eth-historian** is a fourth option: feed it raw block data from any source, get back a header that's been cryptographically verified against canonized commitments — then verify any specific receipt, transaction, or event log inside that block via Merkle Patricia Trie proofs against the authenticated roots.

## Why this exists

* **Helios** ([a16z](https://github.com/a16z/helios)) authenticates Ethereum blocks via beacon-chain sync committees — but only post-Capella (block ≥ 17,034,870, ~April 2023). Earlier blocks have no Merkle path from current beacon state.
* **Portal Network** clients (`trin`, Fluffy) cover the historical range, but trin is unmaintained as of 2026 and Fluffy moved headers off the History sub-network entirely.
* **ZK coprocessors** (Axiom, Lagrange, Brevis) target on-chain smart-contract consumers — wrong unit economics for off-chain indexing.
* The two governing EIPs ([7643](https://eips.ethereum.org/EIPS/eip-7643), [7919](https://eips.ethereum.org/EIPS/eip-7919)) that would standardize this are both Stagnant.

This crate fills the gap with a stable, library-grade API. It vendors verified accumulator data from [trin@30aeef8](https://github.com/ethereum/trin/tree/30aeef83a32ed30e747141137f0b89e1f7da8cbe), asserts SHA-256 fingerprints at every load, and structures the trust model so callers know exactly what they're trusting.

## Quick start

### Rust

```toml
[dependencies]
eth-historian = "0.1"
```

```rust
use eth_historian::{Verifier, sources::ArchiveRpcSource};
use eth_historian::sources::archive_rpc::FilesystemEpochProvider;

let verifier = Verifier::builder()
    .data_source(
        ArchiveRpcSource::new("https://eth.llamarpc.com")
            .with_epoch_provider(FilesystemEpochProvider::new("./epoch_accs"))
    )
    .build();

// Uniswap V2 deployment, May 2020
let block = verifier.verify_block_by_number(10_000_835).await?;
println!("state root: {:?}", block.header.state_root);
println!("verified via: {:?}", block.auth_path);  // HistoricalHashes

// Once authenticated, verify a specific receipt is in this block:
// `raw_receipt` is wire-format bytes; `proof_nodes` is the MPT path
// (both supplied by the caller, e.g. fetched alongside the receipt).
block.verify_receipt_inclusion(receipt_index, &raw_receipt, &proof_nodes)?;
let receipt = block.verify_and_decode_receipt(receipt_index, &raw_receipt, &proof_nodes)?;
for log in receipt.logs() { /* iterate trustlessly */ }
```

### TypeScript / JavaScript

```bash
npm install @willow-network/eth-historian
```

```ts
import { verifyHeaderWithProof } from '@willow-network/eth-historian';

const sszBytes: Uint8Array = await fetchPortalContent(blockNumber);
const verified = await verifyHeaderWithProof(sszBytes);
console.log(verified.stateRoot, 'authenticated via', verified.authPath);
```

### Python

```bash
pip install eth-historian
```

```python
from eth_historian import verify_header_with_proof
verified = await verify_header_with_proof(ssz_bytes)
print(verified.state_root, 'via', verified.auth_path)
```

## Inclusion verification

Once a block is authenticated, its `transactions_root` and `receipts_root` are trustworthy. The [`inclusion`](https://docs.rs/eth-historian/latest/eth_historian/inclusion/) module turns those roots into one-call helpers for:

* **`verify_transaction_inclusion(tx_index, raw_tx, proof)`** — bind the wire-format bytes to the authenticated `transactions_root`.
* **`verify_receipt_inclusion(receipt_index, raw_receipt, proof)`** — bind a receipt to the authenticated `receipts_root`.
* **`verify_and_decode_receipt(...)`** — same, plus return a typed [`alloy::consensus::ReceiptEnvelope`] so you can iterate logs trustlessly.

The MPT proofs themselves are caller-supplied. Most Ethereum execution clients can produce them on demand (`debug_traceBlockByNumber`, `eth_getProof` for state, third-party proof services), or you can compute them locally from the full block body using `alloy-trie`.

End result: any off-chain consumer can verify "this event happened on canonical Ethereum at block N" with a `(header, proof)` pair and a single library call — no archive node, no RPC trust, no separate MPT verifier to compose.

## What's authenticated against what

| Block range | Era | Authenticated against | Trust |
|---|---|---|---|
| 0 – 15,537,393 | pre-merge | embedded `HistoricalHashesAccumulator` | canonized constant |
| 15,537,394 – 17,034,869 | merge → Capella | embedded `historical_roots` snapshot | canonized constant |
| 17,034,870+ | post-Capella | live `historical_summaries` from `BeaconState` | sync-committee BLS, **BFT-equivalent** |

Pre-Capella verification chains to a hardcoded constant; post-Capella verification chains to a current sync-committee signature. The [`AuthPath`](https://docs.rs/eth-historian/latest/eth_historian/enum.AuthPath.html) enum on every `VerifiedBlock` records which one applied — surface this in your UI / logs so downstream consumers can filter by trust tier.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full trust-model writeup, including why the canonized constants are what they are and how to verify the binaries shipped in the package match the upstream values.

## Data sources

eth-historian doesn't fetch bytes itself; you plug in one or more `DataSource` impls. Built-ins:

* **`ArchiveRpcSource`** — talks `eth_getBlockByNumber` to any Ethereum execution RPC, then constructs the canonized accumulator proof locally. Pre-merge proofs come from a configured `EpochProvider`; post-merge proofs (Bellatrix → Electra) come from a configured [`BeaconDataProvider`](#post-merge-operator-setup).
* **`BeaconRpcSource`** — talks the standard Ethereum beacon-API to a (typically self-run) archive beacon node. Implements `BeaconDataProvider`. Required for post-merge `ArchiveRpcSource` proof construction.
* **`PortalSidecarSource`** — talks `portal_legacyHistoryGetContent` to a separately-running `trin` sidecar. Covers all eras trin serves.
* **`Era1FileSource`** — *scaffold; tracked as [issue #13](https://github.com/willow-network/eth-historian/issues/13) — unblocked now that ethportal-api is no longer a transitive dep.*

Multi-source fallback works automatically — register sources in priority order and the first one that returns valid bytes wins.

## Operator setup for pre-merge proof construction

`ArchiveRpcSource` constructs proofs locally, which means it needs the `EpochAccumulator` for whatever block range you're verifying. Per-epoch blobs are ~524 KB; ~995 MB total for the full pre-merge range. We don't bundle them in the crate.

Where to get them:
* Trin's `portal-spec-tests` submodule has a few sample epoch accumulators committed (`epoch_accs/0x*.bin`).
* For full coverage, regenerate from a beacon archive node or download from [`era1.ethportal.net`](https://era1.ethportal.net) (Era1 file format embeds them).

Provide them via `FilesystemEpochProvider::new("./epoch_accs")` or implement the `EpochProvider` trait against your own storage layer.

## Trust assumptions, made explicit

This crate's pre-Capella verification ultimately reduces to: *"the SHA-256 of the binary blobs shipped in this package matches what trin commit `30aeef8` shipped."* We assert this fingerprint at load time and refuse to start if it doesn't match. The fingerprints are:

| Asset | SHA-256 | SSZ tree-hash root |
|---|---|---|
| `merge_macc.bin` | `a2368bfa…d791` | `0x8eac39…9ff9` |
| `historical_roots.ssz` | `64ed2cbe…a316` | `0x4df6b8…3da7` |

Pin the version of this crate you depend on. If we ever change these (e.g. to follow [EIP-7643](https://eips.ethereum.org/EIPS/eip-7643) finalization), it'll be a major-version bump with a clearly written rationale in the changelog.

Post-Capella verification has standard sync-committee light-client trust — no canonized constants beyond what every CL light client needs.

## Status

**v0.1.0** ships the full inclusion-verification + historical-block-authentication surface across all four post-merge forks:

* **Rust core** — `Verifier`, `inclusion` module (receipt / transaction / log inclusion against authenticated roots), four authentication paths (HistoricalHashes / HistoricalRoots / HistoricalSummaries{Capella,Deneb}).
* **Bindings** — TypeScript (wasm-bindgen), Python (PyO3), Go (cgo + cdylib).
* **Data sources** — `ArchiveRpcSource` (full era range, pre-merge via `EpochProvider`, post-merge via `BeaconDataProvider`), `PortalSidecarSource`, `BeaconRpcSource`.
* **End-to-end Merkle-path validation** against real mainnet `SignedBeaconBlock` fixtures across Bellatrix / Capella / Deneb / Electra.

Filed for follow-ups: [`Era1FileSource`](https://github.com/willow-network/eth-historian/issues/13) re-enable, [HistoricalBatch caching](https://github.com/willow-network/eth-historian/issues/15), [Swift](https://github.com/willow-network/eth-historian/issues/5) and [React Hooks](https://github.com/willow-network/eth-historian/issues/14) bindings, [hosted epoch_accs bundle](https://github.com/willow-network/eth-historian/issues/6).

## Prior art

* [`trin`](https://github.com/ethereum/trin) — Rust Portal client. The verifier code in this crate is ported from its `crates/validation/`, with attribution preserved in source headers. Apache-2.0/MIT.
* [`Lighthouse`](https://github.com/sigp/lighthouse) — the Merkle proof library this crate uses traces back to Lighthouse's `consensus/merkle_proof`.
* [Portal Network spec](https://github.com/ethereum/portal-network-specs) — the canonical document; the `HistoricalHashesAccumulator` definition and the four `BlockProofHistorical*` containers come from here.

## Contributing

PRs welcome. The project is maintained by [Willow Network](https://willow.tech) but designed to live as community infrastructure. If you want to take over publishing, fork-with-co-maintainership, or land Era1 / post-merge work, please open an issue.

## License

Dual-licensed under either of:

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
