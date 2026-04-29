# @willow-network/eth-historian

WebAssembly bindings for [`eth-historian`](https://github.com/willow-network/eth-historian) — trustless cryptographic authentication of historical Ethereum execution-layer blocks.

## Install

```bash
npm install @willow-network/eth-historian
```

## Usage

```ts
import { verifyHeaderWithProof, canonizedFingerprints } from '@willow-network/eth-historian';

// 1. Fetch SSZ-encoded HeaderWithProof bytes from any Portal-aware source
//    (trin sidecar, Era1 file you downloaded, your own archival service).
const sszBytes: Uint8Array = await fetchPortalContent(blockNumber);

// 2. Verify cryptographically against the canonized accumulators.
//    All trust-critical work happens inside the wasm module.
try {
  const verified = await verifyHeaderWithProof(sszBytes);
  console.log('block:', verified.blockNumber);
  console.log('state root:', verified.stateRoot);
  console.log('authenticated via:', verified.authPath);
} catch (err) {
  console.error('verification failed:', err.message);
}

// 3. (Optional) Sanity-check the canonized fingerprints shipped in the
//    wasm bundle match what you expect.
const fp = canonizedFingerprints();
console.log(fp.mergeMaccBinSha256);
//   0xa2368bfa82a89a898b31dca6f37aa287918bd671bd74058912bc440c2288d791
```

## Build (from source)

```bash
cd bindings/ts
npm run build         # bundler target (default for webpack/vite/etc.)
npm run build:web     # ES modules for direct browser use
npm run build:nodejs  # Node.js commonjs target
```

Requires [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/).

## Trust model

This package ships the canonized [`HistoricalHashesAccumulator`](https://github.com/ethereum/portal-network-specs/blob/master/legacy/history/history-network.md) and pre-Capella `historical_roots` snapshots inside the wasm bundle. SHA-256 fingerprints are exposed via `canonizedFingerprints()` and you should pin the package version you depend on. See the [main repo's `ARCHITECTURE.md`](https://github.com/willow-network/eth-historian/blob/main/ARCHITECTURE.md) for the full trust-model writeup.
