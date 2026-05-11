# eth-historian (Python)

Python bindings for [`eth-historian`](https://github.com/willow-network/eth-historian) — trustless cryptographic authentication of historical Ethereum execution-layer blocks.

## Install

```bash
pip install eth-historian
```

## Usage

```python
import httpx
from eth_historian import verify_header_with_proof, canonized_fingerprints

# 1. Fetch SSZ-encoded HeaderWithProof bytes from any Portal-aware source.
resp = httpx.post("http://localhost:8545", json={
    "jsonrpc": "2.0", "id": 1,
    "method": "portal_legacyHistoryGetContent",
    # BlockHeaderByNumber content key for block 12,345,678
    "params": ["0x034e61bc0000000000"],
})
ssz_hex = resp.json()["result"]["content"]
ssz_bytes = bytes.fromhex(ssz_hex.removeprefix("0x"))

# 2. Verify cryptographically against the canonized accumulators.
#    Synchronous — no event loop required. Verification is CPU-bound
#    (SSZ decode + Merkle proof check), no I/O involved.
verified = verify_header_with_proof(ssz_bytes)
print(f"block:           {verified.block_number}")
print(f"state root:      {verified.state_root}")
print(f"authenticated:   {verified.auth_path}")

# 3. (Optional) Verify the wheel ships the canonized fingerprints
# you expect.
fp = canonized_fingerprints()
assert fp["merge_macc_bin_sha256"] == \
    "0xa2368bfa82a89a898b31dca6f37aa287918bd671bd74058912bc440c2288d791"
```

### Inclusion verification

Once a block is authenticated, prove specific receipts or transactions are inside it via MPT proofs against the verified roots:

```python
from eth_historian import (
    verify_header_with_proof,
    verify_receipt_inclusion,
    verify_transaction_inclusion,
)

verified = verify_header_with_proof(ssz_bytes)

# Receipt inclusion: prove `raw_receipt` is at `receipt_index` under `receipts_root`.
# `raw_receipt` is wire-format (legacy: RLP; typed: type-byte || RLP).
# `proof_nodes` is a list of `bytes` — the MPT path from root down.
receipts_root = bytes.fromhex(verified.receipts_root.removeprefix("0x"))
verify_receipt_inclusion(receipts_root, receipt_index, raw_receipt, proof_nodes)

# Transaction inclusion against the same authenticated block:
tx_root = bytes.fromhex(verified.transactions_root.removeprefix("0x"))
verify_transaction_inclusion(tx_root, tx_index, raw_tx, tx_proof_nodes)
```

Both functions raise `ValueError` on verification failure with a message describing the mismatch. Caller is responsible for fetching the proof nodes (any archive node can produce them via `debug_traceBlockByNumber` / custom proof endpoints).

## Build (from source)

```bash
cd bindings/python
pip install maturin
maturin develop  # editable install into the active venv
# or
maturin build --release  # produces a wheel in target/wheels/
```

Requires Rust 1.85+ and a Python 3.9+ venv.

## Trust model

This package ships the canonized [`HistoricalHashesAccumulator`](https://github.com/ethereum/portal-network-specs/blob/master/legacy/history/history-network.md) and pre-Capella `historical_roots` snapshots inside the wheel. SHA-256 fingerprints are exposed via `canonized_fingerprints()` and you should pin the package version you depend on. See the [main repo's `ARCHITECTURE.md`](https://github.com/willow-network/eth-historian/blob/main/ARCHITECTURE.md) for the full trust-model writeup.
