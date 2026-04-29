# eth-historian (Python)

Python bindings for [`eth-historian`](https://github.com/willow-network/eth-historian) — trustless cryptographic authentication of historical Ethereum execution-layer blocks.

## Install

```bash
pip install eth-historian
```

## Usage

```python
import asyncio
import httpx
from eth_historian import verify_header_with_proof, canonized_fingerprints

async def main():
    # 1. Fetch SSZ-encoded HeaderWithProof bytes from any Portal-aware source.
    async with httpx.AsyncClient() as client:
        # Example: trin sidecar legacy History network
        resp = await client.post("http://localhost:8545", json={
            "jsonrpc": "2.0", "id": 1,
            "method": "portal_legacyHistoryGetContent",
            # BlockHeaderByNumber content key for block 12,345,678
            "params": ["0x034e61bc0000000000"],
        })
        ssz_hex = resp.json()["result"]["content"]
        ssz_bytes = bytes.fromhex(ssz_hex.removeprefix("0x"))

    # 2. Verify cryptographically against the canonized accumulators.
    verified = await verify_header_with_proof(ssz_bytes)
    print(f"block:           {verified.block_number}")
    print(f"state root:      {verified.state_root}")
    print(f"authenticated:   {verified.auth_path}")

    # 3. (Optional) Verify the wheel ships the canonized fingerprints
    # you expect.
    fp = canonized_fingerprints()
    assert fp["merge_macc_bin_sha256"] == \
        "0xa2368bfa82a89a898b31dca6f37aa287918bd671bd74058912bc440c2288d791"

asyncio.run(main())
```

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
