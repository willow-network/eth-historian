# Architecture

This document explains exactly what `eth-historian` authenticates,
against what root of trust, and how a production deployment should pin
the assumptions it depends on.

## The problem

Authenticating a historical Ethereum execution-layer block means
proving — to an off-chain consumer that does not run an archive node —
that block N's header is canonical. Three things have to chain together:

1. The block's hash is the right hash for slot/height N.
2. That slot/height is part of the canonical chain.
3. The verifier's notion of "canonical" can be derived from a small,
   stable, externally-verifiable input.

For different eras of Ethereum, step 3 looks different:

| Era | Block range | Canonical commitment |
|---|---|---|
| Pre-merge (PoW) | 0 – 15,537,393 | `HistoricalHashesAccumulator` (frozen at TheMerge) |
| Post-merge / pre-Capella | 15,537,394 – 17,034,869 | `BeaconState.historical_roots` (frozen at Capella) |
| Post-Capella | 17,034,870+ | `BeaconState.historical_summaries` (live) |

The first two are **canonized constants**. The third chains to a current
sync-committee BLS signature, which is BFT-equivalent under standard
Altair light-client assumptions.

## What this crate ships

```
src/assets/
├── merge_macc.bin            (60,708 B)   — PreMergeAccumulator
└── historical_roots.ssz      (24,256 B)   — HistoricalRootsAccumulator
```

Both blobs are vendored from
[trin commit `30aeef8`](https://github.com/ethereum/trin/tree/30aeef83a32ed30e747141137f0b89e1f7da8cbe/crates/validation/src/assets).
Their SHA-256 hashes (`a2368bfa…d791` and `64ed2cbe…a316`) and SSZ
tree-hash roots (`0x8eac39…9ff9` and `0x4df6b8…3da7`) are constants in
[`src/constants.rs`](src/constants.rs) and asserted at every
[`Verifier::builder().build()`](src/api.rs) call. A tampered binary
panics at startup rather than silently breaking verification.

For the post-Capella path, callers supply their own `HistoricalSummaries`
snapshot via `Verifier::builder().historical_summaries(..)`. We don't
bundle one because the snapshot must be reasonably fresh — if the user
needs Capella+ verification, they should source a current snapshot from
a beacon archive node and refresh it periodically.

## Verification flow

```
                           verify_header_with_proof(bytes)
                                       │
                                       ▼
                    ┌──────────────────────────────────────┐
                    │ SSZ decode → HeaderWithProof         │
                    │   .header (alloy::Header)            │
                    │   .proof  (BlockHeaderProof variant) │
                    └──────────────────┬───────────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                │              Era dispatch on                │
                │       (proof variant + header.timestamp)    │
                └──┬───────────────┬───────────────┬─────────┬┘
                   │               │               │         │
              HistoricalHashes  HistoricalRoots  Capella  Deneb+
                   │               │               │         │
                   ▼               ▼               ▼         ▼
              embedded         embedded        live HS   live HS
              merge_macc      historical_roots  snapshot  snapshot
                   │               │               │         │
                   ▼               ▼               ▼         ▼
              verify_merkle_proof against the appropriate root
                   │               │               │         │
                   └───────────────┴───────────────┴─────────┘
                                       │
                                       ▼
                              VerifiedBlock {
                                header,
                                auth_path,
                              }
```

Every path bottoms out in `verify_merkle_proof(leaf, branch, depth, gen_index, root)` (see [`src/merkle/proof.rs`](src/merkle/proof.rs)) — a constant-time SSZ Merkle path verification using SHA-256 hash compression.

## Trust model — what each variant assumes

### `AuthPath::HistoricalHashes` — pre-merge

* Trust assumption: the `merge_macc.bin` shipped in this crate hashes to
  `0x8eac399e24480dce3cfe06f4bdecba51c6e5d0c46200e3e8611a0b44a3a69ff9`,
  and that root is the canonical `HistoricalHashesAccumulator` for
  pre-PoS Ethereum mainnet.
* Verification: SSZ Merkle path of length 15 from `header.hash_slow()`
  to the relevant `epoch_accumulator_root` inside `historical_epochs`.
* **Caveat:** the canonical root is not on-chain anywhere. Trust derives
  from the social agreement that this binary is what trin / Fluffy /
  ultralight all shipped at the time of TheMerge. EIP-7643 attempts to
  formalize this as `0xec8e040f…e701`, but is currently Stagnant and
  publishes a *different* root than trin ships — we follow trin because
  it's the actively-tested implementation.

### `AuthPath::HistoricalRoots` — merge → Capella

* Trust assumption: the `historical_roots.ssz` shipped in this crate
  hashes to `0x4df6b89755125d4f6c5575039a04e22301a5a49ee893c1d27e559e3eeab73da7`
  and that root is the canonical `BeaconState.historical_roots` snapshot
  at the Capella fork (slot 6,209,536).
* Verification: a chain of two SSZ Merkle proofs:
  1. `BeaconBlockProofHistoricalRoots` (length 14): the beacon block
     containing this EL block is in `historical_roots`.
  2. `ExecutionBlockProofBellatrix` (length 11): the EL block hash is
     in that beacon block's `ExecutionPayload`.
* **Caveat:** like the pre-merge accumulator, this is a canonized
  constant. Beacon `historical_roots` was frozen at the Capella fork.

### `AuthPath::HistoricalSummariesCapella` / `HistoricalSummariesDeneb` — post-Capella

* Trust assumption: a current sync-committee BLS signature (≥ 2/3 of
  512 validators), supplied implicitly by the caller's `HistoricalSummaries`
  snapshot being from a recently-finalized `BeaconState`.
* Verification: same two-step chain as the `HistoricalRoots` variant,
  but with `historical_summaries[i]` (live, finalized) as the root
  instead of a baked-in constant.
* **No canonized-constant caveat.** Trust reduces to the standard
  Altair light-client assumption that's been the basis for `Helios`,
  `Lodestar`, and every other CL light client for ~3 years.

## Pinning recommendations

For production deployments:

1. **Pin a specific release of `eth-historian`.** Don't track
   `^0.1`; pin `=0.1.X`. Major-version bumps will accompany changes to
   the canonized constants if/when those happen (e.g. EIP-7643 finalizes
   with a different root).

2. **Verify the SHA-256 fingerprints out-of-band.** Compare the values
   returned by `canonized_fingerprints()` (or `assert_canonized_accumulator_fingerprints()`'s
   constants) against trin's published values. If they ever differ from
   `a2368bfa…d791` and `64ed2cbe…a316`, refuse to start.

3. **Surface `auth_path` to your users.** A subgrove / dataset / agent
   that consumes pre-Capella data has weaker trust than one consuming
   post-Capella data. Show this distinction. Don't paper over it.

4. **For post-Capella, refresh `HistoricalSummaries` periodically.**
   A snapshot from 12 months ago can't authenticate a block from 11
   months ago. Pull a fresh snapshot from your beacon archive node
   every ~6 months.

## Why a single root of trust per era, not per block

Beacon `historical_summaries` updates every 8192 slots (~27 hours). One
snapshot covers ~8192 EL blocks. We could fetch a fresh snapshot for
every block; the trade-off is per-block I/O. The current design caches
one snapshot in the `HistoricalSummariesProvider` and looks up the
relevant index for each request. If your application verifies blocks
across a wide time range, refresh the snapshot when it falls behind.

## Inclusion verification

`VerifiedBlock` carries the authenticated `transactions_root` and
`receipts_root`. The [`inclusion`](../src/inclusion.rs) module turns
those roots into one-call MPT-proof helpers:

* `verify_transaction_inclusion(tx_index, raw_tx, proof)` — bind
  wire-format bytes to the authenticated `transactions_root`.
* `verify_receipt_inclusion(receipt_index, raw_receipt, proof)` — bind
  to the authenticated `receipts_root`.
* `verify_and_decode_receipt(...)` — same, plus return a typed
  `alloy::consensus::ReceiptEnvelope` (handles legacy / EIP-2930 /
  EIP-1559 / EIP-4844 / EIP-7702 variants).

These are **trie-binding** helpers — they prove `(key, value)` is in a
trie rooted at the supplied root, with key derived from the index per
Ethereum's MPT convention (`rlp(index)`). They do not perform any
independent header verification; the trust comes from the
`VerifiedBlock` providing an authenticated root.

Implementation delegates to `alloy-trie::proof::verify_proof` (the same
verifier used by the alloy / reth ecosystem). The
`root_matches_alloy_canonical_receipt_root` integration test confirms
the trie shape we generate matches `alloy::consensus::proofs::calculate_receipt_root`.

## What this crate explicitly does NOT verify

* **State roots.** `header.state_root` is authenticated, but resolving
  individual storage slots requires additional MPT proofs out of scope
  here. (Could land in a future release — same pattern as receipt inclusion, but
  against the state trie which is significantly more complex.)
* **Reorgs.** This crate authenticates that a block was *at some point*
  canonical (per the embedded accumulator or current beacon state). It
  does not detect reorgs against your local view; that's a chain-tip
  concern handled by tools like Helios.
* **MPT proof generation.** Callers supply the proof — `eth-historian`
  only verifies it. Most archive nodes can produce receipt/tx proofs;
  for self-generated proofs, use `alloy-trie::HashBuilder` against the
  full block body.

## References

* [Portal Network legacy history spec](https://github.com/ethereum/portal-network-specs/blob/master/legacy/history/history-network.md) — defines the four `BlockProofHistorical*` proof variants.
* [EIP-7643: History accumulator for pre-PoS data](https://eips.ethereum.org/EIPS/eip-7643) — Stagnant, but the canonical document for the pre-merge accumulator concept.
* [EIP-7919: Pureth Meta](https://eips.ethereum.org/EIPS/eip-7919) — Stagnant; bundles a vision for verifiable Ethereum data access that this crate operationalizes for the historical-block subset.
* [trin's `crates/validation`](https://github.com/ethereum/trin/tree/30aeef83a32ed30e747141137f0b89e1f7da8cbe/crates/validation) — source of the verifier code and accumulator binaries vendored here.
