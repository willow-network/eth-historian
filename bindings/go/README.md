# eth-historian (Go)

Go bindings for [eth-historian](https://github.com/willow-network/eth-historian) — trustless cryptographic authentication of historical Ethereum execution-layer blocks.

## Install

```go
import "github.com/willow-network/eth-historian/bindings/go"
```

The bindings use `cgo` against a Rust static library. From a fresh checkout:

```bash
cd bindings/go
make test            # runs `cargo build --release` then `go test`
```

Cargo + Rust 1.85+ required.

## Usage

```go
package main

import (
    "fmt"
    "log"

    eth_historian "github.com/willow-network/eth-historian/bindings/go"
)

func main() {
    // 1. Fetch SSZ-encoded HeaderWithProof bytes from any Portal-aware
    //    source (trin sidecar, Era1 file, your own archival service).
    var sszBytes []byte = fetchPortalContent(blockNumber)

    // 2. Verify cryptographically against the canonized accumulators.
    //    Pre-merge and merge→Capella work today; post-Capella requires
    //    extending the binding to accept a HistoricalSummaries snapshot
    //    (tracked as a v0.2 follow-up).
    verified, err := eth_historian.VerifyHeaderWithProof(sszBytes)
    if err != nil {
        log.Fatalf("verification failed: %v", err)
    }
    fmt.Printf("block:           %d\n", verified.BlockNumber)
    fmt.Printf("state root:      %s\n", verified.StateRoot)
    fmt.Printf("authenticated:   %s\n", verified.AuthPath)

    // 3. (Optional) Pin the canonized fingerprints out-of-band.
    fp := eth_historian.GetCanonizedFingerprints()
    if fp.MergeMaccBinSha256 !=
        "0xa2368bfa82a89a898b31dca6f37aa287918bd671bd74058912bc440c2288d791" {
        log.Fatal("untrusted build — merge_macc.bin SHA-256 doesn't match published value")
    }
}
```

## Distribution

The Go module currently builds against a locally-built Rust static library at `target/release/libeth_historian.a`. For pre-built distribution (so users don't need Rust+cargo):

* macOS arm64 + linux amd64 + windows amd64 are the typical first three
* Use `goreleaser` or a GitHub Actions matrix to publish a tarball per platform

This is a v0.2 packaging concern — for v0.1, contributors check out the repo and run `make test`.

## Trust model

This binding ships the canonized [`HistoricalHashesAccumulator`](https://github.com/ethereum/portal-network-specs/blob/master/legacy/history/history-network.md) and pre-Capella `historical_roots` snapshots inside the static library. SHA-256 fingerprints are exposed via `GetCanonizedFingerprints()` and you should pin the eth-historian version you depend on. See the [main repo's `ARCHITECTURE.md`](https://github.com/willow-network/eth-historian/blob/main/ARCHITECTURE.md) for the full trust-model writeup.
