// Package eth_historian — Go bindings for eth-historian.
//
// Trustless cryptographic authentication of historical Ethereum
// execution-layer blocks for off-chain consumers.
//
// Build prerequisite:  cargo build --release  (in this directory)
// Then:                go test ./...
package eth_historian

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo darwin LDFLAGS: -L${SRCDIR}/target/release -leth_historian -framework Security -framework SystemConfiguration
#cgo linux LDFLAGS: -L${SRCDIR}/target/release -leth_historian -lm -ldl -lpthread
#cgo windows LDFLAGS: -L${SRCDIR}/target/release -leth_historian -lws2_32 -luserenv -lntdll
#include "eth_historian.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// AuthPath records which canonized commitment authenticated a verified block.
type AuthPath uint8

const (
	// HistoricalHashes — pre-merge block (block 0..15,537,393).
	HistoricalHashes AuthPath = 0
	// HistoricalRoots — post-merge / pre-Capella (15,537,394..17,034,869).
	HistoricalRoots AuthPath = 1
	// HistoricalSummariesCapella — Capella .. Deneb (~17,034,870..19,426,587).
	HistoricalSummariesCapella AuthPath = 2
	// HistoricalSummariesDeneb — post-Deneb (~19,426,587 onward).
	HistoricalSummariesDeneb AuthPath = 3
)

// String returns a human-readable label.
func (a AuthPath) String() string {
	switch a {
	case HistoricalHashes:
		return "HistoricalHashes"
	case HistoricalRoots:
		return "HistoricalRoots"
	case HistoricalSummariesCapella:
		return "HistoricalSummariesCapella"
	case HistoricalSummariesDeneb:
		return "HistoricalSummariesDeneb"
	default:
		return fmt.Sprintf("AuthPath(%d)", a)
	}
}

// VerifiedBlock is the result of a successful verification.
//
// Hash fields are hex-encoded with the "0x" prefix for parity with the
// TypeScript and Python bindings.
type VerifiedBlock struct {
	BlockNumber      uint64
	Timestamp        uint64
	BlockHash        string
	StateRoot        string
	ReceiptsRoot     string
	TransactionsRoot string
	ParentHash       string
	AuthPath         AuthPath
}

// VerifyHeaderWithProof verifies SSZ-encoded HeaderWithProof bytes
// against the canonized accumulators (and any HistoricalSummaries
// snapshot the Rust core was constructed with — the Go binding currently
// uses the default empty snapshot, so post-Capella verification will
// fail until/unless the binding is extended; pre-merge and merge→Capella
// work today).
//
// On failure returns a non-nil error with the underlying Rust message.
func VerifyHeaderWithProof(bytes []byte) (*VerifiedBlock, error) {
	var ptr *C.uint8_t
	if len(bytes) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&bytes[0]))
	}
	res := C.eth_historian_verify_header_with_proof(ptr, C.size_t(len(bytes)))
	if res.ok == 0 {
		msg := "eth-historian: unknown error"
		if res.error != nil {
			msg = C.GoString(res.error)
			C.eth_historian_free_error(res.error)
		}
		return nil, errors.New(msg)
	}
	return &VerifiedBlock{
		BlockNumber:      uint64(res.block_number),
		Timestamp:        uint64(res.timestamp),
		BlockHash:        hexEncode(res.block_hash[:]),
		StateRoot:        hexEncode(res.state_root[:]),
		ReceiptsRoot:     hexEncode(res.receipts_root[:]),
		TransactionsRoot: hexEncode(res.transactions_root[:]),
		ParentHash:       hexEncode(res.parent_hash[:]),
		AuthPath:         AuthPath(res.auth_path),
	}, nil
}

// VerifyTransactionInclusion verifies a transaction is in a block at
// txIndex, against the authenticated transactionsRoot.
//
// transactionsRoot must be 32 bytes. rawTx is wire-format (legacy: RLP;
// typed: type-byte || RLP). proofNodes is the MPT path from the root
// down to the leaf. Returns nil on success; non-nil error on failure
// with the underlying Rust message.
func VerifyTransactionInclusion(transactionsRoot []byte, txIndex uint64, rawTx []byte, proofNodes [][]byte) error {
	return runInclusion(
		transactionsRoot,
		"transactionsRoot",
		txIndex,
		rawTx,
		proofNodes,
		func(rootPtr *C.uint8_t, txPtr *C.uint8_t, txLen C.size_t, ptrs **C.uint8_t, lens *C.size_t, n C.size_t) *C.char {
			return C.eth_historian_verify_transaction_inclusion(
				rootPtr, C.uint64_t(txIndex), txPtr, txLen, ptrs, lens, n,
			)
		},
	)
}

// VerifyReceiptInclusion verifies a receipt is in a block at
// receiptIndex, against the authenticated receiptsRoot.
//
// receiptsRoot must be 32 bytes. rawReceipt is wire-format (legacy: RLP;
// typed: type-byte || RLP). proofNodes is the MPT path from the root
// down to the leaf. Returns nil on success; non-nil error on failure.
func VerifyReceiptInclusion(receiptsRoot []byte, receiptIndex uint64, rawReceipt []byte, proofNodes [][]byte) error {
	return runInclusion(
		receiptsRoot,
		"receiptsRoot",
		receiptIndex,
		rawReceipt,
		proofNodes,
		func(rootPtr *C.uint8_t, valPtr *C.uint8_t, valLen C.size_t, ptrs **C.uint8_t, lens *C.size_t, n C.size_t) *C.char {
			return C.eth_historian_verify_receipt_inclusion(
				rootPtr, C.uint64_t(receiptIndex), valPtr, valLen, ptrs, lens, n,
			)
		},
	)
}

// runInclusion handles the cgo bookkeeping common to both inclusion
// helpers: argument validation, marshalling proof nodes into parallel
// C arrays, calling the inclusion FFI, and translating the C-string
// error path into Go's error type.
func runInclusion(
	root []byte,
	rootField string,
	_ uint64,
	rawValue []byte,
	proofNodes [][]byte,
	call func(rootPtr *C.uint8_t, valPtr *C.uint8_t, valLen C.size_t, ptrs **C.uint8_t, lens *C.size_t, n C.size_t) *C.char,
) error {
	if len(root) != 32 {
		return fmt.Errorf("eth-historian: %s must be 32 bytes, got %d", rootField, len(root))
	}

	var rootPtr *C.uint8_t
	rootPtr = (*C.uint8_t)(unsafe.Pointer(&root[0]))

	var valPtr *C.uint8_t
	if len(rawValue) > 0 {
		valPtr = (*C.uint8_t)(unsafe.Pointer(&rawValue[0]))
	}

	// Marshal `proofNodes` into a parallel ptr+len array. Pinning the
	// underlying slice headers via the local `ptrs`/`lens` slices keeps
	// the Go GC from moving them while the C call runs.
	n := len(proofNodes)
	ptrs := make([]*C.uint8_t, n)
	lens := make([]C.size_t, n)
	for i, node := range proofNodes {
		if len(node) > 0 {
			ptrs[i] = (*C.uint8_t)(unsafe.Pointer(&node[0]))
		}
		lens[i] = C.size_t(len(node))
	}

	var ptrsPtr **C.uint8_t
	var lensPtr *C.size_t
	if n > 0 {
		ptrsPtr = (**C.uint8_t)(unsafe.Pointer(&ptrs[0]))
		lensPtr = (*C.size_t)(unsafe.Pointer(&lens[0]))
	}

	cerr := call(rootPtr, valPtr, C.size_t(len(rawValue)), ptrsPtr, lensPtr, C.size_t(n))
	// Pin proofNodes / rawValue / root through the call (KeepAlive is
	// the cgo idiom; the variables are unused after this point but
	// must outlive the FFI call).
	runtime.KeepAlive(root)
	runtime.KeepAlive(rawValue)
	runtime.KeepAlive(proofNodes)
	runtime.KeepAlive(ptrs)
	runtime.KeepAlive(lens)

	if cerr == nil {
		return nil
	}
	msg := C.GoString(cerr)
	C.eth_historian_free_error(cerr)
	return errors.New(msg)
}

// CanonizedFingerprints returns the SHA-256 fingerprints of the embedded
// canonized accumulator binaries shipped with this build. Useful for
// pinning / supply-chain audit; values must match the published constants
// for a trusted build.
type CanonizedFingerprints struct {
	MergeMaccBinSha256       string
	HistoricalRootsSszSha256 string
}

func GetCanonizedFingerprints() CanonizedFingerprints {
	var merge [32]C.uint8_t
	var roots [32]C.uint8_t
	C.eth_historian_canonized_fingerprints(&merge[0], &roots[0])

	mergeBytes := make([]byte, 32)
	rootsBytes := make([]byte, 32)
	for i := 0; i < 32; i++ {
		mergeBytes[i] = byte(merge[i])
		rootsBytes[i] = byte(roots[i])
	}
	return CanonizedFingerprints{
		MergeMaccBinSha256:       "0x" + hex.EncodeToString(mergeBytes),
		HistoricalRootsSszSha256: "0x" + hex.EncodeToString(rootsBytes),
	}
}

func hexEncode(b []C.uint8_t) string {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = byte(b[i])
	}
	return "0x" + hex.EncodeToString(out)
}
