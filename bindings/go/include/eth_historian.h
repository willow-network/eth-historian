/*
 * eth-historian C ABI for Go bindings.
 *
 * See bindings/go/src/lib.rs for the full Rust-side documentation.
 */

#ifndef ETH_HISTORIAN_H
#define ETH_HISTORIAN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t  ok;                       /* 1 = success, 0 = failure */
    uint64_t block_number;
    uint64_t timestamp;
    uint8_t  block_hash[32];
    uint8_t  state_root[32];
    uint8_t  receipts_root[32];
    uint8_t  transactions_root[32];
    uint8_t  parent_hash[32];
    uint8_t  auth_path;                /* 0=HistoricalHashes 1=HistoricalRoots
                                          2=HistoricalSummariesCapella
                                          3=HistoricalSummariesDeneb */
    char*    error;                    /* NULL on success, malloc'd on failure */
} EthHistorianVerifyResult;

/*
 * Verify SSZ-encoded HeaderWithProof bytes. On failure, `result.error`
 * contains a malloc'd C string the caller MUST free via
 * eth_historian_free_error().
 */
EthHistorianVerifyResult eth_historian_verify_header_with_proof(
    const uint8_t* bytes,
    size_t         len
);

void eth_historian_free_error(char* error);

/*
 * Inclusion verification. Both functions return NULL on success;
 * on failure they return a malloc'd C string the caller MUST free via
 * eth_historian_free_error().
 *
 * `proof_node_ptrs` and `proof_node_lens` are parallel arrays of length
 * `num_proof_nodes`: the i-th proof node is `proof_node_ptrs[i]` of
 * length `proof_node_lens[i]` bytes.
 */
char* eth_historian_verify_transaction_inclusion(
    const uint8_t*       transactions_root,   /* 32 bytes */
    uint64_t             tx_index,
    const uint8_t*       raw_tx,
    size_t               raw_tx_len,
    const uint8_t* const* proof_node_ptrs,
    const size_t*        proof_node_lens,
    size_t               num_proof_nodes
);

char* eth_historian_verify_receipt_inclusion(
    const uint8_t*       receipts_root,       /* 32 bytes */
    uint64_t             receipt_index,
    const uint8_t*       raw_receipt,
    size_t               raw_receipt_len,
    const uint8_t* const* proof_node_ptrs,
    const size_t*        proof_node_lens,
    size_t               num_proof_nodes
);

void eth_historian_canonized_fingerprints(
    uint8_t merge_macc_sha256_out[32],
    uint8_t historical_roots_sha256_out[32]
);

#ifdef __cplusplus
}
#endif

#endif /* ETH_HISTORIAN_H */
