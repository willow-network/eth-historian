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

void eth_historian_canonized_fingerprints(
    uint8_t merge_macc_sha256_out[32],
    uint8_t historical_roots_sha256_out[32]
);

#ifdef __cplusplus
}
#endif

#endif /* ETH_HISTORIAN_H */
