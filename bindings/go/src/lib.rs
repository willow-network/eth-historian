//! C ABI shim for Go bindings.
//!
//! Mirrors the wasm and Python surface: a single
//! `eth_historian_verify_header_with_proof(bytes, len) -> Result` call
//! plus `eth_historian_canonized_fingerprints` for the integrity-check
//! constants. The Result struct embeds the verified header fields so
//! the success path doesn't allocate (no Go `runtime.Free` needed); only
//! the error path returns a Rust-allocated C string that the caller must
//! free via `eth_historian_free_error`.

use std::ffi::{c_char, CString};
use std::ptr;
use std::sync::OnceLock;

use eth_historian::portal_types::HeaderWithProof;
use eth_historian::{AuthPath, Verifier};
use ssz::Decode;
use tokio::runtime::Runtime;

fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to construct tokio runtime for eth-historian Go binding")
    })
}

/// Auth path discriminator. Mirrors `eth_historian::AuthPath`. Stable
/// numeric values so the Go enum can rely on them.
#[repr(u8)]
#[derive(Copy, Clone)]
pub enum FfiAuthPath {
    HistoricalHashes = 0,
    HistoricalRoots = 1,
    HistoricalSummariesCapella = 2,
    HistoricalSummariesDeneb = 3,
}

#[repr(C)]
pub struct FfiVerifyResult {
    /// 1 on success, 0 on failure. Look at `error` only when 0.
    pub ok: u8,
    pub block_number: u64,
    pub timestamp: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub transactions_root: [u8; 32],
    pub parent_hash: [u8; 32],
    pub auth_path: u8,
    /// Null on success. Rust-allocated C string on failure — caller
    /// **must** free via `eth_historian_free_error`.
    pub error: *mut c_char,
}

impl Default for FfiVerifyResult {
    fn default() -> Self {
        Self {
            ok: 0,
            block_number: 0,
            timestamp: 0,
            block_hash: [0; 32],
            state_root: [0; 32],
            receipts_root: [0; 32],
            transactions_root: [0; 32],
            parent_hash: [0; 32],
            auth_path: 0,
            error: ptr::null_mut(),
        }
    }
}

fn make_error(msg: String) -> FfiVerifyResult {
    let mut r = FfiVerifyResult::default();
    r.error = CString::new(msg)
        .unwrap_or_else(|_| CString::new("internal: unencodable error message").unwrap())
        .into_raw();
    r
}

/// Verify SSZ-encoded `HeaderWithProof` bytes.
///
/// # Safety
///
/// `bytes` must point to at least `len` valid bytes. Passing a null
/// pointer with non-zero `len` is undefined behavior. `len == 0` is
/// safe (returns an SSZ-decode error).
#[no_mangle]
pub unsafe extern "C" fn eth_historian_verify_header_with_proof(
    bytes: *const u8,
    len: usize,
) -> FfiVerifyResult {
    if bytes.is_null() && len != 0 {
        return make_error("eth_historian: null bytes pointer with non-zero len".into());
    }

    let slice = if len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(bytes, len)
    };

    let hwp = match HeaderWithProof::from_ssz_bytes(slice) {
        Ok(h) => h,
        Err(e) => return make_error(format!("SSZ decode failed: {:?}", e)),
    };

    let verifier = Verifier::new();
    let verified = match runtime().block_on(verifier.verify(&hwp)) {
        Ok(v) => v,
        Err(e) => return make_error(format!("verification failed: {}", e)),
    };

    let h = &verified.header;
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(h.hash_slow().as_slice());
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(h.state_root.as_slice());
    let mut receipts_root = [0u8; 32];
    receipts_root.copy_from_slice(h.receipts_root.as_slice());
    let mut transactions_root = [0u8; 32];
    transactions_root.copy_from_slice(h.transactions_root.as_slice());
    let mut parent_hash = [0u8; 32];
    parent_hash.copy_from_slice(h.parent_hash.as_slice());

    let auth_path = match verified.auth_path {
        AuthPath::HistoricalHashes => 0,
        AuthPath::HistoricalRoots => 1,
        AuthPath::HistoricalSummariesCapella => 2,
        AuthPath::HistoricalSummariesDeneb => 3,
    };

    FfiVerifyResult {
        ok: 1,
        block_number: h.number,
        timestamp: h.timestamp,
        block_hash,
        state_root,
        receipts_root,
        transactions_root,
        parent_hash,
        auth_path,
        error: ptr::null_mut(),
    }
}

/// Free a `FfiVerifyResult.error` returned by a failed verification.
/// Must NOT be called on a null pointer; safe to skip if `result.ok == 1`.
///
/// # Safety
///
/// `error` must be a pointer previously returned in `FfiVerifyResult.error`.
#[no_mangle]
pub unsafe extern "C" fn eth_historian_free_error(error: *mut c_char) {
    if !error.is_null() {
        drop(CString::from_raw(error));
    }
}

/// Write the SHA-256 fingerprints of the embedded canonized accumulator
/// binaries into the two 32-byte caller-provided buffers. Useful for
/// audit / pinning.
///
/// # Safety
///
/// Both pointers must be valid for 32 bytes of write. Passing nulls is UB.
#[no_mangle]
pub unsafe extern "C" fn eth_historian_canonized_fingerprints(
    merge_macc_sha256_out: *mut u8,
    historical_roots_sha256_out: *mut u8,
) {
    use eth_historian::constants::{HISTORICAL_ROOTS_SSZ_SHA256, MERGE_MACC_BIN_SHA256};
    if !merge_macc_sha256_out.is_null() {
        ptr::copy_nonoverlapping(MERGE_MACC_BIN_SHA256.as_ptr(), merge_macc_sha256_out, 32);
    }
    if !historical_roots_sha256_out.is_null() {
        ptr::copy_nonoverlapping(
            HISTORICAL_ROOTS_SSZ_SHA256.as_ptr(),
            historical_roots_sha256_out,
            32,
        );
    }
}
