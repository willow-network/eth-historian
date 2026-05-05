//! Python bindings for eth-historian.
//!
//! Mirrors the wasm-bindgen surface: a single async function
//! `verify_header_with_proof(bytes)` plus `canonized_fingerprints()` for
//! pinning audit. Apps fetch SSZ-encoded `HeaderWithProof` bytes their
//! own way (Portal sidecar via httpx, Era1 file via filesystem, etc.)
//! and pass them in.

use std::sync::OnceLock;

use eth_historian::{HeaderWithProof, Verifier};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use ssz::Decode;
use tokio::runtime::Runtime;

fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to construct tokio runtime for eth-historian Python binding")
    })
}

#[pyclass(name = "VerifiedBlock")]
#[derive(Clone)]
struct PyVerifiedBlock {
    #[pyo3(get)]
    block_number: u64,
    #[pyo3(get)]
    block_hash: String,
    #[pyo3(get)]
    state_root: String,
    #[pyo3(get)]
    receipts_root: String,
    #[pyo3(get)]
    transactions_root: String,
    #[pyo3(get)]
    parent_hash: String,
    #[pyo3(get)]
    timestamp: u64,
    #[pyo3(get)]
    auth_path: String,
}

#[pymethods]
impl PyVerifiedBlock {
    fn __repr__(&self) -> String {
        format!(
            "VerifiedBlock(block_number={}, auth_path={:?}, block_hash={:?})",
            self.block_number, self.auth_path, self.block_hash
        )
    }
}

/// Verify SSZ-encoded `HeaderWithProof` bytes.
///
/// Synchronous — returns a `VerifiedBlock` directly, or raises
/// `ValueError` on verification failure. Verification is CPU-bound
/// (SSZ decode + Merkle proof check), no I/O involved, so a sync API
/// is appropriate and lets callers use it from both sync and async
/// Python code without runtime ceremony.
#[pyfunction]
fn verify_header_with_proof(py: Python<'_>, bytes: Vec<u8>) -> PyResult<PyVerifiedBlock> {
    py.allow_threads(|| {
        let verifier = Verifier::new();

        let hwp = HeaderWithProof::from_ssz_bytes(&bytes).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("SSZ decode failed: {:?}", e))
        })?;

        let verified = runtime().block_on(verifier.verify(&hwp)).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("verification failed: {}", e))
        })?;

        let h = &verified.header;
        Ok(PyVerifiedBlock {
            block_number: h.number,
            block_hash: format!("0x{}", hex::encode(h.hash_slow().as_slice())),
            state_root: format!("0x{}", hex::encode(h.state_root.as_slice())),
            receipts_root: format!("0x{}", hex::encode(h.receipts_root.as_slice())),
            transactions_root: format!("0x{}", hex::encode(h.transactions_root.as_slice())),
            parent_hash: format!("0x{}", hex::encode(h.parent_hash.as_slice())),
            timestamp: h.timestamp,
            auth_path: format!("{:?}", verified.auth_path),
        })
    })
}

/// Returns the SHA-256 fingerprints of the embedded canonized accumulator
/// binaries as a dict. Useful for clients that want to double-check the
/// installed wheel ships the constants they expect.
#[pyfunction]
fn canonized_fingerprints<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    use eth_historian::constants::{HISTORICAL_ROOTS_SSZ_SHA256, MERGE_MACC_BIN_SHA256};
    let d = PyDict::new(py);
    d.set_item(
        "merge_macc_bin_sha256",
        format!("0x{}", hex::encode(MERGE_MACC_BIN_SHA256)),
    )?;
    d.set_item(
        "historical_roots_ssz_sha256",
        format!("0x{}", hex::encode(HISTORICAL_ROOTS_SSZ_SHA256)),
    )?;
    Ok(d)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyVerifiedBlock>()?;
    m.add_function(wrap_pyfunction!(verify_header_with_proof, m)?)?;
    m.add_function(wrap_pyfunction!(canonized_fingerprints, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
