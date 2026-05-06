"""Python re-export shim. The actual module is built by maturin from
`bindings/python/src/lib.rs`. This file just makes the package importable
in editable mode (`pip install -e .`)."""

from eth_historian._native import (  # type: ignore[import-not-found]
    VerifiedBlock,
    canonized_fingerprints,
    verify_header_with_proof,
    verify_receipt_inclusion,
    verify_transaction_inclusion,
    __version__,
)

__all__ = [
    "VerifiedBlock",
    "verify_header_with_proof",
    "verify_receipt_inclusion",
    "verify_transaction_inclusion",
    "canonized_fingerprints",
    "__version__",
]
