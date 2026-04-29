"""Python re-export shim. The actual module is built by maturin from
`bindings/python/src/lib.rs`. This file just makes the package importable
in editable mode (`pip install -e .`)."""

from eth_historian._native import (  # type: ignore[import-not-found]
    VerifiedBlock,
    verify_header_with_proof,
    canonized_fingerprints,
    __version__,
)

__all__ = [
    "VerifiedBlock",
    "verify_header_with_proof",
    "canonized_fingerprints",
    "__version__",
]
