"""Basic smoke tests. Run via `maturin develop && pytest`."""

import pytest
from eth_historian import canonized_fingerprints, verify_header_with_proof, VerifiedBlock


def test_canonized_fingerprints_match_published():
    """The wheel must ship trin@30aeef8's canonized accumulators."""
    fp = canonized_fingerprints()
    assert (
        fp["merge_macc_bin_sha256"]
        == "0xa2368bfa82a89a898b31dca6f37aa287918bd671bd74058912bc440c2288d791"
    )
    assert (
        fp["historical_roots_ssz_sha256"]
        == "0x64ed2cbed13a65c224b471f53b5f832030c11e73710e2702121e7b1a5082a316"
    )


def test_empty_bytes_rejected():
    """An empty payload should fail SSZ decode, not crash."""
    with pytest.raises(ValueError):
        verify_header_with_proof(b"")


def test_garbage_bytes_rejected():
    """Random bytes should fail SSZ decode cleanly."""
    with pytest.raises(ValueError):
        verify_header_with_proof(b"not-valid-ssz-content" * 50)
