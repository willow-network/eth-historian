package eth_historian

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../tests/fixtures/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "0x")
	bytes, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %s: %v", name, err)
	}
	return bytes
}

func TestCanonizedFingerprints_MatchPublishedConstants(t *testing.T) {
	fp := GetCanonizedFingerprints()
	const expectedMerge = "0xa2368bfa82a89a898b31dca6f37aa287918bd671bd74058912bc440c2288d791"
	const expectedRoots = "0x64ed2cbed13a65c224b471f53b5f832030c11e73710e2702121e7b1a5082a316"
	if fp.MergeMaccBinSha256 != expectedMerge {
		t.Errorf("merge_macc.bin SHA-256 mismatch:\n  got:      %s\n  expected: %s", fp.MergeMaccBinSha256, expectedMerge)
	}
	if fp.HistoricalRootsSszSha256 != expectedRoots {
		t.Errorf("historical_roots.ssz SHA-256 mismatch:\n  got:      %s\n  expected: %s", fp.HistoricalRootsSszSha256, expectedRoots)
	}
}

func TestVerifyHeaderWithProof_PreMergeRealBlock(t *testing.T) {
	bytes := loadFixture(t, "header_with_proof_1000010.hex")
	v, err := VerifyHeaderWithProof(bytes)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if v.BlockNumber != 1_000_010 {
		t.Errorf("block_number: got %d, want 1000010", v.BlockNumber)
	}
	if v.AuthPath != HistoricalHashes {
		t.Errorf("auth_path: got %s, want HistoricalHashes", v.AuthPath)
	}
	const expectedStateRoot = "0xafbf9bfd23008e8df44a83bb51ade45b993b3253fbce69cf7cec5d628eca6d45"
	if v.StateRoot != expectedStateRoot {
		t.Errorf("state_root mismatch:\n  got:      %s\n  expected: %s", v.StateRoot, expectedStateRoot)
	}
}

func TestVerifyHeaderWithProof_MergeToCapellaRealBlock(t *testing.T) {
	bytes := loadFixture(t, "header_with_proof_15539558.hex")
	v, err := VerifyHeaderWithProof(bytes)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if v.BlockNumber != 15_539_558 {
		t.Errorf("block_number: got %d, want 15539558", v.BlockNumber)
	}
	if v.AuthPath != HistoricalRoots {
		t.Errorf("auth_path: got %s, want HistoricalRoots", v.AuthPath)
	}
}

func TestVerifyHeaderWithProof_EmptyBytesRejected(t *testing.T) {
	_, err := VerifyHeaderWithProof([]byte{})
	if err == nil {
		t.Fatal("empty bytes should fail SSZ decode")
	}
	if !strings.Contains(err.Error(), "SSZ decode") {
		t.Errorf("expected SSZ decode error, got: %v", err)
	}
}

func TestVerifyHeaderWithProof_GarbageRejected(t *testing.T) {
	garbage := []byte("not-valid-ssz-content-not-valid-ssz-content-not-valid")
	_, err := VerifyHeaderWithProof(garbage)
	if err == nil {
		t.Fatal("garbage bytes should fail")
	}
}

func TestAuthPath_String(t *testing.T) {
	cases := []struct {
		path AuthPath
		want string
	}{
		{HistoricalHashes, "HistoricalHashes"},
		{HistoricalRoots, "HistoricalRoots"},
		{HistoricalSummariesCapella, "HistoricalSummariesCapella"},
		{HistoricalSummariesDeneb, "HistoricalSummariesDeneb"},
		{AuthPath(99), "AuthPath(99)"},
	}
	for _, c := range cases {
		if got := c.path.String(); got != c.want {
			t.Errorf("AuthPath(%d).String() = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestVerifyTransactionInclusion_RejectsWrongRootLength(t *testing.T) {
	err := VerifyTransactionInclusion([]byte{0x01, 0x02}, 0, []byte("tx"), nil)
	if err == nil {
		t.Fatal("expected error for non-32-byte root")
	}
	if !strings.Contains(err.Error(), "must be 32 bytes") {
		t.Errorf("expected 'must be 32 bytes' message, got: %v", err)
	}
}

func TestVerifyReceiptInclusion_RejectsWrongRootLength(t *testing.T) {
	err := VerifyReceiptInclusion(make([]byte, 31), 0, []byte("r"), nil)
	if err == nil {
		t.Fatal("expected error for non-32-byte root")
	}
	if !strings.Contains(err.Error(), "must be 32 bytes") {
		t.Errorf("expected 'must be 32 bytes' message, got: %v", err)
	}
}

func TestVerifyTransactionInclusion_EmptyProofRejected(t *testing.T) {
	// 32-byte root is structurally valid; Rust core rejects the
	// empty-proof path with `MptInclusion`. This proves the FFI surface
	// correctly forwards calls into the verifier.
	root := make([]byte, 32)
	err := VerifyTransactionInclusion(root, 0, []byte("tx"), nil)
	if err == nil {
		t.Fatal("expected MPT verification failure for empty proof")
	}
}
