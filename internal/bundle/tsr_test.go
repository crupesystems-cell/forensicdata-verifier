// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/crupesystems-cell/forensicdata-verifier/internal/tsa"
)

func sha256Bytes(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// ── verifyTSRImprint ────────────────────────────────────────────────────────

func TestVerifyTSRImprint_NilInfo(t *testing.T) {
	if err := verifyTSRImprint(nil, "abcd"); err == nil {
		t.Fatalf("want error on nil info, got nil")
	}
}

func TestVerifyTSRImprint_WrongAlgorithm(t *testing.T) {
	info := &tsa.TimestampInfo{
		HashAlgorithm: "SHA-1",
		HashedMessage: sha256Bytes("anything"),
	}
	err := verifyTSRImprint(info, "deadbeef")
	if err == nil {
		t.Fatalf("want algorithm error, got nil")
	}
	if !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("err %q should mention SHA-256 requirement", err)
	}
}

func TestVerifyTSRImprint_AcceptsSHA256NameVariants(t *testing.T) {
	for _, name := range []string{"SHA-256", "SHA256", "sha-256", "sha256", "Sha-256"} {
		t.Run(name, func(t *testing.T) {
			imprint := sha256Bytes("manifest-canonical-bytes")
			info := &tsa.TimestampInfo{
				HashAlgorithm: name,
				HashedMessage: imprint,
			}
			expectedHex := tsa.SHA256OfBytes([]byte("manifest-canonical-bytes"))
			if err := verifyTSRImprint(info, expectedHex); err != nil {
				t.Fatalf("algo name %q rejected: %v", name, err)
			}
		})
	}
}

func TestVerifyTSRImprint_ImprintMismatch(t *testing.T) {
	info := &tsa.TimestampInfo{
		HashAlgorithm: "SHA-256",
		HashedMessage: sha256Bytes("CONTENT A"),
	}
	expectedHexForB := tsa.SHA256OfBytes([]byte("CONTENT B"))
	err := verifyTSRImprint(info, expectedHexForB)
	if err == nil {
		t.Fatalf("want mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "MISMATCH") {
		t.Fatalf("err %q should mention MISMATCH", err)
	}
}

func TestVerifyTSRImprint_EmptyHashedMessage(t *testing.T) {
	info := &tsa.TimestampInfo{
		HashAlgorithm: "SHA-256",
		HashedMessage: nil,
	}
	err := verifyTSRImprint(info, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatalf("want error on empty hashed message, got nil")
	}
}

func TestVerifyTSRImprint_HappyPath(t *testing.T) {
	const content = "canonical manifest bytes — pretend these are the §6.1 form"
	imprint := sha256Bytes(content)
	info := &tsa.TimestampInfo{
		HashAlgorithm: "SHA-256",
		HashedMessage: imprint,
	}
	expectedHex := tsa.SHA256OfBytes([]byte(content))
	if err := verifyTSRImprint(info, expectedHex); err != nil {
		t.Fatalf("happy path rejected: %v", err)
	}
}
