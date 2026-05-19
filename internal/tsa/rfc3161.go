// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package tsa parses and (partially) verifies RFC 3161 Time-Stamp Responses
// produced by CKNF's media-store TSA pipeline (see CKNF Python
// `cknf.tsa_client.request_timestamp`).
//
// v0.1.0 scope:
//
//   - Parse DER-encoded TimeStampResponse via the digitorus/timestamp
//     library (battle-tested in Sigstore / Cosign).
//   - Verify that the TSR's hashed-message field matches the expected
//     SHA-256 of the audio.
//   - Surface the TSA-provided timestamp and the signing-certificate
//     subject so an operator can inspect them.
//
// v0.2.0 deferred (Plan §7 Risk #3 mitigation):
//
//   - Cryptographic signature verification against a bundled trust root
//     list (freetsa.org, DigiCert, Sectigo). Requires shipping CA-bundle
//     bytes inside the verifier binary; we defer until we have a stable
//     trust-root set blessed by Hubert.
//
// Note on pack-vs-side-input layout: CKNF stores the .tsr file alongside
// the recording (`<rec_dir>/original.tsr`) and does NOT embed it in the
// Legal-Pack ZIP. The verifier therefore accepts the TSR as a separate
// CLI argument (`--tsr <path>`). When the operator forgets the flag, the
// orchestrator reports a SKIPPED check, not a FAIL — TSA absence is a
// legal state of CKNF recordings, not a tampering signal.
package tsa

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/digitorus/timestamp"
)

// TimestampInfo is the high-level summary surfaced to the orchestrator
// and the CLI report.
type TimestampInfo struct {
	SerialNumber       string
	HashedMessage      []byte
	HashAlgorithm      string
	GenTime            string
	SigningCertSubject string
}

// Parse decodes a DER-encoded TimeStampResponse and returns the
// TimestampInfo summary. Returns an error if the bytes are not parseable
// RFC 3161 (corrupt file, wrong file type).
//
// The CKNF media-store writes the full RFC 3161 TimeStampResponse
// (status block + inner TimeStampToken) into `original.tsr`. We therefore
// use digitorus's `ParseResponse` rather than `Parse`, which expects the
// inner PKCS7 SignedData only.
func Parse(tsrBytes []byte) (*TimestampInfo, error) {
	if len(tsrBytes) == 0 {
		return nil, fmt.Errorf("tsa parse: empty TSR bytes")
	}
	t, err := timestamp.ParseResponse(tsrBytes)
	if err != nil {
		return nil, fmt.Errorf("tsa parse: %w", err)
	}
	info := &TimestampInfo{
		HashedMessage: t.HashedMessage,
		HashAlgorithm: t.HashAlgorithm.String(),
	}
	if t.SerialNumber != nil {
		info.SerialNumber = t.SerialNumber.String()
	}
	if !t.Time.IsZero() {
		info.GenTime = t.Time.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if len(t.Certificates) > 0 {
		info.SigningCertSubject = t.Certificates[0].Subject.String()
	}
	return info, nil
}

// ParseFile reads the TSR bytes from disk and returns Parse(bytes).
func ParseFile(path string) (*TimestampInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tsa parse file %q: %w", path, err)
	}
	return Parse(data)
}

// VerifyDigest confirms that the TSR's hashed-message field equals the
// given expectedSHA256 (lowercase hex, 64 chars). Mismatch means the
// TSR was issued for different content than the audio in the Legal-Pack
// — either the TSR was substituted, or the audio was modified after
// timestamping.
//
// Returns nil on PASS; a descriptive error on FAIL.
func VerifyDigest(info *TimestampInfo, expectedSHA256 string) error {
	if info == nil {
		return fmt.Errorf("tsa verify digest: timestamp info is nil")
	}
	if len(info.HashedMessage) == 0 {
		return fmt.Errorf("tsa verify digest: TSR carries no hashed message")
	}
	got := hex.EncodeToString(info.HashedMessage)
	if got != expectedSHA256 {
		return fmt.Errorf(
			"tsa verify digest: MISMATCH\n"+
				"    expected (audio SHA-256): %s\n"+
				"    TSR-claimed digest:       %s\n"+
				"  → the TSR was issued for different content than the audio in the pack",
			expectedSHA256, got,
		)
	}
	return nil
}

// VerifyBytes is a one-shot: parse + verify in a single call. The expected
// digest is the lowercase-hex SHA-256 of the audio bytes — the caller can
// compute it via the helper below or pull it from sha256_report.txt.
func VerifyBytes(tsrBytes []byte, expectedSHA256 string) (*TimestampInfo, error) {
	info, err := Parse(tsrBytes)
	if err != nil {
		return nil, err
	}
	if err := VerifyDigest(info, expectedSHA256); err != nil {
		return info, err
	}
	return info, nil
}

// SHA256OfBytes returns the lowercase hex SHA-256 of the input. Provided
// so callers can fold "compute the audio digest" into their flow without
// pulling crypto/sha256 in directly.
func SHA256OfBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
