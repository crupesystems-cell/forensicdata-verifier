// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Stage B.2 — sha256_report.txt Parser.
//
// The golden text-fixture below mirrors the layout produced by
// `legal_pack._build_sha256_report` in the CKNF Python source. If the
// Python template ever changes (line order, label spelling, separator
// width), this fixture and the parser must be updated in lock-step.

package legalpack

import (
	"strings"
	"testing"
)

// goldenReport is byte-for-byte compatible with the format emitted by
// CKNF `legal_pack._build_sha256_report`. Values are synthetic but the
// shape is canonical.
const goldenReport = `CKNF SHA-256 INTEGRITY REPORT
============================================================
Recording ID:         Hubert_Test_2026-05-19_abcdef12
Audio File:           original.m4a
File Size:            123456 bytes
SHA-256:              0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

Created:              2026-05-19T10:00:00+00:00
Language:             de-DE

Chain Hash:           aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Chain Prev:           bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
Identity Fingerprint: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

TSA Status:           PRESENT
TSA Token Size:       4321 bytes
TSA Standard:         RFC 3161

Verification:
  shasum -a 256 original.m4a
  → must equal 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

If a TSA token (.tsr) is present, verify with:
  openssl ts -verify -data original.m4a -in original.tsr -CAfile <tsa_ca>

============================================================
`

// goldenReportOffline is the offline-fallback shape: TSA Status: NOT AVAILABLE
// with a note line and no token size.
const goldenReportOffline = `CKNF SHA-256 INTEGRITY REPORT
============================================================
Recording ID:         Hubert_Test_2026-05-19_offline00
Audio File:           original.wav
File Size:            9999 bytes
SHA-256:              feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface

Created:              2026-05-19T10:05:00+00:00
Language:             en-US

Chain Hash:           1111111111111111111111111111111111111111111111111111111111111111
Chain Prev:           (genesis)
Identity Fingerprint: (none)

TSA Status:           NOT AVAILABLE - offline (deferred retry available)
TSA Note:             SHA-256 digest is deterministic and remains a forensic anchor.
                      A timestamp can be obtained later via Sync Timestamps.

Verification:
  shasum -a 256 original.wav
  → must equal feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface

If a TSA token (.tsr) is present, verify with:
  openssl ts -verify -data original.wav -in original.tsr -CAfile <tsa_ca>

============================================================
`

// ─────────────────────────────────────────────────────────────────────────────
// Parse — happy path (TSA present)
// ─────────────────────────────────────────────────────────────────────────────

func TestParseSha256Report_Happy(t *testing.T) {
	r, err := ParseSha256Report([]byte(goldenReport))
	if err != nil {
		t.Fatalf("ParseSha256Report: %v", err)
	}
	if r.RecordingID != "Hubert_Test_2026-05-19_abcdef12" {
		t.Errorf("RecordingID: %q", r.RecordingID)
	}
	if r.AudioFilename != "original.m4a" {
		t.Errorf("AudioFilename: %q", r.AudioFilename)
	}
	if r.FileSize != 123456 {
		t.Errorf("FileSize: %d", r.FileSize)
	}
	wantSHA := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if r.SHA256 != wantSHA {
		t.Errorf("SHA256: %q", r.SHA256)
	}
	if r.CreatedAt != "2026-05-19T10:00:00+00:00" {
		t.Errorf("CreatedAt: %q", r.CreatedAt)
	}
	if r.Language != "de-DE" {
		t.Errorf("Language: %q", r.Language)
	}
	if r.ChainHash != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("ChainHash: %q", r.ChainHash)
	}
	if r.ChainPrev != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Errorf("ChainPrev: %q", r.ChainPrev)
	}
	if r.IdentityFingerprint != "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" {
		t.Errorf("IdentityFingerprint: %q", r.IdentityFingerprint)
	}
	if !r.TSAPresent {
		t.Errorf("TSAPresent: got false, want true")
	}
	if r.TSATokenSize != 4321 {
		t.Errorf("TSATokenSize: %d", r.TSATokenSize)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Parse — offline-fallback path (TSA NOT AVAILABLE, (genesis) chain_prev, (none) identity)
// ─────────────────────────────────────────────────────────────────────────────

func TestParseSha256Report_Offline(t *testing.T) {
	r, err := ParseSha256Report([]byte(goldenReportOffline))
	if err != nil {
		t.Fatalf("ParseSha256Report: %v", err)
	}
	if r.AudioFilename != "original.wav" {
		t.Errorf("AudioFilename: %q", r.AudioFilename)
	}
	if r.FileSize != 9999 {
		t.Errorf("FileSize: %d", r.FileSize)
	}
	if r.TSAPresent {
		t.Errorf("TSAPresent: got true, want false (offline fallback)")
	}
	if r.TSATokenSize != 0 {
		t.Errorf("TSATokenSize on offline: got %d, want 0", r.TSATokenSize)
	}
	// (genesis) and (none) are sentinel placeholders, NOT real hash values.
	// The parser must surface them as empty strings + flags.
	if r.ChainPrev != "" {
		t.Errorf("ChainPrev for (genesis) should normalize to empty, got %q", r.ChainPrev)
	}
	if !r.ChainPrevIsGenesis {
		t.Error("ChainPrevIsGenesis should be true for (genesis) placeholder")
	}
	if r.IdentityFingerprint != "" {
		t.Errorf("IdentityFingerprint for (none) should normalize to empty, got %q", r.IdentityFingerprint)
	}
	if !r.IdentityFingerprintIsNone {
		t.Error("IdentityFingerprintIsNone should be true for (none) placeholder")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Error paths
// ─────────────────────────────────────────────────────────────────────────────

func TestParseSha256Report_Empty(t *testing.T) {
	_, err := ParseSha256Report(nil)
	if err == nil {
		t.Error("expected error on nil input, got nil")
	}
	_, err = ParseSha256Report([]byte(""))
	if err == nil {
		t.Error("expected error on empty input, got nil")
	}
}

func TestParseSha256Report_MissingHeader(t *testing.T) {
	// Wrong header — should reject so we don't accidentally parse some other
	// text file as a sha256_report.
	bad := strings.Replace(goldenReport, "CKNF SHA-256 INTEGRITY REPORT", "Not the right header", 1)
	if _, err := ParseSha256Report([]byte(bad)); err == nil {
		t.Error("expected error on wrong header, got nil")
	}
}

func TestParseSha256Report_MissingSHA256Field(t *testing.T) {
	bad := strings.Replace(goldenReport, "SHA-256:              0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n", "", 1)
	if _, err := ParseSha256Report([]byte(bad)); err == nil {
		t.Error("expected error when SHA-256 field absent, got nil")
	}
}

func TestParseSha256Report_NonNumericFileSize(t *testing.T) {
	bad := strings.Replace(goldenReport, "File Size:            123456 bytes", "File Size:            not_a_number bytes", 1)
	if _, err := ParseSha256Report([]byte(bad)); err == nil {
		t.Error("expected error on non-numeric file size, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256 hex shape — must be exactly 64 lowercase hex chars (Python hashlib output)
// ─────────────────────────────────────────────────────────────────────────────

func TestParseSha256Report_SHA256ShapeRejectsShort(t *testing.T) {
	bad := strings.Replace(goldenReport,
		"SHA-256:              0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"SHA-256:              tooshort", 1)
	if _, err := ParseSha256Report([]byte(bad)); err == nil {
		t.Error("expected error on short SHA-256, got nil")
	}
}

func TestParseSha256Report_SHA256ShapeRejectsNonHex(t *testing.T) {
	bad := strings.Replace(goldenReport,
		"SHA-256:              0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"SHA-256:              ZZZZ56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", 1)
	if _, err := ParseSha256Report([]byte(bad)); err == nil {
		t.Error("expected error on non-hex SHA-256, got nil")
	}
}
