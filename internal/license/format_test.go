// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Stage A.2 — License-Format-Parser (Option β).
//
// Tests deliberately do NOT verify HMAC authenticity. Per
// 12_PLAN_VERIFIER_CLI__v1.md §7 Risk #1, the HMAC secret must never be
// shipped in the open-source binary, so authenticity verification is out of
// scope. These tests only confirm the structural format and the presence of
// the checksum field.

package license

import (
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Parse
// ─────────────────────────────────────────────────────────────────────────────

func TestParse_ValidLifetimeCFS(t *testing.T) {
	got, err := Parse("CKNF-LCFS15022-6FBF59ED")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Prefix != "CKNF" {
		t.Errorf("Prefix: got %q, want %q", got.Prefix, "CKNF")
	}
	if got.Tier != "L" {
		t.Errorf("Tier: got %q, want %q", got.Tier, "L")
	}
	if got.TierName != "Lifetime" {
		t.Errorf("TierName: got %q, want %q", got.TierName, "Lifetime")
	}
	if got.Programs != "CFS" {
		t.Errorf("Programs: got %q, want %q", got.Programs, "CFS")
	}
	if got.Serial != 15022 {
		t.Errorf("Serial: got %d, want %d", got.Serial, 15022)
	}
	if got.Checksum != "6FBF59ED" {
		t.Errorf("Checksum: got %q, want %q", got.Checksum, "6FBF59ED")
	}
}

func TestParse_SecondValidSample(t *testing.T) {
	// Second known-good sample from wbr_keygen vertriebs-wrapper Hebel-3.
	got, err := Parse("CKNF-LCFS29688-5721A434")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Serial != 29688 || got.Checksum != "5721A434" {
		t.Errorf("Serial/Checksum mismatch: %+v", got)
	}
}

func TestParse_ValidTrial(t *testing.T) {
	// Trial tier — same shape as Lifetime, just T instead of L.
	got, err := Parse("CKNF-TCFS14823-DEADBEEF")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Tier != "T" {
		t.Errorf("Tier: got %q, want %q", got.Tier, "T")
	}
	if got.TierName != "Trial" {
		t.Errorf("TierName: got %q, want %q", got.TierName, "Trial")
	}
}

func TestParse_AlternatePrograms(t *testing.T) {
	// Programs is a 3-char code (CFS = full suite, but other combos may exist).
	// Parser must accept any 3-char A-Z code; semantic meaning is out of scope.
	cases := []string{
		"CKNF-LCKN20000-AAAABBBB", // CKN-only license
		"CKNF-LFDC30000-11112222", // FDC-only
		"CKNF-LFDS40000-99998888", // FDS-only
	}
	for _, in := range cases {
		if _, err := Parse(in); err != nil {
			t.Errorf("Parse(%q) returned error: %v", in, err)
		}
	}
}

func TestParse_AlternatePrefix(t *testing.T) {
	// Prefix is a 4-char code. CKNF is the typical Suite prefix, but the
	// parser must remain agnostic — different suite-products may issue
	// different prefixes.
	got, err := Parse("CONS-LCFS15022-6FBF59ED")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Prefix != "CONS" {
		t.Errorf("Prefix: got %q, want %q", got.Prefix, "CONS")
	}
}

// ── Format errors ────────────────────────────────────────────────────────────

func TestParse_EmptyString(t *testing.T) {
	if _, err := Parse(""); err == nil {
		t.Error("expected error on empty string, got nil")
	}
}

func TestParse_WhitespaceOnly(t *testing.T) {
	if _, err := Parse("   \t  "); err == nil {
		t.Error("expected error on whitespace-only string, got nil")
	}
}

func TestParse_PrefixTooShort(t *testing.T) {
	if _, err := Parse("CKN-LCFS15022-6FBF59ED"); err == nil {
		t.Error("expected error on 3-char prefix, got nil")
	}
}

func TestParse_PrefixTooLong(t *testing.T) {
	if _, err := Parse("CKNFL-LCFS15022-6FBF59ED"); err == nil {
		t.Error("expected error on 5-char prefix, got nil")
	}
}

func TestParse_InvalidTier(t *testing.T) {
	// X is not a recognized tier letter.
	if _, err := Parse("CKNF-XCFS15022-6FBF59ED"); err == nil {
		t.Error("expected error on invalid tier letter, got nil")
	}
}

func TestParse_SerialTooShort(t *testing.T) {
	if _, err := Parse("CKNF-LCFS1502-6FBF59ED"); err == nil {
		t.Error("expected error on 4-digit serial, got nil")
	}
}

func TestParse_SerialTooLong(t *testing.T) {
	if _, err := Parse("CKNF-LCFS150220-6FBF59ED"); err == nil {
		t.Error("expected error on 6-digit serial, got nil")
	}
}

func TestParse_ChecksumTooShort(t *testing.T) {
	if _, err := Parse("CKNF-LCFS15022-6FBF59E"); err == nil {
		t.Error("expected error on 7-char checksum, got nil")
	}
}

func TestParse_ChecksumTooLong(t *testing.T) {
	if _, err := Parse("CKNF-LCFS15022-6FBF59EDD"); err == nil {
		t.Error("expected error on 9-char checksum, got nil")
	}
}

func TestParse_ChecksumNonHex(t *testing.T) {
	if _, err := Parse("CKNF-LCFS15022-GGGGGGGG"); err == nil {
		t.Error("expected error on non-hex checksum, got nil")
	}
}

func TestParse_LowercaseChecksumRejected(t *testing.T) {
	// CKNF wbr_keygen emits uppercase hex. Reject lowercase to catch
	// transcription errors that change semantic meaning.
	if _, err := Parse("CKNF-LCFS15022-6fbf59ed"); err == nil {
		t.Error("expected error on lowercase checksum, got nil")
	}
}

func TestParse_MissingDashes(t *testing.T) {
	if _, err := Parse("CKNFLCFS150226FBF59ED"); err == nil {
		t.Error("expected error on missing dashes, got nil")
	}
}

func TestParse_LeadingTrailingWhitespaceAccepted(t *testing.T) {
	// Operators may paste with surrounding whitespace; trim it.
	got, err := Parse("  CKNF-LCFS15022-6FBF59ED  \n")
	if err != nil {
		t.Fatalf("expected leading/trailing whitespace to be trimmed, got error: %v", err)
	}
	if got.Serial != 15022 {
		t.Errorf("Serial: got %d, want %d", got.Serial, 15022)
	}
}

// ── Serial range warning (per wbr_keygen SERIAL_OFFSET = 14822) ──────────────

func TestParse_SerialBelowOffsetIsValidFormatButFlagged(t *testing.T) {
	// wbr_keygen generates serials in 14823..99999 (counter 1..85177 + offset 14822).
	// A serial below 14823 is structurally valid hex/digits but cannot have been
	// produced by the canonical generator. The parser MUST still accept the
	// string (format-only per Option β) but expose a flag for the CLI layer to
	// surface as a warning.
	got, err := Parse("CKNF-LCFS00001-AAAABBBB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.SerialOutOfRange {
		t.Error("SerialOutOfRange should be true for serial < 14823")
	}
}

func TestParse_SerialAtOffsetBoundaryIsValid(t *testing.T) {
	// Serial 14823 = counter 1 + offset = lowest valid serial.
	got, err := Parse("CKNF-LCFS14823-AAAABBBB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SerialOutOfRange {
		t.Error("SerialOutOfRange should be false for serial == 14823")
	}
}

// ── Format() round-trip (Stringer interface) ─────────────────────────────────

func TestLicense_Format_RoundTrip(t *testing.T) {
	original := "CKNF-LCFS15022-6FBF59ED"
	parsed, err := Parse(original)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if got := parsed.Format(); got != original {
		t.Errorf("Format() round-trip failed: got %q, want %q", got, original)
	}
}

// ── Describe() returns human-friendly summary ────────────────────────────────

func TestLicense_Describe_LifetimeCFS(t *testing.T) {
	lic, _ := Parse("CKNF-LCFS15022-6FBF59ED")
	desc := lic.Describe()
	mustContain(t, desc, "Lifetime")
	mustContain(t, desc, "CFS")
	mustContain(t, desc, "15022")
	mustContain(t, desc, "CKNF")
}

func TestLicense_Describe_TrialIncludesTrialWord(t *testing.T) {
	lic, _ := Parse("CKNF-TCFS14823-DEADBEEF")
	desc := lic.Describe()
	mustContain(t, desc, "Trial")
}

func mustContain(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("expected %q to contain %q", s, substr)
	}
}
