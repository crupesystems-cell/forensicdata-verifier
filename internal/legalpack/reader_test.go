// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Stage B.1 — Legal-Pack ZIP-Reader + Entry-List.
//
// These tests synthesize minimal valid (and deliberately broken) CKNF
// Legal-Pack ZIPs in t.TempDir() — no binary fixtures committed. Real
// CKNF-produced packs will be added under testdata/golden_legal_pack/ once
// available; the synthetic shape must match those bit-for-bit at the entry-
// list level.

package legalpack

import (
	"archive/zip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers — synthesize Legal-Pack ZIPs in tempdir
// ─────────────────────────────────────────────────────────────────────────────

// writeZip creates a ZIP at the given path with the given entries (name →
// content). Calls t.Fatal on any I/O error.
func writeZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer f.Close()
	w := zip.NewWriter(f)
	// Sort entry names for deterministic ZIP byte-layout (helpful when we
	// later compare two synthetic packs).
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := fw.Write([]byte(entries[name])); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
}

// minimalValidEntries returns the 10-entry map for a structurally valid
// Mac-style Legal-Pack (audio = original.m4a). The content of each entry is
// placeholder — B.1 only checks entry NAMES, not their inner format.
func minimalValidEntries() map[string]string {
	return map[string]string{
		"original.m4a":           "fake audio bytes",
		"sha256_report.txt":      "sha256: deadbeef",
		"transcript_raw.txt":     "raw text",
		"transcript_clean.txt":   "clean text",
		"transcript.docx":        "fake docx bytes",
		"transcript_history.txt": "(no version history)\n",
		"chain_of_custody.pdf":   "fake pdf bytes",
		"audit.jsonl":            `{"ts":"2026-05-19T10:00:00+00:00","event":"TEST_EVENT","role":"operator","identity_fingerprint":"(none)","detail":{}}` + "\n",
		"verification_qr.png":    "fake png bytes",
		"cover.pdf":              "fake pdf bytes",
	}
}

// minimalValidWinEntries is the same shape but with original.wav (Windows audio).
func minimalValidWinEntries() map[string]string {
	m := minimalValidEntries()
	delete(m, "original.m4a")
	m["original.wav"] = "fake wav bytes"
	return m
}

// ─────────────────────────────────────────────────────────────────────────────
// Open + Entries
// ─────────────────────────────────────────────────────────────────────────────

func TestOpen_ValidMacPack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, path, minimalValidEntries())

	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer pack.Close()

	got := pack.Entries()
	if len(got) != 10 {
		t.Errorf("Entries: got %d, want 10 (entries=%v)", len(got), got)
	}
}

func TestOpen_ValidWinPack(t *testing.T) {
	// Same shape with original.wav — must also pass.
	path := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, path, minimalValidWinEntries())

	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer pack.Close()

	if pack.AudioEntry() != "original.wav" {
		t.Errorf("AudioEntry: got %q, want %q", pack.AudioEntry(), "original.wav")
	}
}

func TestOpen_FileNotFound(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "nonexistent.zip"))
	if err == nil {
		t.Error("Open on missing path should return error, got nil")
	}
}

func TestOpen_NotAZip(t *testing.T) {
	// Plain text file — should fail to parse as ZIP.
	path := filepath.Join(t.TempDir(), "notazip.zip")
	if err := os.WriteFile(path, []byte("this is not a zip"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_, err := Open(path)
	if err == nil {
		t.Error("Open on non-ZIP should return error, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// MissingEntries — sanity-check that all 10 entries are present
// ─────────────────────────────────────────────────────────────────────────────

func TestMissingEntries_ValidMacPack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, path, minimalValidEntries())

	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pack.Close()

	missing := pack.MissingEntries()
	if len(missing) != 0 {
		t.Errorf("MissingEntries on valid pack: got %v, want empty", missing)
	}
}

func TestMissingEntries_ValidWinPack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, path, minimalValidWinEntries())

	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pack.Close()

	missing := pack.MissingEntries()
	if len(missing) != 0 {
		t.Errorf("MissingEntries on valid win pack: got %v, want empty", missing)
	}
}

func TestMissingEntries_NoAudio(t *testing.T) {
	// Remove both audio variants — must be flagged.
	entries := minimalValidEntries()
	delete(entries, "original.m4a")
	path := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, path, entries)

	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pack.Close()

	missing := pack.MissingEntries()
	if len(missing) == 0 {
		t.Error("MissingEntries should flag missing audio, got empty")
	}
	// The audio slot is reported as a combined "m4a or wav" string so the
	// operator understands it's a slot-level miss, not a single-file miss.
	// Use substring-match to confirm either variant name is mentioned.
	if !anyContainsSubstr(missing, "original.m4a") && !anyContainsSubstr(missing, "original.wav") {
		t.Errorf("MissingEntries should mention audio entry, got %v", missing)
	}
}

func TestMissingEntries_NoSha256Report(t *testing.T) {
	entries := minimalValidEntries()
	delete(entries, "sha256_report.txt")
	path := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, path, entries)

	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pack.Close()

	missing := pack.MissingEntries()
	if !contains(missing, "sha256_report.txt") {
		t.Errorf("MissingEntries should include sha256_report.txt, got %v", missing)
	}
}

func TestMissingEntries_NoQR(t *testing.T) {
	entries := minimalValidEntries()
	delete(entries, "verification_qr.png")
	path := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, path, entries)

	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pack.Close()

	missing := pack.MissingEntries()
	if !contains(missing, "verification_qr.png") {
		t.Errorf("MissingEntries should include verification_qr.png, got %v", missing)
	}
}

func TestMissingEntries_MultipleMissing(t *testing.T) {
	entries := minimalValidEntries()
	delete(entries, "chain_of_custody.pdf")
	delete(entries, "cover.pdf")
	delete(entries, "audit.jsonl")
	path := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, path, entries)

	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pack.Close()

	missing := pack.MissingEntries()
	if len(missing) != 3 {
		t.Errorf("MissingEntries: got %d (%v), want 3", len(missing), missing)
	}
	for _, want := range []string{"chain_of_custody.pdf", "cover.pdf", "audit.jsonl"} {
		if !contains(missing, want) {
			t.Errorf("MissingEntries should include %q, got %v", want, missing)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IsValidStructure — top-level sanity (entries present AND no errors)
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidStructure_ValidPack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, path, minimalValidEntries())

	pack, _ := Open(path)
	defer pack.Close()

	if !pack.IsValidStructure() {
		t.Error("IsValidStructure on valid pack: got false, want true")
	}
}

func TestIsValidStructure_MissingEntry(t *testing.T) {
	entries := minimalValidEntries()
	delete(entries, "sha256_report.txt")
	path := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, path, entries)

	pack, _ := Open(path)
	defer pack.Close()

	if pack.IsValidStructure() {
		t.Error("IsValidStructure with missing entry: got true, want false")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ReadEntry — extract individual file content
// ─────────────────────────────────────────────────────────────────────────────

func TestReadEntry_ExtractsBytes(t *testing.T) {
	entries := minimalValidEntries()
	entries["sha256_report.txt"] = "EXPECTED_REPORT_BODY"
	path := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, path, entries)

	pack, _ := Open(path)
	defer pack.Close()

	got, err := pack.ReadEntry("sha256_report.txt")
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if string(got) != "EXPECTED_REPORT_BODY" {
		t.Errorf("ReadEntry content mismatch: got %q", string(got))
	}
}

func TestReadEntry_MissingReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pack.zip")
	writeZip(t, path, minimalValidEntries())

	pack, _ := Open(path)
	defer pack.Close()

	_, err := pack.ReadEntry("does_not_exist.txt")
	if err == nil {
		t.Error("ReadEntry on missing entry: got nil error, want error")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func containsAny(haystack []string, needles ...string) bool {
	for _, n := range needles {
		if contains(haystack, n) {
			return true
		}
	}
	return false
}

// anyContainsSubstr reports whether any element of haystack contains substr
// as a substring (case-sensitive).
func anyContainsSubstr(haystack []string, substr string) bool {
	for _, s := range haystack {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// Defensive: this catches any helper drift that would render the test suite
// brittle. If the canonical Required-Entries list is ever extended, this
// helper must be updated alongside it.
func TestRequiredEntries_Count(t *testing.T) {
	// 10 required slots in v1: 1 audio (m4a OR wav) + 9 fixed-name entries.
	required := RequiredEntries()
	if len(required) != 10 {
		t.Errorf("RequiredEntries should describe 10 slots, got %d: %v", len(required), required)
	}
	// At least one slot must mention the audio variants.
	found := false
	for _, r := range required {
		if strings.Contains(r, "original.m4a") || strings.Contains(r, "original.wav") {
			found = true
			break
		}
	}
	if !found {
		t.Error("RequiredEntries should describe audio slot referencing original.m4a / original.wav")
	}
}
