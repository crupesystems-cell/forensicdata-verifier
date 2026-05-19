// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Stage B.3 — Audio-SHA-256 forensic check.
//
// The "consistent pack" helper below produces a ZIP whose sha256_report.txt
// references the actual SHA-256 of the embedded audio bytes. This is the
// canonical happy-path setup — every tamper-test is derived from it by
// mutating ONE specific value.

package legalpack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// reportTemplate is a format string for a minimal valid sha256_report.txt
// suitable for hashing-tests. The four %s slots are recording-id,
// audio-filename, audio-byte-count, and sha256-hex.
const reportTemplate = `CKNF SHA-256 INTEGRITY REPORT
============================================================
Recording ID:         %s
Audio File:           %s
File Size:            %d bytes
SHA-256:              %s

Created:              2026-05-19T10:00:00+00:00
Language:             de-DE

Chain Hash:           aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Chain Prev:           (genesis)
Identity Fingerprint: (none)

TSA Status:           NOT AVAILABLE - offline (deferred retry available)
TSA Note:             test-only

============================================================
`

// buildConsistentPack writes a ZIP where the sha256_report.txt SHA-256
// matches the actual audio bytes. Returns the ZIP path.
func buildConsistentPack(t *testing.T, audioName string, audioBytes []byte) string {
	t.Helper()
	sum := sha256.Sum256(audioBytes)
	hexSum := hex.EncodeToString(sum[:])
	report := fmt.Sprintf(reportTemplate, "Test_Recording_2026-05-19_aaaaaaaa", audioName, len(audioBytes), hexSum)

	entries := map[string]string{
		audioName:                string(audioBytes),
		"sha256_report.txt":      report,
		"transcript_raw.txt":     "raw",
		"transcript_clean.txt":   "clean",
		"transcript.docx":        "fake docx",
		"transcript_history.txt": "(no version history)\n",
		"chain_of_custody.pdf":   "fake pdf",
		"audit.jsonl":            `{"ts":"2026-05-19T10:00:00+00:00","event":"TEST","role":"operator","identity_fingerprint":"(none)","detail":{}}` + "\n",
		"verification_qr.png":    "fake png",
		"cover.pdf":              "fake pdf",
	}
	path := filepath.Join(t.TempDir(), "consistent.zip")
	writeZip(t, path, entries)
	return path
}

// ─────────────────────────────────────────────────────────────────────────────
// Happy path
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyAudioSHA256_Happy(t *testing.T) {
	path := buildConsistentPack(t, "original.m4a", []byte("the actual audio bytes"))
	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pack.Close()

	reportBytes, err := pack.ReadEntry("sha256_report.txt")
	if err != nil {
		t.Fatalf("ReadEntry sha256_report: %v", err)
	}
	report, err := ParseSha256Report(reportBytes)
	if err != nil {
		t.Fatalf("ParseSha256Report: %v", err)
	}

	if err := VerifyAudioSHA256(pack, report); err != nil {
		t.Errorf("VerifyAudioSHA256 on consistent pack: %v", err)
	}
}

func TestVerifyAudioSHA256_HappyWavVariant(t *testing.T) {
	// Same logic but Windows .wav audio.
	path := buildConsistentPack(t, "original.wav", []byte("different wav bytes here"))
	pack, _ := Open(path)
	defer pack.Close()
	reportBytes, _ := pack.ReadEntry("sha256_report.txt")
	report, _ := ParseSha256Report(reportBytes)

	if err := VerifyAudioSHA256(pack, report); err != nil {
		t.Errorf("VerifyAudioSHA256 on consistent wav pack: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tamper detection
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyAudioSHA256_TamperedAudio(t *testing.T) {
	// Hand-craft a pack where the report has a known-good SHA but the audio
	// entry contains DIFFERENT bytes than the report's SHA describes.
	audioGood := []byte("the actual audio bytes")
	sumGood := sha256.Sum256(audioGood)
	hexGood := hex.EncodeToString(sumGood[:])
	report := fmt.Sprintf(reportTemplate, "Tamper_2026-05-19_aaaaaaaa", "original.m4a", len(audioGood), hexGood)

	audioTampered := []byte("the audio bytes after tampering")
	entries := map[string]string{
		"original.m4a":           string(audioTampered),
		"sha256_report.txt":      report,
		"transcript_raw.txt":     "raw",
		"transcript_clean.txt":   "clean",
		"transcript.docx":        "fake docx",
		"transcript_history.txt": "(no version history)\n",
		"chain_of_custody.pdf":   "fake pdf",
		"audit.jsonl":            `{"ts":"2026-05-19T10:00:00+00:00","event":"TEST","role":"operator","identity_fingerprint":"(none)","detail":{}}` + "\n",
		"verification_qr.png":    "fake png",
		"cover.pdf":              "fake pdf",
	}
	path := filepath.Join(t.TempDir(), "tampered.zip")
	writeZip(t, path, entries)

	pack, _ := Open(path)
	defer pack.Close()
	reportBytes, _ := pack.ReadEntry("sha256_report.txt")
	parsedReport, _ := ParseSha256Report(reportBytes)

	err := VerifyAudioSHA256(pack, parsedReport)
	if err == nil {
		t.Fatal("VerifyAudioSHA256 on tampered audio: got nil error, want mismatch error")
	}
	if !strings.Contains(err.Error(), "MISMATCH") {
		t.Errorf("error should mention MISMATCH, got: %v", err)
	}
	// Both expected and computed SHA must appear in the error message —
	// that's what makes the failure actionable for the operator.
	if !strings.Contains(err.Error(), hexGood) {
		t.Errorf("error should include expected SHA %s, got: %v", hexGood, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Precondition errors
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyAudioSHA256_NilPack(t *testing.T) {
	if err := VerifyAudioSHA256(nil, &Sha256Report{}); err == nil {
		t.Error("expected error on nil pack")
	}
}

func TestVerifyAudioSHA256_NilReport(t *testing.T) {
	path := buildConsistentPack(t, "original.m4a", []byte("x"))
	pack, _ := Open(path)
	defer pack.Close()
	if err := VerifyAudioSHA256(pack, nil); err == nil {
		t.Error("expected error on nil report")
	}
}

func TestVerifyAudioSHA256_NoAudioEntry(t *testing.T) {
	// Pack with all 9 fixed entries but no audio.
	entries := minimalValidEntries()
	delete(entries, "original.m4a")
	path := filepath.Join(t.TempDir(), "no_audio.zip")
	writeZip(t, path, entries)

	pack, _ := Open(path)
	defer pack.Close()

	err := VerifyAudioSHA256(pack, &Sha256Report{SHA256: "any"})
	if err == nil {
		t.Error("expected error when pack has no audio entry")
	}
	if !strings.Contains(err.Error(), "no audio entry") {
		t.Errorf("error should mention 'no audio entry', got: %v", err)
	}
}

func TestVerifyAudioSHA256_FilenameMismatch(t *testing.T) {
	// Pack contains original.m4a but report claims original.wav.
	path := buildConsistentPack(t, "original.m4a", []byte("audio"))
	pack, _ := Open(path)
	defer pack.Close()

	reportBytes, _ := pack.ReadEntry("sha256_report.txt")
	report, _ := ParseSha256Report(reportBytes)
	report.AudioFilename = "original.wav" // simulate report-tampering

	err := VerifyAudioSHA256(pack, report)
	if err == nil {
		t.Error("expected error when report's AudioFilename disagrees with pack")
	}
	if !strings.Contains(err.Error(), "inconsistent") {
		t.Errorf("error should mention 'inconsistent', got: %v", err)
	}
}

func TestVerifyAudioSHA256_EmptyReportFilenameAccepted(t *testing.T) {
	// Older pack: report.AudioFilename may be empty. Verifier must use the
	// pack's actual audio entry name and still verify the SHA-256.
	path := buildConsistentPack(t, "original.m4a", []byte("x"))
	pack, _ := Open(path)
	defer pack.Close()

	reportBytes, _ := pack.ReadEntry("sha256_report.txt")
	report, _ := ParseSha256Report(reportBytes)
	report.AudioFilename = ""

	if err := VerifyAudioSHA256(pack, report); err != nil {
		t.Errorf("empty AudioFilename should be tolerated, got: %v", err)
	}
}
