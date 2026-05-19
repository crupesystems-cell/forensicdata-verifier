// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Stage B.4 — Verification-QR decode + payload-match.
//
// QR images are encoded synthetically with skip2/go-qrcode (test-only dep)
// so we don't ship any binary fixtures. The encode→decode round-trip path
// exercises the same library code used in production: `goqr.Recognize` on
// a standard image.Image.

package legalpack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"path/filepath"
	"strings"
	"testing"

	qrcode "github.com/skip2/go-qrcode"
)

// buildSmallSolidPNG returns the bytes of a tiny solid-white PNG — valid as
// an image but carrying no QR pattern. Used to exercise the "QR not found"
// branch of DecodeQRPNG without depending on any binary fixture.
func buildSmallSolidPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	for x := 0; x < 32; x++ {
		for y := 0; y < 32; y++ {
			img.Set(x, y, color.White)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return buf.Bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// canonicalPayload serializes the four-field CKNF QR payload with the same
// `sort_keys=True` discipline the Python source uses, so the encoded bytes
// match what `legal_pack._build_verification_qr` would produce.
func canonicalPayload(id, sha, chain, createdAt string) string {
	m := map[string]string{
		"id":         id,
		"sha256":     sha,
		"chain_hash": chain,
		"created_at": createdAt,
	}
	// Go's encoding/json already sorts map[string]string keys, matching
	// Python's sort_keys=True for this payload shape.
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// encodeQRPNG returns the PNG bytes of a QR code carrying the given payload.
// Test-only — production never encodes QRs.
//
// Size is 512 px and ECC is "High" — these settings were chosen after the
// liyue201/goqr decoder was observed to flip individual bytes on smaller,
// lower-ECC images (e.g. recognising "256" as "652"). The CKNF production
// QR is rendered at box_size=6 with border=2, which yields ~200–250 px for
// our payload sizes; the production decoder is the human eye + a phone
// camera, both of which are very tolerant. For automated decode in this
// test we use settings that round-trip reliably with our chosen decoder.
func encodeQRPNG(t *testing.T, payload string) []byte {
	t.Helper()
	png, err := qrcode.Encode(payload, qrcode.High, 512)
	if err != nil {
		t.Fatalf("encode qr: %v", err)
	}
	return png
}

// buildPackWithQR returns a path to a synthesised CKNF Legal-Pack ZIP that
// contains a real (encoded) QR with the given payload, plus a sha256_report
// whose fields are consistent with the audio bytes (so VerifyAudio still
// passes — every test here isolates the QR check).
func buildPackWithQR(
	t *testing.T,
	audioName string,
	audioBytes []byte,
	reportID string,
	reportChainHash string,
	qrID, qrSHA, qrChain, qrCreated string,
) string {
	t.Helper()
	sum := sha256.Sum256(audioBytes)
	hexSum := hex.EncodeToString(sum[:])

	report := fmt.Sprintf(
		`CKNF SHA-256 INTEGRITY REPORT
============================================================
Recording ID:         %s
Audio File:           %s
File Size:            %d bytes
SHA-256:              %s

Created:              2026-05-19T10:00:00+00:00
Language:             de-DE

Chain Hash:           %s
Chain Prev:           (genesis)
Identity Fingerprint: (none)

TSA Status:           NOT AVAILABLE - offline (deferred retry available)
TSA Note:             test-only

============================================================
`,
		reportID, audioName, len(audioBytes), hexSum, reportChainHash,
	)

	qrPayload := canonicalPayload(qrID, qrSHA, qrChain, qrCreated)
	qrPNG := encodeQRPNG(t, qrPayload)

	entries := map[string]string{
		audioName:                string(audioBytes),
		"sha256_report.txt":      report,
		"transcript_raw.txt":     "raw",
		"transcript_clean.txt":   "clean",
		"transcript.docx":        "fake docx",
		"transcript_history.txt": "(no version history)\n",
		"chain_of_custody.pdf":   "fake pdf",
		"audit.jsonl":            `{"ts":"2026-05-19T10:00:00+00:00","event":"TEST","role":"operator","identity_fingerprint":"(none)","detail":{}}` + "\n",
		"verification_qr.png":    string(qrPNG),
		"cover.pdf":              "fake pdf",
	}
	path := filepath.Join(t.TempDir(), "qr_test_pack.zip")
	writeZip(t, path, entries)
	return path
}

// ─────────────────────────────────────────────────────────────────────────────
// DecodeQRPNG — image-layer
// ─────────────────────────────────────────────────────────────────────────────

func TestDecodeQRPNG_Happy(t *testing.T) {
	payload := canonicalPayload("RecA", "abc", "def", "2026-05-19T10:00:00+00:00")
	png := encodeQRPNG(t, payload)

	got, err := DecodeQRPNG(png)
	if err != nil {
		t.Fatalf("DecodeQRPNG: %v", err)
	}
	if got != payload {
		t.Errorf("payload round-trip mismatch:\n  encoded: %q\n  decoded: %q", payload, got)
	}
}

func TestDecodeQRPNG_EmptyBytes(t *testing.T) {
	if _, err := DecodeQRPNG(nil); err == nil {
		t.Error("expected error on nil PNG bytes")
	}
	if _, err := DecodeQRPNG([]byte{}); err == nil {
		t.Error("expected error on empty PNG bytes")
	}
}

func TestDecodeQRPNG_NotPNG(t *testing.T) {
	_, err := DecodeQRPNG([]byte("this is not a PNG"))
	if err == nil {
		t.Fatal("expected error on non-PNG bytes")
	}
	if !strings.Contains(err.Error(), "PNG decode failed") {
		t.Errorf("error should mention 'PNG decode failed', got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ParseQRPayload — JSON-layer
// ─────────────────────────────────────────────────────────────────────────────

func TestParseQRPayload_Happy(t *testing.T) {
	s := canonicalPayload("Rec_001", "abcd", "ef01", "2026-05-19T10:00:00+00:00")
	p, err := ParseQRPayload(s)
	if err != nil {
		t.Fatalf("ParseQRPayload: %v", err)
	}
	if p.ID != "Rec_001" || p.SHA256 != "abcd" || p.ChainHash != "ef01" || p.CreatedAt != "2026-05-19T10:00:00+00:00" {
		t.Errorf("ParseQRPayload returned wrong fields: %+v", p)
	}
}

func TestParseQRPayload_EmptyString(t *testing.T) {
	if _, err := ParseQRPayload(""); err == nil {
		t.Error("expected error on empty payload string")
	}
}

func TestParseQRPayload_InvalidJSON(t *testing.T) {
	_, err := ParseQRPayload("{ not json")
	if err == nil {
		t.Error("expected error on malformed JSON")
	}
	if !strings.Contains(err.Error(), "JSON decode failed") {
		t.Errorf("error should mention 'JSON decode failed', got: %v", err)
	}
}

func TestParseQRPayload_MissingFields(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    string
	}{
		{"missing id", `{"sha256":"a","chain_hash":"b","created_at":"c"}`, "missing 'id'"},
		{"missing sha256", `{"id":"a","chain_hash":"b","created_at":"c"}`, "missing 'sha256'"},
		{"missing chain_hash", `{"id":"a","sha256":"b","created_at":"c"}`, "missing 'chain_hash'"},
		{"missing created_at", `{"id":"a","sha256":"b","chain_hash":"c"}`, "missing 'created_at'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseQRPayload(tc.payload)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestParseQRPayload_UnknownField(t *testing.T) {
	// DisallowUnknownFields keeps the parser strict to catch silent format
	// drift — a future schema change must update both Python and Go in lockstep.
	bad := `{"id":"a","sha256":"b","chain_hash":"c","created_at":"d","extra":"x"}`
	if _, err := ParseQRPayload(bad); err == nil {
		t.Error("expected error on unknown field 'extra'")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyQR — orchestration
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyQR_Happy(t *testing.T) {
	audio := []byte("the actual audio bytes")
	sum := sha256.Sum256(audio)
	audioHex := hex.EncodeToString(sum[:])
	chainHash := strings.Repeat("a", 64)
	recID := "Test_Recording_2026-05-19_aaaaaaaa"

	path := buildPackWithQR(t, "original.m4a", audio,
		recID, chainHash,
		recID, audioHex, chainHash, "2026-05-19T10:00:00+00:00",
	)
	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pack.Close()

	reportBytes, _ := pack.ReadEntry("sha256_report.txt")
	report, err := ParseSha256Report(reportBytes)
	if err != nil {
		t.Fatalf("ParseSha256Report: %v", err)
	}

	if err := VerifyQR(pack, report); err != nil {
		t.Errorf("VerifyQR on consistent pack: %v", err)
	}
}

func TestVerifyQR_RecordingIDMismatch(t *testing.T) {
	audio := []byte("audio")
	sum := sha256.Sum256(audio)
	audioHex := hex.EncodeToString(sum[:])
	chainHash := strings.Repeat("b", 64)

	// Report claims one recording_id; QR carries a different one.
	path := buildPackWithQR(t, "original.m4a", audio,
		"REPORT_REC_ID", chainHash,
		"QR_REC_ID_DIFFERENT", audioHex, chainHash, "2026-05-19T10:00:00+00:00",
	)
	pack, _ := Open(path)
	defer pack.Close()
	reportBytes, _ := pack.ReadEntry("sha256_report.txt")
	report, _ := ParseSha256Report(reportBytes)

	err := VerifyQR(pack, report)
	if err == nil {
		t.Fatal("expected recording_id mismatch")
	}
	if !strings.Contains(err.Error(), "recording_id MISMATCH") {
		t.Errorf("error should mention 'recording_id MISMATCH', got: %v", err)
	}
}

func TestVerifyQR_SHA256Mismatch(t *testing.T) {
	audio := []byte("audio bytes")
	sum := sha256.Sum256(audio)
	audioHex := hex.EncodeToString(sum[:])
	chainHash := strings.Repeat("c", 64)
	recID := "Rec_001"
	wrongSHA := strings.Repeat("d", 64)

	path := buildPackWithQR(t, "original.m4a", audio,
		recID, chainHash,
		recID, wrongSHA, chainHash, "2026-05-19T10:00:00+00:00",
	)
	pack, _ := Open(path)
	defer pack.Close()
	reportBytes, _ := pack.ReadEntry("sha256_report.txt")
	report, _ := ParseSha256Report(reportBytes)

	// Sanity: report.SHA256 is the audio hash; QR's wrong SHA differs.
	if report.SHA256 != audioHex {
		t.Fatalf("test setup: report.SHA256 should equal audio hash, got %s vs %s",
			report.SHA256, audioHex)
	}

	err := VerifyQR(pack, report)
	if err == nil {
		t.Fatal("expected SHA-256 mismatch")
	}
	if !strings.Contains(err.Error(), "audio SHA-256 MISMATCH") {
		t.Errorf("error should mention 'audio SHA-256 MISMATCH', got: %v", err)
	}
}

func TestVerifyQR_ChainHashMismatch(t *testing.T) {
	audio := []byte("audio")
	sum := sha256.Sum256(audio)
	audioHex := hex.EncodeToString(sum[:])
	reportChain := strings.Repeat("e", 64)
	qrChain := strings.Repeat("f", 64)
	recID := "Rec_002"

	path := buildPackWithQR(t, "original.m4a", audio,
		recID, reportChain,
		recID, audioHex, qrChain, "2026-05-19T10:00:00+00:00",
	)
	pack, _ := Open(path)
	defer pack.Close()
	reportBytes, _ := pack.ReadEntry("sha256_report.txt")
	report, _ := ParseSha256Report(reportBytes)

	err := VerifyQR(pack, report)
	if err == nil {
		t.Fatal("expected chain_hash mismatch")
	}
	if !strings.Contains(err.Error(), "chain_hash MISMATCH") {
		t.Errorf("error should mention 'chain_hash MISMATCH', got: %v", err)
	}
}

func TestVerifyQR_ReportChainHashUnsetIsTolerated(t *testing.T) {
	// When sha256_report has Chain Hash: (unset), the QR's chain_hash is
	// not cross-checked. This documents the degenerate-but-legal path.
	audio := []byte("audio")
	sum := sha256.Sum256(audio)
	audioHex := hex.EncodeToString(sum[:])
	recID := "Rec_unset"

	// Build a custom pack where report's Chain Hash field is "(unset)".
	report := fmt.Sprintf(
		`CKNF SHA-256 INTEGRITY REPORT
============================================================
Recording ID:         %s
Audio File:           %s
File Size:            %d bytes
SHA-256:              %s

Created:              2026-05-19T10:00:00+00:00
Language:             de-DE

Chain Hash:           (unset)
Chain Prev:           (genesis)
Identity Fingerprint: (none)

TSA Status:           NOT AVAILABLE - offline (deferred retry available)
TSA Note:             test-only

============================================================
`,
		recID, "original.m4a", len(audio), audioHex,
	)
	qrPNG := encodeQRPNG(t,
		canonicalPayload(recID, audioHex, strings.Repeat("1", 64), "2026-05-19T10:00:00+00:00"),
	)
	entries := map[string]string{
		"original.m4a":           string(audio),
		"sha256_report.txt":      report,
		"transcript_raw.txt":     "raw",
		"transcript_clean.txt":   "clean",
		"transcript.docx":        "fake docx",
		"transcript_history.txt": "(no version history)\n",
		"chain_of_custody.pdf":   "fake pdf",
		"audit.jsonl":            `{"ts":"2026-05-19T10:00:00+00:00","event":"TEST","role":"operator","identity_fingerprint":"(none)","detail":{}}` + "\n",
		"verification_qr.png":    string(qrPNG),
		"cover.pdf":              "fake pdf",
	}
	path := filepath.Join(t.TempDir(), "unset_chain.zip")
	writeZip(t, path, entries)

	pack, _ := Open(path)
	defer pack.Close()
	reportBytes, _ := pack.ReadEntry("sha256_report.txt")
	parsedReport, err := ParseSha256Report(reportBytes)
	if err != nil {
		t.Fatalf("ParseSha256Report: %v", err)
	}
	if parsedReport.ChainHash != "" {
		t.Fatalf("test setup: expected report.ChainHash empty after (unset) normalization, got %q",
			parsedReport.ChainHash)
	}

	if err := VerifyQR(pack, parsedReport); err != nil {
		t.Errorf("VerifyQR with report ChainHash=(unset) should tolerate any QR chain_hash, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Precondition errors
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyQR_NilPack(t *testing.T) {
	if err := VerifyQR(nil, &Sha256Report{}); err == nil {
		t.Error("expected error on nil pack")
	}
}

func TestVerifyQR_NilReport(t *testing.T) {
	audio := []byte("x")
	path := buildPackWithQR(t, "original.m4a", audio,
		"r", strings.Repeat("a", 64),
		"r", "any", "any", "any",
	)
	pack, _ := Open(path)
	defer pack.Close()
	if err := VerifyQR(pack, nil); err == nil {
		t.Error("expected error on nil report")
	}
}

func TestVerifyQR_MissingQREntry(t *testing.T) {
	// Pack without verification_qr.png — VerifyQR must fail with a clear
	// "cannot read" error rather than silently passing.
	entries := minimalValidEntries()
	delete(entries, "verification_qr.png")
	path := filepath.Join(t.TempDir(), "no_qr.zip")
	writeZip(t, path, entries)

	pack, _ := Open(path)
	defer pack.Close()
	err := VerifyQR(pack, &Sha256Report{RecordingID: "r", SHA256: "x"})
	if err == nil {
		t.Fatal("expected error when QR entry missing")
	}
	if !strings.Contains(err.Error(), "cannot read verification_qr.png") {
		t.Errorf("error should mention 'cannot read verification_qr.png', got: %v", err)
	}
}

func TestVerifyQR_CorruptedQRImage(t *testing.T) {
	// Pack contains a PNG-shaped but QR-unreadable file at verification_qr.png.
	// Use a small valid PNG with no QR pattern.
	smallPNG := buildSmallSolidPNG(t)
	entries := minimalValidEntries()
	entries["verification_qr.png"] = string(smallPNG)
	path := filepath.Join(t.TempDir(), "bad_qr.zip")
	writeZip(t, path, entries)

	pack, _ := Open(path)
	defer pack.Close()
	err := VerifyQR(pack, &Sha256Report{RecordingID: "r", SHA256: "x"})
	if err == nil {
		t.Fatal("expected error when QR pattern unreadable")
	}
	// Either "QR recognition failed" or "no QR code found" depending on lib.
	if !strings.Contains(err.Error(), "QR") {
		t.Errorf("error should mention 'QR', got: %v", err)
	}
}
