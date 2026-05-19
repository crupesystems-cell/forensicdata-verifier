// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Stage C.4 — Top-level legal-pack verification orchestrator.

package legalpack

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

func buildConsistentPackForOrchestrator(t *testing.T) (path string, audioBytes []byte, recID string) {
	t.Helper()
	audio := []byte("orchestrator-test audio bytes")
	sum := sha256.Sum256(audio)
	audioHex := hex.EncodeToString(sum[:])
	chainHash := strings.Repeat("a", 64)
	recordingID := "Orchestrator_Test_Recording_20260519_aaaaaaaa"

	p := buildPackWithQR(t, "original.m4a", audio,
		recordingID, chainHash,
		recordingID, audioHex, chainHash, "2026-05-19T10:00:00+00:00",
	)
	return p, audio, recordingID
}

func TestVerifyLegalPack_HappyNoTSR(t *testing.T) {
	path, _, recID := buildConsistentPackForOrchestrator(t)

	v, err := VerifyLegalPack(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyLegalPack: %v", err)
	}
	if v.OverallResult != "PASS" {
		t.Errorf("verdict: want PASS, got %s\n  summary: %s", v.OverallResult, v.Summary)
	}
	if v.RecordingID != recID {
		t.Errorf("RecordingID: want %s, got %s", recID, v.RecordingID)
	}

	gotResults := map[string]string{}
	for _, c := range v.Checks {
		gotResults[c.Name] = c.Result
	}
	wantPass := []string{checkAudio, checkQR}
	wantSkip := []string{checkAudit, checkTSA}
	for _, n := range wantPass {
		if gotResults[n] != "PASS" {
			t.Errorf("check %s: want PASS, got %s", n, gotResults[n])
		}
	}
	for _, n := range wantSkip {
		if gotResults[n] != "SKIPPED" {
			t.Errorf("check %s: want SKIPPED, got %s", n, gotResults[n])
		}
	}
}

func TestVerifyLegalPack_TamperedAudioFails(t *testing.T) {
	audio := []byte("audio before tampering")
	sum := sha256.Sum256(audio)
	audioHex := hex.EncodeToString(sum[:])
	chainHash := strings.Repeat("a", 64)
	recID := "Tampered_Recording_20260519"

	tamperedAudio := []byte("MODIFIED audio after sealing")
	entries := minimalValidEntries()
	delete(entries, "original.m4a")
	entries["original.m4a"] = string(tamperedAudio)
	entries["sha256_report.txt"] = fmt.Sprintf(
		`CKNF SHA-256 INTEGRITY REPORT
============================================================
Recording ID:         %s
Audio File:           original.m4a
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
		recID, len(audio), audioHex, chainHash,
	)

	qrPNG := encodeQRPNG(t, canonicalPayload(recID, audioHex, chainHash, "2026-05-19T10:00:00+00:00"))
	entries["verification_qr.png"] = string(qrPNG)

	path := filepath.Join(t.TempDir(), "tampered.zip")
	writeZip(t, path, entries)

	v, err := VerifyLegalPack(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyLegalPack: %v", err)
	}
	if v.OverallResult != "FAIL" {
		t.Errorf("want FAIL on tampered audio, got %s\n  summary: %s", v.OverallResult, v.Summary)
	}
	got := map[string]string{}
	for _, c := range v.Checks {
		got[c.Name] = c.Result
	}
	if got[checkAudio] != "FAIL" {
		t.Errorf("audio check should FAIL on tampered pack, got %s", got[checkAudio])
	}
	for _, c := range v.Checks {
		if c.Name == checkAudio {
			if !strings.Contains(c.Error, "MISMATCH") {
				t.Errorf("audio check error should mention MISMATCH, got: %q", c.Error)
			}
		}
	}
}

func TestVerifyLegalPack_MissingFile(t *testing.T) {
	_, err := VerifyLegalPack(filepath.Join(t.TempDir(), "nonexistent.zip"), VerifyOptions{})
	if err == nil {
		t.Error("expected error on nonexistent path")
	}
}

func TestVerifyLegalPack_MissingRequiredEntries(t *testing.T) {
	entries := minimalValidEntries()
	delete(entries, "verification_qr.png")
	path := filepath.Join(t.TempDir(), "missing_qr.zip")
	writeZip(t, path, entries)

	_, err := VerifyLegalPack(path, VerifyOptions{})
	if err == nil {
		t.Error("expected error when pack is missing required entry")
	}
	if !strings.Contains(err.Error(), "missing required entries") {
		t.Errorf("error should mention missing entries, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TSA integration
// ─────────────────────────────────────────────────────────────────────────────

func buildTestTSR(t *testing.T, digest []byte) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject: pkix.Name{
			CommonName: "Verifier Orch Test TSA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	ts := &timestamp.Timestamp{
		HashedMessage:     digest,
		HashAlgorithm:     crypto.SHA256,
		Time:              time.Date(2026, 5, 19, 10, 5, 0, 0, time.UTC),
		Nonce:             big.NewInt(0xABCD),
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		Certificates:      []*x509.Certificate{cert},
		AddTSACertificate: true,
	}
	tsr, err := ts.CreateResponseWithOpts(cert, priv, crypto.SHA256)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	return tsr
}

func TestVerifyLegalPack_TSRMatching(t *testing.T) {
	path, audio, _ := buildConsistentPackForOrchestrator(t)
	sum := sha256.Sum256(audio)

	tsrBytes := buildTestTSR(t, sum[:])
	tsrPath := filepath.Join(t.TempDir(), "original.tsr")
	if err := os.WriteFile(tsrPath, tsrBytes, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	v, err := VerifyLegalPack(path, VerifyOptions{TSRPath: tsrPath})
	if err != nil {
		t.Fatalf("VerifyLegalPack: %v", err)
	}
	if v.OverallResult != "PASS" {
		t.Errorf("want PASS with matching TSR, got %s\n  summary: %s", v.OverallResult, v.Summary)
	}
	got := map[string]string{}
	for _, c := range v.Checks {
		got[c.Name] = c.Result
	}
	if got[checkTSA] != "PASS" {
		t.Errorf("TSA check: want PASS, got %s", got[checkTSA])
	}
	if v.TSAReport == nil {
		t.Error("TSAReport should be populated when --tsr is provided")
	}
}

func TestVerifyLegalPack_TSRDigestMismatch(t *testing.T) {
	path, _, _ := buildConsistentPackForOrchestrator(t)
	wrongDigest := sha256.Sum256([]byte("different bytes"))
	tsrBytes := buildTestTSR(t, wrongDigest[:])
	tsrPath := filepath.Join(t.TempDir(), "wrong.tsr")
	if err := os.WriteFile(tsrPath, tsrBytes, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	v, err := VerifyLegalPack(path, VerifyOptions{TSRPath: tsrPath})
	if err != nil {
		t.Fatalf("VerifyLegalPack: %v", err)
	}
	if v.OverallResult != "FAIL" {
		t.Errorf("want FAIL on TSR digest mismatch, got %s", v.OverallResult)
	}
	for _, c := range v.Checks {
		if c.Name == checkTSA && c.Result != "FAIL" {
			t.Errorf("TSA check should FAIL on digest mismatch, got %s", c.Result)
		}
	}
}

func TestVerifyLegalPack_TSRBadFile(t *testing.T) {
	path, _, _ := buildConsistentPackForOrchestrator(t)
	badPath := filepath.Join(t.TempDir(), "bad.tsr")
	if err := os.WriteFile(badPath, []byte("not a valid TSR"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	v, err := VerifyLegalPack(path, VerifyOptions{TSRPath: badPath})
	if err != nil {
		t.Fatalf("VerifyLegalPack: %v", err)
	}
	if v.OverallResult != "FAIL" {
		t.Error("want FAIL when TSR parse fails")
	}
}
