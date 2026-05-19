//go:build ignore

// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// gen/main.go produces reproducible synthetic CKNF Legal-Pack ZIPs under
// testdata/golden_legal_pack/. The packs are NOT committed; this script
// regenerates them on demand for smoke-testing the built binary.
//
// Run:
//
//	cd /Volumes/FDC_MASTER/source/verifier
//	go run ./testdata/gen
//
// Output:
//
//	testdata/golden_legal_pack/valid-2026-05-19.zip       — consistent pack
//	testdata/golden_legal_pack/tampered-audio.zip         — audio bytes mutated post-seal
//	testdata/golden_legal_pack/tampered-qr.zip            — QR payload re-issued for a different recording
//	testdata/golden_legal_pack/tampered-sha-report.zip    — sha256_report.txt SHA claim flipped
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

const (
	outDir         = "testdata/golden_legal_pack"
	recordingID    = "Golden_Recording_2026-05-19_aaaaaaaa"
	createdAt      = "2026-05-19T10:00:00+00:00"
	language       = "de-DE"
	chainHashBytes = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func main() {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fail("mkdir: %v", err)
	}

	audio := []byte("golden-pack audio bytes 2026-05-19 — deterministic content for snapshot tests")
	sum := sha256.Sum256(audio)
	audioHex := hex.EncodeToString(sum[:])

	writePack(filepath.Join(outDir, "valid-2026-05-19.zip"), packSpec{
		audioBytes:      audio,
		reportSHA256:    audioHex,
		reportChainHash: chainHashBytes,
		reportRecID:     recordingID,
		qrID:            recordingID,
		qrSHA256:        audioHex,
		qrChainHash:     chainHashBytes,
		qrCreatedAt:     createdAt,
	})
	fmt.Println("✓ valid-2026-05-19.zip")

	tampered := append([]byte("MODIFIED-AFTER-SEALING:"), audio...)
	writePack(filepath.Join(outDir, "tampered-audio.zip"), packSpec{
		audioBytes:      tampered,
		reportSHA256:    audioHex,
		reportChainHash: chainHashBytes,
		reportRecID:     recordingID,
		qrID:            recordingID,
		qrSHA256:        audioHex,
		qrChainHash:     chainHashBytes,
		qrCreatedAt:     createdAt,
	})
	fmt.Println("✓ tampered-audio.zip")

	writePack(filepath.Join(outDir, "tampered-qr.zip"), packSpec{
		audioBytes:      audio,
		reportSHA256:    audioHex,
		reportChainHash: chainHashBytes,
		reportRecID:     recordingID,
		qrID:            "INJECTED_Different_Recording_Id",
		qrSHA256:        audioHex,
		qrChainHash:     chainHashBytes,
		qrCreatedAt:     createdAt,
	})
	fmt.Println("✓ tampered-qr.zip")

	wrongSHA := strings.Repeat("d", 64)
	writePack(filepath.Join(outDir, "tampered-sha-report.zip"), packSpec{
		audioBytes:      audio,
		reportSHA256:    wrongSHA,
		reportChainHash: chainHashBytes,
		reportRecID:     recordingID,
		qrID:            recordingID,
		qrSHA256:        wrongSHA,
		qrChainHash:     chainHashBytes,
		qrCreatedAt:     createdAt,
	})
	fmt.Println("✓ tampered-sha-report.zip")

	fmt.Println()
	fmt.Println("All fixtures written to", outDir)
}

type packSpec struct {
	audioBytes      []byte
	reportSHA256    string
	reportChainHash string
	reportRecID     string
	qrID            string
	qrSHA256        string
	qrChainHash     string
	qrCreatedAt     string
}

func writePack(path string, s packSpec) {
	out, err := os.Create(path)
	if err != nil {
		fail("create %s: %v", path, err)
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	defer zw.Close()

	report := fmt.Sprintf(`CKNF SHA-256 INTEGRITY REPORT
============================================================
Recording ID:         %s
Audio File:           original.m4a
File Size:            %d bytes
SHA-256:              %s

Created:              %s
Language:             %s

Chain Hash:           %s
Chain Prev:           (genesis)
Identity Fingerprint: (none)

TSA Status:           NOT AVAILABLE - offline (deferred retry available)
TSA Note:             test-only

============================================================
`, s.reportRecID, len(s.audioBytes), s.reportSHA256, createdAt, language, s.reportChainHash)

	payload := map[string]string{
		"id":         s.qrID,
		"sha256":     s.qrSHA256,
		"chain_hash": s.qrChainHash,
		"created_at": s.qrCreatedAt,
	}
	pb, _ := json.Marshal(payload)
	qrPNG, err := qrcode.Encode(string(pb), qrcode.High, 512)
	if err != nil {
		fail("qrcode.Encode: %v", err)
	}

	auditLine := fmt.Sprintf(
		`{"ts":"%s","event":"GOLDEN_FIXTURE","role":"operator","identity_fingerprint":"(none)","detail":{}}`+"\n",
		createdAt,
	)

	for name, content := range map[string]string{
		"original.m4a":           string(s.audioBytes),
		"sha256_report.txt":      report,
		"transcript_raw.txt":     "raw transcript (synthetic)\n",
		"transcript_clean.txt":   "clean transcript (synthetic)\n",
		"transcript.docx":        "synthetic docx",
		"transcript_history.txt": "(no version history)\n",
		"chain_of_custody.pdf":   "synthetic pdf",
		"audit.jsonl":            auditLine,
		"verification_qr.png":    string(qrPNG),
		"cover.pdf":              "synthetic pdf",
	} {
		fw, err := zw.Create(name)
		if err != nil {
			fail("zip create %s: %v", name, err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			fail("zip write %s: %v", name, err)
		}
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
