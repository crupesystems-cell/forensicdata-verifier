// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package legalpack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	_ "image/png" // register PNG decoder for image.Decode

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// QRPayload is the JSON object encoded inside `verification_qr.png`.
//
// The CKNF Python source emits this payload via `legal_pack._build_verification_qr`
// with `json.dumps(..., sort_keys=True, ensure_ascii=False)`. The four fields
// are deliberately kept tiny so the QR stays low-density and scanner-friendly.
type QRPayload struct {
	ID        string `json:"id"`
	SHA256    string `json:"sha256"`
	ChainHash string `json:"chain_hash"`
	CreatedAt string `json:"created_at"`
}

// DecodeQRPNG decodes a PNG-encoded QR image and returns the embedded text
// payload. Errors describe the failure stage (image-decode vs. QR-recognize)
// so the operator can distinguish a corrupted PNG from a damaged QR pattern.
//
// Decoder: gozxing (Go port of ZXing). Chosen over alternatives after
// observing byte-level mis-decode in liyue201/goqr on certain payload
// sizes — ZXing's error-correction handling is the reference implementation
// in the QR ecosystem.
func DecodeQRPNG(pngBytes []byte) (string, error) {
	if len(pngBytes) == 0 {
		return "", fmt.Errorf("decode qr: empty PNG bytes")
	}
	img, _, err := image.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		return "", fmt.Errorf("decode qr: PNG decode failed: %w", err)
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("decode qr: bitmap construction failed: %w", err)
	}
	reader := qrcode.NewQRCodeReader()
	result, err := reader.Decode(bmp, nil)
	if err != nil {
		return "", fmt.Errorf("decode qr: QR recognition failed: %w", err)
	}
	return result.GetText(), nil
}

// ParseQRPayload parses the JSON payload string into a QRPayload. The four
// CKNF fields are required; an empty value in any field is rejected so a
// half-populated forensic payload cannot silently pass verification.
func ParseQRPayload(payload string) (*QRPayload, error) {
	if payload == "" {
		return nil, fmt.Errorf("parse qr payload: empty string")
	}
	var p QRPayload
	dec := json.NewDecoder(bytes.NewReader([]byte(payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse qr payload: JSON decode failed: %w", err)
	}
	if p.ID == "" {
		return nil, fmt.Errorf("parse qr payload: missing 'id'")
	}
	if p.SHA256 == "" {
		return nil, fmt.Errorf("parse qr payload: missing 'sha256'")
	}
	if p.ChainHash == "" {
		return nil, fmt.Errorf("parse qr payload: missing 'chain_hash'")
	}
	if p.CreatedAt == "" {
		return nil, fmt.Errorf("parse qr payload: missing 'created_at'")
	}
	return &p, nil
}

// VerifyQR is the legal-pack verification step that confirms the QR image
// inside the pack carries a payload consistent with sha256_report.txt.
//
// A mismatch means EITHER the QR was regenerated from a different recording
// (substitution attack), OR the sha256_report.txt was modified after the QR
// was sealed. Either path: pack is no longer forensically intact.
//
// Returns nil on PASS; a descriptive error on FAIL. Errors are designed to
// be safe to surface verbatim in CLI output.
func VerifyQR(pack *Pack, report *Sha256Report) error {
	if pack == nil {
		return fmt.Errorf("verify qr: pack is nil")
	}
	if report == nil {
		return fmt.Errorf("verify qr: sha256_report is nil")
	}

	pngBytes, err := pack.ReadEntry(EntryVerificationQR)
	if err != nil {
		return fmt.Errorf("verify qr: cannot read %s: %w", EntryVerificationQR, err)
	}
	payloadStr, err := DecodeQRPNG(pngBytes)
	if err != nil {
		return fmt.Errorf("verify qr: %w", err)
	}
	payload, err := ParseQRPayload(payloadStr)
	if err != nil {
		return fmt.Errorf("verify qr: %w", err)
	}

	// Cross-check each field against sha256_report.txt. We compare the
	// three forensically-load-bearing fields (id, sha256, chain_hash). The
	// created_at field is informational and not cross-checked against the
	// report (the report carries its own "Created" timestamp, which may
	// differ in formatting; both are signed by the chain-hash so neither
	// can drift silently).
	if payload.ID != report.RecordingID {
		return fmt.Errorf(
			"verify qr: recording_id MISMATCH\n"+
				"    sha256_report.txt: %s\n"+
				"    verification_qr:   %s\n"+
				"  → pack pieces were not sealed together",
			report.RecordingID, payload.ID,
		)
	}
	if payload.SHA256 != report.SHA256 {
		return fmt.Errorf(
			"verify qr: audio SHA-256 MISMATCH\n"+
				"    sha256_report.txt: %s\n"+
				"    verification_qr:   %s\n"+
				"  → pack pieces were not sealed together",
			report.SHA256, payload.SHA256,
		)
	}
	// The report's ChainHash is empty only when the source recording was
	// emitted with the "(unset)" sentinel — degenerate but legal. In that
	// case the QR payload is permitted to carry any non-empty chain_hash
	// (older recordings) without raising a failure here; callers wanting
	// strict equivalence must check both directly.
	if report.ChainHash != "" && payload.ChainHash != report.ChainHash {
		return fmt.Errorf(
			"verify qr: chain_hash MISMATCH\n"+
				"    sha256_report.txt: %s\n"+
				"    verification_qr:   %s\n"+
				"  → forensic chain anchor disagrees between pack pieces",
			report.ChainHash, payload.ChainHash,
		)
	}

	return nil
}
