// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package legalpack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// VerifyAudioSHA256 is the first real forensic check in the legal-pack
// verification pipeline: it confirms that the audio bytes inside the pack
// hash to exactly the SHA-256 value claimed in the pack's sha256_report.txt.
//
// A mismatch means EITHER the audio file was modified after the recording
// was sealed (tampering), OR the sha256_report.txt was modified
// independently (also tampering). Either way: the pack is no longer
// forensically intact.
//
// Returns nil on PASS; a descriptive error on any FAIL or precondition gap.
// Errors are designed to be safe to surface in CLI output verbatim.
func VerifyAudioSHA256(pack *Pack, report *Sha256Report) error {
	if pack == nil {
		return fmt.Errorf("verify audio: pack is nil")
	}
	if report == nil {
		return fmt.Errorf("verify audio: sha256_report is nil")
	}

	audioName := pack.AudioEntry()
	if audioName == "" {
		return fmt.Errorf(
			"verify audio: pack contains no audio entry (expected %s or %s)",
			EntryAudioMac, EntryAudioWin,
		)
	}

	// Cross-check the report's claimed audio filename against what the pack
	// actually contains. Empty report.AudioFilename is tolerated (older
	// packs may not have populated this field consistently).
	if report.AudioFilename != "" && report.AudioFilename != audioName {
		return fmt.Errorf(
			"verify audio: pack contains entry %q but sha256_report.txt claims %q "+
				"— pack composition is inconsistent",
			audioName, report.AudioFilename,
		)
	}

	audioBytes, err := pack.ReadEntry(audioName)
	if err != nil {
		return fmt.Errorf("verify audio: cannot read %s: %w", audioName, err)
	}

	sum := sha256.Sum256(audioBytes)
	got := hex.EncodeToString(sum[:])
	if got != report.SHA256 {
		return fmt.Errorf(
			"verify audio: SHA-256 MISMATCH for %s\n"+
				"    sha256_report.txt claims: %s\n"+
				"    computed from bytes:      %s\n"+
				"  → audio file or report has been modified since sealing",
			audioName, report.SHA256, got,
		)
	}

	return nil
}
