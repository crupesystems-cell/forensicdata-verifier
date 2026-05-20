// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

// tsr.go — Bundle-Spec v1.0 §11 RFC 3161 timestamp-token verification
// (structural).
//
// §12.1 check #10 mandates that — when `manifest.tsr` is present — the
// verifier parses the DER-encoded TimeStampResponse and confirms that the
// embedded `messageImprint` matches SHA-256 of the canonical manifest.
//
// §12.2 (OPTIONAL) extends this to a cryptographic signature check against
// a bundled TSA-CA trust root. v0.2.1 (this file) implements only the
// structural part — the trust-root verification lands in a later release
// once Hubert ratifies a CA set.

import (
	"fmt"
	"strings"

	"github.com/crupesystems-cell/forensicdata-verifier/internal/tsa"
)

// verifyTSRImprint runs the algorithm + imprint checks against an
// already-parsed RFC 3161 token. Factored out of timestampCheck so it can
// be unit-tested without constructing a real TSR.
func verifyTSRImprint(info *tsa.TimestampInfo, manifestHashHex string) error {
	if info == nil {
		return fmt.Errorf("verify imprint: timestamp info is nil")
	}
	algo := strings.ToUpper(strings.ReplaceAll(info.HashAlgorithm, "-", ""))
	if algo != "SHA256" {
		return fmt.Errorf(
			"TSR hashAlgorithm = %q but Bundle-Spec v1.0 §11 mandates SHA-256",
			info.HashAlgorithm)
	}
	return tsa.VerifyDigest(info, manifestHashHex)
}

// timestampCheck is the §12.1 #10 orchestrator entry point.
//
// Behaviour:
//   - No `manifest.tsr` entry in bundle → PASS with informational detail.
//     (`TIMESTAMP_MISSING` per-package-class enforcement is a higher-level
//     policy concern; v0.2.1 does not warn on absence.)
//   - manifest.tsr present → parse via `internal/tsa`, verify
//     hashAlgorithm = SHA-256 and `hashedMessage` matches SHA-256 of
//     canonical manifest.
//   - Parse error / imprint mismatch → FAIL with TIMESTAMP_INVALID.
func timestampCheck(r *Reader, m *Manifest) CheckResult {
	if !r.HasEntry(EntryManifestTSR) {
		return CheckResult{
			Name:   checkTimestamp,
			Result: resultPass,
			Detail: fmt.Sprintf("no %s in bundle (timestamp absent)", EntryManifestTSR),
		}
	}

	tsrBytes, err := r.ReadEntry(EntryManifestTSR)
	if err != nil {
		return CheckResult{
			Name:   checkTimestamp,
			Result: resultFail,
			Error:  fmt.Sprintf("read %s: %v", EntryManifestTSR, err),
		}
	}

	info, err := tsa.Parse(tsrBytes)
	if err != nil {
		return CheckResult{
			Name:   checkTimestamp,
			Result: resultFail,
			Error:  fmt.Sprintf("parse RFC 3161 token: %v", err),
		}
	}

	// SHA-256 of the canonical manifest = Manifest.Hash() (per §8.1).
	manifestHash, err := m.Hash()
	if err != nil {
		return CheckResult{
			Name:   checkTimestamp,
			Result: resultFail,
			Error:  fmt.Sprintf("canonicalise manifest for TSR imprint check: %v", err),
		}
	}

	if err := verifyTSRImprint(info, manifestHash); err != nil {
		return CheckResult{
			Name:   checkTimestamp,
			Result: resultFail,
			Error:  err.Error(),
		}
	}

	detail := "RFC 3161 timestamp valid (imprint matches canonical manifest)"
	if info.GenTime != "" {
		detail += fmt.Sprintf("; genTime=%s", info.GenTime)
	}
	if info.SigningCertSubject != "" {
		detail += fmt.Sprintf("; tsa=%s", info.SigningCertSubject)
	}
	return CheckResult{
		Name:   checkTimestamp,
		Result: resultPass,
		Detail: detail,
	}
}
