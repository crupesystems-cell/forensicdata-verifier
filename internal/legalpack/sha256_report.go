// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package legalpack

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Sha256Report is the parsed form of a CKNF Legal-Pack `sha256_report.txt`
// entry. The plain-text format is emitted by `legal_pack._build_sha256_report`
// in the CKNF Python source.
//
// Sentinel placeholders are normalized to empty string + boolean flag:
//   - ChainPrev = "(genesis)"   → ChainPrev="", ChainPrevIsGenesis=true
//   - IdentityFingerprint = "(none)" → ""  + IdentityFingerprintIsNone=true
//   - ChainHash = "(unset)"     → ChainHash="" (no companion flag; callers
//                                 must check the empty string explicitly)
type Sha256Report struct {
	RecordingID               string
	AudioFilename             string
	FileSize                  int64
	SHA256                    string // 64-char lowercase hex
	CreatedAt                 string // ISO-8601 as recorded; not re-parsed
	Language                  string // BCP-47, e.g. "de-DE"
	ChainHash                 string // 64-char lowercase hex, or "" if (unset)
	ChainPrev                 string // 64-char hex, or "" if (genesis)
	ChainPrevIsGenesis        bool
	IdentityFingerprint       string // 64-char hex, or "" if (none)
	IdentityFingerprintIsNone bool
	TSAPresent                bool  // true iff "TSA Status: PRESENT"
	TSATokenSize              int64 // bytes, only populated when TSAPresent
}

var (
	reportHeader   = "CKNF SHA-256 INTEGRITY REPORT"
	sha256HexShape = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ParseSha256Report parses the plain-text sha256_report.txt content.
//
// Format-discipline: this parser tolerates additional/unknown lines (forward
// compatibility) but REQUIRES the canonical header line and all named
// fields below to be present in the order CKNF emits them. A missing or
// malformed required field returns an error rather than silently producing
// a partial record — a half-parsed forensic report is worse than no parse
// at all.
func ParseSha256Report(content []byte) (*Sha256Report, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("sha256_report content is empty")
	}

	// Header check — fast-reject obviously wrong inputs.
	if !bytes.HasPrefix(content, []byte(reportHeader)) {
		return nil, fmt.Errorf("sha256_report: missing canonical header %q", reportHeader)
	}

	fields := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		// Lines we care about have the shape:  "Label:<spaces>Value"
		colonIdx := strings.Index(line, ":")
		if colonIdx <= 0 {
			continue
		}
		label := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])
		// Multiple occurrences of "TSA Status:" / "TSA Note:" etc. shouldn't
		// happen in canonical output; last-write-wins is acceptable.
		fields[label] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("sha256_report scan: %w", err)
	}

	r := &Sha256Report{}

	if r.RecordingID = fields["Recording ID"]; r.RecordingID == "" {
		return nil, fmt.Errorf("sha256_report: missing Recording ID")
	}
	if r.AudioFilename = fields["Audio File"]; r.AudioFilename == "" {
		return nil, fmt.Errorf("sha256_report: missing Audio File")
	}
	sizeStr := fields["File Size"]
	if sizeStr == "" {
		return nil, fmt.Errorf("sha256_report: missing File Size")
	}
	// "123456 bytes" → trim the suffix.
	sizeStr = strings.TrimSuffix(sizeStr, " bytes")
	sizeStr = strings.TrimSpace(sizeStr)
	sz, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("sha256_report: File Size %q is not numeric: %w", sizeStr, err)
	}
	r.FileSize = sz

	r.SHA256 = fields["SHA-256"]
	if r.SHA256 == "" {
		return nil, fmt.Errorf("sha256_report: missing SHA-256")
	}
	if !sha256HexShape.MatchString(r.SHA256) {
		return nil, fmt.Errorf("sha256_report: SHA-256 %q is not 64 lowercase hex chars", r.SHA256)
	}

	if r.CreatedAt = fields["Created"]; r.CreatedAt == "" {
		return nil, fmt.Errorf("sha256_report: missing Created")
	}
	if r.Language = fields["Language"]; r.Language == "" {
		return nil, fmt.Errorf("sha256_report: missing Language")
	}

	// Chain Hash — may be "(unset)" placeholder in degenerate cases.
	r.ChainHash = normalizePlaceholder(fields["Chain Hash"], "(unset)")
	// Chain Prev — "(genesis)" sentinel means "first link in the chain".
	r.ChainPrev, r.ChainPrevIsGenesis = normalizeWithFlag(fields["Chain Prev"], "(genesis)")
	// Identity Fingerprint — "(none)" sentinel means "operator chose not to bind".
	r.IdentityFingerprint, r.IdentityFingerprintIsNone = normalizeWithFlag(fields["Identity Fingerprint"], "(none)")

	// TSA Status: either "PRESENT" (followed by TSA Token Size + Standard)
	// or "NOT AVAILABLE - offline (deferred retry available)" (followed by a Note).
	tsaStatus := fields["TSA Status"]
	switch {
	case strings.HasPrefix(tsaStatus, "PRESENT"):
		r.TSAPresent = true
		tokenStr := strings.TrimSuffix(fields["TSA Token Size"], " bytes")
		tokenStr = strings.TrimSpace(tokenStr)
		if tokenStr != "" {
			ts, err := strconv.ParseInt(tokenStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("sha256_report: TSA Token Size %q is not numeric: %w", tokenStr, err)
			}
			r.TSATokenSize = ts
		}
	case strings.Contains(tsaStatus, "NOT AVAILABLE"):
		r.TSAPresent = false
	default:
		// Unknown TSA Status string — be strict to catch format drift.
		return nil, fmt.Errorf("sha256_report: unrecognized TSA Status %q", tsaStatus)
	}

	return r, nil
}

// normalizePlaceholder returns "" iff value matches the sentinel; otherwise
// returns the value unchanged. Use for fields where the placeholder needs
// to be invisible to downstream verifiers (e.g. they only care whether the
// hash exists).
func normalizePlaceholder(value, sentinel string) string {
	if value == sentinel {
		return ""
	}
	return value
}

// normalizeWithFlag returns (normalized-value, isSentinel-bool). Used for
// fields where downstream verifiers need to know explicitly whether the
// sentinel was set (e.g. genesis-link in the chain).
func normalizeWithFlag(value, sentinel string) (string, bool) {
	if value == sentinel {
		return "", true
	}
	return value, false
}
