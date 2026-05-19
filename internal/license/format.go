// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package license parses Consilium / FORensicData suite license strings.
//
// Scope: STRUCTURAL FORMAT VALIDATION ONLY.
//
// This package deliberately does NOT verify HMAC authenticity. Per
// 12_PLAN_VERIFIER_CLI__v1.md §7 Risk #1 (Option β), shipping the HMAC
// secret in the open-source verifier binary would expose it and let third
// parties forge keys. Authenticity verification requires the issuing
// service.
//
// What the parser confirms:
//   - The 4-char prefix is present (e.g. CKNF)
//   - The tier letter is L (Lifetime) or T (Trial)
//   - A 3-char programs code is present (e.g. CFS = CKNF+FDC+FDS suite)
//   - The serial is exactly 5 digits
//   - The checksum field is exactly 8 uppercase hex characters
//
// The parser additionally flags serials below the canonical wbr_keygen
// SERIAL_OFFSET (14822), because such a value — while structurally valid —
// cannot have been produced by the official generator and is therefore
// almost certainly fabricated or transcription-corrupted.
package license

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SerialOffset mirrors the SERIAL_OFFSET constant in wbr_keygen.py. The
// canonical generator computes Serial = Counter + SerialOffset, with
// Counter ∈ [1, 99999 - SerialOffset]. Serials below this offset are
// therefore structurally valid but never issued by the canonical pipeline.
const SerialOffset = 14822

// licenseRegex matches the Consilium unified license format:
//
//	PREFIX(4 A-Z) "-" TIER(L|T) PROGRAMS(3 A-Z) SERIAL(5 digits) "-" CHECKSUM(8 hex)
//
// Example: CKNF-LCFS15022-6FBF59ED
var licenseRegex = regexp.MustCompile(
	`^([A-Z]{4})-([LT])([A-Z]{3})(\d{5})-([0-9A-F]{8})$`,
)

// License is the structured form of a parsed license string. Fields are
// extracted verbatim — no authenticity claim is made by the presence of
// this struct.
type License struct {
	Prefix           string // 4-char product family code, e.g. "CKNF"
	Tier             string // single letter: "L" (Lifetime) or "T" (Trial)
	TierName         string // human-readable: "Lifetime" or "Trial"
	Programs         string // 3-char code, e.g. "CFS" for the full Suite
	Serial           int    // 5-digit serial as recovered from the string
	Checksum         string // 8-char uppercase hex (NOT HMAC-verified)
	SerialOutOfRange bool   // true iff Serial < SerialOffset+1 (canonical lower bound)
}

// Parse validates a license string and returns the parsed structure.
//
// It accepts leading/trailing whitespace (operators often paste with
// surrounding spaces). It rejects internal whitespace, lowercase hex in the
// checksum, and any structural deviation from the format.
//
// Returns a wrapped error on any structural failure; the error string is
// safe to surface in CLI output.
func Parse(s string) (*License, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil, fmt.Errorf("license string is empty")
	}

	m := licenseRegex.FindStringSubmatch(trimmed)
	if m == nil {
		return nil, fmt.Errorf(
			"license string %q does not match expected format "+
				"PREFIX(4 A-Z)-TIER(L|T)PROGRAMS(3 A-Z)SERIAL(5 digits)-CHECKSUM(8 hex)",
			trimmed,
		)
	}

	serial, err := strconv.Atoi(m[4])
	if err != nil {
		// Regex guarantees \d{5}; this is defensive only.
		return nil, fmt.Errorf("license serial %q is not numeric: %w", m[4], err)
	}

	lic := &License{
		Prefix:           m[1],
		Tier:             m[2],
		Programs:         m[3],
		Serial:           serial,
		Checksum:         m[5],
		SerialOutOfRange: serial < SerialOffset+1,
	}
	lic.TierName = tierName(lic.Tier)
	return lic, nil
}

// Format returns the canonical string form of the license. Always equal to
// the parser input for any successfully-parsed string (round-trip stable).
func (l *License) Format() string {
	return fmt.Sprintf(
		"%s-%s%s%05d-%s",
		l.Prefix, l.Tier, l.Programs, l.Serial, l.Checksum,
	)
}

// Describe returns a human-readable single-line summary suitable for CLI
// output. Deliberately makes no authenticity claim.
func (l *License) Describe() string {
	suffix := ""
	if l.SerialOutOfRange {
		suffix = fmt.Sprintf(
			" — WARNING: serial %d is below canonical lower bound %d, "+
				"likely fabricated or transcription error",
			l.Serial, SerialOffset+1,
		)
	}
	return fmt.Sprintf(
		"Format valid: Prefix=%s, Tier=%s, Programs=%s, Serial=%d, Checksum=%s%s",
		l.Prefix, l.TierName, l.Programs, l.Serial, l.Checksum, suffix,
	)
}

func tierName(tier string) string {
	switch tier {
	case "L":
		return "Lifetime"
	case "T":
		return "Trial"
	default:
		// Regex restricts to L|T, so this is defensive.
		return tier
	}
}
