// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package report renders a legalpack.Verdict for an operator. Two formats
// are supported:
//
//   - "human" — color-coded, copy-paste-friendly text for terminals and
//     email reports. Color sequences are emitted only when a TTY is
//     detected (`useColor=true`); otherwise plain text is emitted so the
//     output stays clean inside log files and CI logs.
//
//   - "json"  — deterministic JSON for downstream tooling. The schema
//     mirrors legalpack.Verdict; field order is fixed by the underlying
//     struct definition so snapshot tests stay stable.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/crupesystems-cell/forensicdata-verifier/internal/legalpack"
)

const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiGrey   = "\x1b[90m"
)

// Human renders the verdict as a multi-line operator-friendly report.
// If useColor is false, color escapes are omitted.
func Human(w io.Writer, v *legalpack.Verdict, useColor bool) error {
	if v == nil {
		return fmt.Errorf("report: nil verdict")
	}
	var b strings.Builder

	b.WriteString(colored(useColor, ansiGrey, "Format:  "))
	b.WriteString(v.Format)
	b.WriteString("\n")
	if v.RecordingID != "" {
		b.WriteString(colored(useColor, ansiGrey, "ID:      "))
		b.WriteString(v.RecordingID)
		b.WriteString("\n")
	}
	b.WriteString("\n")

	for _, c := range v.Checks {
		writeCheck(&b, c, useColor)
	}

	if v.AuditCount > 0 {
		b.WriteString(colored(useColor, ansiGrey,
			fmt.Sprintf("\nAudit log: %d event(s), chain %s\n", v.AuditCount, signedStr(v.AuditSigned))))
	}
	if v.TSAReport != nil {
		b.WriteString(colored(useColor, ansiGrey, "TSA:       "))
		b.WriteString(fmt.Sprintf("serial=%s, genTime=%s",
			v.TSAReport.SerialNumber, v.TSAReport.GenTime))
		if v.TSAReport.SigningCertSubject != "" {
			b.WriteString(", signer=" + v.TSAReport.SigningCertSubject)
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	switch v.OverallResult {
	case "PASS":
		b.WriteString(colored(useColor, ansiGreen, "VERDICT: PASS"))
	default:
		b.WriteString(colored(useColor, ansiRed, "VERDICT: FAIL"))
	}
	b.WriteString("\n")
	b.WriteString(v.Summary)
	b.WriteString("\n")

	_, err := w.Write([]byte(b.String()))
	return err
}

// JSON renders the verdict as a single JSON object with a trailing newline.
// Snapshot-stable: legalpack.Verdict's field tags fix the key order.
func JSON(w io.Writer, v *legalpack.Verdict) error {
	if v == nil {
		return fmt.Errorf("report: nil verdict")
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func writeCheck(b *strings.Builder, c legalpack.CheckResult, useColor bool) {
	var symbol, color string
	switch c.Result {
	case "PASS":
		symbol = "✓"
		color = ansiGreen
	case "FAIL":
		symbol = "✗"
		color = ansiRed
	case "SKIPPED":
		symbol = "○"
		color = ansiYellow
	default:
		symbol = "?"
		color = ansiGrey
	}
	b.WriteString(colored(useColor, color, fmt.Sprintf("%s %-20s ", symbol, c.Name)))
	switch c.Result {
	case "PASS":
		b.WriteString(c.Detail)
	case "FAIL":
		lines := strings.Split(c.Error, "\n")
		for i, ln := range lines {
			if i > 0 {
				b.WriteString("\n                       ")
			}
			b.WriteString(ln)
		}
	case "SKIPPED":
		b.WriteString(c.Skipped)
	}
	b.WriteString("\n")
}

func colored(use bool, color, s string) string {
	if !use {
		return s
	}
	return color + s + ansiReset
}

func signedStr(signed bool) string {
	if signed {
		return "is hash-chained"
	}
	return "unsigned (CKNF v2.3 schema)"
}
