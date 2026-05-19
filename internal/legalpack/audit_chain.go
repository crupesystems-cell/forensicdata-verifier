// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package legalpack

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/crupesystems-cell/forensicdata-verifier/internal/canonicaljson"
)

// AuditEntry is one parsed line of `audit.jsonl`. The first five fields
// match the CKNF Python source `recording_store.append_audit` schema:
//
//	{"ts": "...", "event": "...", "identity_fingerprint": "...",
//	 "role": "operator", "detail": {...}}
//
// Two additional fields are recognised but optional. They are placeholders
// for the planned per-event hash-chain (Plan §5/C.1). When CKNF eventually
// emits them, this verifier picks them up without code changes.
type AuditEntry struct {
	TS                  string         `json:"ts"`
	Event               string         `json:"event"`
	Role                string         `json:"role,omitempty"`
	IdentityFingerprint string         `json:"identity_fingerprint,omitempty"`
	Detail              map[string]any `json:"detail,omitempty"`

	// Optional hash-chain fields. Populated when present in the JSONL line,
	// left empty otherwise. Their presence drives whether VerifyAuditChain
	// performs cryptographic verification or only structural verification.
	SelfHash string `json:"self_hash,omitempty"`
	PrevHash string `json:"prev_hash,omitempty"`

	// Raw is the original line bytes (without trailing newline). Captured so
	// we can compute hash-equivalence checks without re-serializing through
	// Go's encoder (which may produce a different byte layout than Python).
	Raw string `json:"-"`
}

// AuditReport summarises the audit.jsonl verification outcome.
type AuditReport struct {
	// Count is the number of well-formed event entries.
	Count int
	// Signed is true iff at least one entry carried both self_hash and
	// prev_hash (or the genesis "" prev_hash). When false, VerifyAuditChain
	// returns nil — there is no chain to verify.
	Signed bool
	// Entries is the parsed entries, in file order.
	Entries []AuditEntry
}

// ParseAuditJSONL parses the bytes of an audit.jsonl entry. Each non-empty
// line MUST be a valid JSON object. Blank lines are skipped. A trailing
// newline is tolerated. Any malformed line surfaces as an error — partial
// parses are unacceptable for a forensic chain.
//
// Numeric values inside `detail` are parsed as json.Number so the
// canonical-JSON recompute later can distinguish integers from floats.
// Standard json.Unmarshal would silently widen integer-shaped numbers to
// float64, which would then trip canonicaljson's float guard.
func ParseAuditJSONL(content []byte) (*AuditReport, error) {
	report := &AuditReport{}
	if len(content) == 0 {
		return report, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimRight(scanner.Text(), "\r")
		if strings.TrimSpace(raw) == "" {
			continue
		}
		entry, err := parseAuditEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("audit.jsonl line %d: %w", lineNo, err)
		}
		report.Entries = append(report.Entries, entry)
		report.Count++
		if entry.SelfHash != "" {
			report.Signed = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit.jsonl scan: %w", err)
	}
	return report, nil
}

// parseAuditEntry decodes one JSON-object line using json.Number for all
// numeric leaves. Keeping integers as json.Number lets the canonical-JSON
// recompute emit them byte-identical to Python (which uses int, not float).
func parseAuditEntry(raw string) (AuditEntry, error) {
	var generic map[string]any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return AuditEntry{}, fmt.Errorf("invalid JSON: %w", err)
	}

	entry := AuditEntry{Raw: raw}
	if v, ok := generic["ts"].(string); ok {
		entry.TS = v
	}
	if v, ok := generic["event"].(string); ok {
		entry.Event = v
	}
	if v, ok := generic["role"].(string); ok {
		entry.Role = v
	}
	if v, ok := generic["identity_fingerprint"].(string); ok {
		entry.IdentityFingerprint = v
	}
	if v, ok := generic["self_hash"].(string); ok {
		entry.SelfHash = v
	}
	if v, ok := generic["prev_hash"].(string); ok {
		entry.PrevHash = v
	}
	if v, ok := generic["detail"].(map[string]any); ok {
		entry.Detail = v
	}

	if entry.TS == "" {
		return AuditEntry{}, fmt.Errorf("missing 'ts' field")
	}
	if entry.Event == "" {
		return AuditEntry{}, fmt.Errorf("missing 'event' field")
	}
	return entry, nil
}

// VerifyAuditChain runs the cryptographic chain check on an AuditReport
// whose Signed field is true. For each entry it confirms:
//
//  1. self_hash[i] == sha256_of_canonical_json(entry_without_self_hash[i])
//  2. prev_hash[i] == self_hash[i-1]   (or "" for the genesis link)
//
// On an unsigned report (no self_hash fields present anywhere), this is a
// no-op returning nil — there is no chain to verify. The fact that the
// audit log is unsigned is reported separately by AuditReport.Signed and
// surfaced by the legal-pack orchestrator as a SKIPPED check, not a FAIL.
//
// Mixed reports — some entries signed and others not — are rejected as a
// format violation: a partial chain cannot be forensically verified.
func VerifyAuditChain(report *AuditReport) error {
	if report == nil {
		return fmt.Errorf("verify audit chain: report is nil")
	}
	if !report.Signed {
		return nil
	}

	var prev string
	for i, entry := range report.Entries {
		if entry.SelfHash == "" {
			return fmt.Errorf(
				"audit.jsonl entry %d (event=%s ts=%s) is missing self_hash "+
					"— partial chains cannot be verified",
				i, entry.Event, entry.TS,
			)
		}
		expected, err := computeSelfHash(entry)
		if err != nil {
			return fmt.Errorf("audit.jsonl entry %d: cannot compute self_hash: %w", i, err)
		}
		if expected != entry.SelfHash {
			return fmt.Errorf(
				"audit.jsonl entry %d (event=%s) self_hash MISMATCH\n"+
					"    claimed:  %s\n"+
					"    computed: %s\n"+
					"  → event fields were modified after the audit was signed",
				i, entry.Event, entry.SelfHash, expected,
			)
		}
		if entry.PrevHash != prev {
			return fmt.Errorf(
				"audit.jsonl entry %d (event=%s) prev_hash linkage broken\n"+
					"    expected (previous self_hash): %s\n"+
					"    found (this prev_hash):        %s\n"+
					"  → audit chain has been spliced or re-ordered",
				i, entry.Event, prev, entry.PrevHash,
			)
		}
		prev = entry.SelfHash
	}
	return nil
}

// computeSelfHash returns the SHA-256 hex of canonical_json(entry with
// self_hash field removed). This is the recompute side of the chain check
// — for it to match the entry's claimed self_hash, both Python (CKNF) and
// Go (this verifier) must produce byte-identical canonical JSON.
func computeSelfHash(entry AuditEntry) (string, error) {
	m := map[string]any{
		"ts":    entry.TS,
		"event": entry.Event,
	}
	if entry.Role != "" {
		m["role"] = entry.Role
	}
	if entry.IdentityFingerprint != "" {
		m["identity_fingerprint"] = entry.IdentityFingerprint
	}
	if entry.Detail != nil {
		m["detail"] = entry.Detail
	}
	if entry.PrevHash != "" {
		m["prev_hash"] = entry.PrevHash
	}
	return canonicaljson.SHA256Hex(m)
}

// VerifyAuditJSONL is the top-level entry-point called by the legal-pack
// orchestrator. It reads the pack's audit.jsonl, parses every line, and
// runs the chain check when the log is signed. Returns the AuditReport
// (with Count + Signed fields populated) so the orchestrator can decide
// whether the chain-check verdict is PASS, SKIPPED, or FAIL.
func VerifyAuditJSONL(pack *Pack) (*AuditReport, error) {
	if pack == nil {
		return nil, fmt.Errorf("verify audit.jsonl: pack is nil")
	}
	raw, err := pack.ReadEntry(EntryAuditJsonl)
	if err != nil {
		return nil, fmt.Errorf("verify audit.jsonl: cannot read %s: %w", EntryAuditJsonl, err)
	}
	report, err := ParseAuditJSONL(raw)
	if err != nil {
		return nil, err
	}
	if err := VerifyAuditChain(report); err != nil {
		return report, err
	}
	return report, nil
}
