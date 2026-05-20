// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

// audit.go — Bundle-Spec v1.0 §10.2 hash-chain validation (Go verifier side).
//
// Byte-exact Go mirror of:
//
//	/Volumes/FDC_MASTER/SIS/packages/forensicdata_audit/src/forensicdata_audit/chain.py
//
// Verify-only: reads `audit/events.jsonl` from a bundle and validates the
// hash-chain. Failure → AUDIT_CHAIN_BROKEN (§12.3 Exit 25).

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ZeroHash is the §10.2 chain-genesis sentinel (64 lowercase hex zeros).
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// AuditEventMap is the parsed form of one `events.jsonl` line. We hold the
// raw JSON map (instead of a typed struct) so that re-canonicalisation
// preserves the producer's exact field set — including any spec-additive
// fields a future minor release may introduce.
type AuditEventMap map[string]any

// ChainValidationResult mirrors Python `ChainValidationResult` and feeds
// the §12.3 priority resolver via the `auditChainCheck` orchestrator.
type ChainValidationResult struct {
	Valid           bool
	BrokenAtIndex   int    // -1 when valid
	BrokenAtEventID string // "" when valid
	Error           string // "" when valid
}

// parseAuditEventsJSONL parses raw `events.jsonl` bytes into a slice of
// events. Blank lines are skipped (matching Python `read_events_jsonl`).
// Malformed JSON returns an error with line number for operator triage.
func parseAuditEventsJSONL(data []byte) ([]AuditEventMap, error) {
	var events []AuditEventMap
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Allow up to 1 MiB per audit line (defensive — spec lines are small).
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev AuditEventMap
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan events.jsonl: %w", err)
	}
	return events, nil
}

// hashStoredEventLine returns SHA-256 (lowercase hex) of canonical-JSON of
// the full event. Mirrors Python `hash_stored_event_line`.
func hashStoredEventLine(ev AuditEventMap) (string, error) {
	canon, err := CanonicalJSON(ev)
	if err != nil {
		return "", fmt.Errorf("canonicalise event: %w", err)
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// computeCurrentEventHash returns SHA-256 (lowercase hex) of canonical-JSON
// of the event with `current_event_hash` cleared to "" (Bundle-Spec §10.2
// protocol). Mirrors Python `compute_current_event_hash`.
func computeCurrentEventHash(ev AuditEventMap) (string, error) {
	// Shallow copy so we don't mutate the caller's map.
	payload := make(AuditEventMap, len(ev))
	for k, v := range ev {
		payload[k] = v
	}
	payload["current_event_hash"] = ""
	canon, err := CanonicalJSON(payload)
	if err != nil {
		return "", fmt.Errorf("canonicalise event-for-hashing: %w", err)
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// stringField is a defensive accessor: returns "" if the key is missing or
// the value is not a string.
func stringField(ev AuditEventMap, key string) string {
	if v, ok := ev[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func hashExcerpt(h string) string {
	if len(h) >= 8 {
		return h[:8]
	}
	return h
}

// ValidateAuditChain re-derives `previous_event_hash` and
// `current_event_hash` for every event and returns the first broken link.
// Mirrors Python `validate_chain` byte-for-byte (Bundle-Spec §10.2).
func ValidateAuditChain(events []AuditEventMap) ChainValidationResult {
	if len(events) == 0 {
		return ChainValidationResult{Valid: true, BrokenAtIndex: -1}
	}

	for i, ev := range events {
		var expectedPrev string
		if i == 0 {
			expectedPrev = ZeroHash
		} else {
			h, err := hashStoredEventLine(events[i-1])
			if err != nil {
				return ChainValidationResult{
					Valid:           false,
					BrokenAtIndex:   i,
					BrokenAtEventID: stringField(ev, "event_id"),
					Error: fmt.Sprintf(
						"canonicalise prior event at index %d: %v", i-1, err),
				}
			}
			expectedPrev = h
		}

		gotPrev := stringField(ev, "previous_event_hash")
		if gotPrev != expectedPrev {
			return ChainValidationResult{
				Valid:           false,
				BrokenAtIndex:   i,
				BrokenAtEventID: stringField(ev, "event_id"),
				Error: fmt.Sprintf(
					"previous_event_hash mismatch at position %d (event %q): expected %s…, got %s…",
					i, stringField(ev, "event_id"),
					hashExcerpt(expectedPrev), hashExcerpt(gotPrev)),
			}
		}

		expectedCur, err := computeCurrentEventHash(ev)
		if err != nil {
			return ChainValidationResult{
				Valid:           false,
				BrokenAtIndex:   i,
				BrokenAtEventID: stringField(ev, "event_id"),
				Error: fmt.Sprintf(
					"canonicalise event at index %d: %v", i, err),
			}
		}
		gotCur := stringField(ev, "current_event_hash")
		if gotCur != expectedCur {
			return ChainValidationResult{
				Valid:           false,
				BrokenAtIndex:   i,
				BrokenAtEventID: stringField(ev, "event_id"),
				Error: fmt.Sprintf(
					"current_event_hash mismatch at position %d (event %q): expected %s…, got %s…",
					i, stringField(ev, "event_id"),
					hashExcerpt(expectedCur), hashExcerpt(gotCur)),
			}
		}
	}

	return ChainValidationResult{Valid: true, BrokenAtIndex: -1}
}

// auditChainCheck is the §12.1 #9 orchestrator entry point.
//
// Behaviour:
//   - No `audit/events.jsonl` entry in bundle → PASS with informational
//     detail. Absence is a presence-layer concern (handled by
//     `manifest_present` / `MissingRequired`), not a chain-validity one.
//   - Empty file (zero events) → PASS.
//   - Parse error / chain link broken → FAIL with diagnostic.
func auditChainCheck(r *Reader) CheckResult {
	if !r.HasEntry(EntryAuditEventsJSON) {
		return CheckResult{
			Name:   checkAuditChain,
			Result: resultPass,
			Detail: fmt.Sprintf("no %s in bundle (audit layer absent)", EntryAuditEventsJSON),
		}
	}

	data, err := r.ReadEntry(EntryAuditEventsJSON)
	if err != nil {
		return CheckResult{
			Name:   checkAuditChain,
			Result: resultFail,
			Error:  fmt.Sprintf("read %s: %v", EntryAuditEventsJSON, err),
		}
	}

	events, err := parseAuditEventsJSONL(data)
	if err != nil {
		return CheckResult{
			Name:   checkAuditChain,
			Result: resultFail,
			Error:  fmt.Sprintf("parse %s: %v", EntryAuditEventsJSON, err),
		}
	}

	res := ValidateAuditChain(events)
	if !res.Valid {
		return CheckResult{
			Name:   checkAuditChain,
			Result: resultFail,
			Error:  res.Error,
		}
	}

	return CheckResult{
		Name:   checkAuditChain,
		Result: resultPass,
		Detail: fmt.Sprintf("hash chain validated over %d event(s)", len(events)),
	}
}
