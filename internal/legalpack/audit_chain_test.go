// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Stage C.1 — audit.jsonl chain-integrity.

package legalpack

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crupesystems-cell/forensicdata-verifier/internal/canonicaljson"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// makeUnsignedLine emits a CKNF-current-style audit.jsonl line (no chain
// fields). The role and detail are kept simple — chain logic does not look
// at them, only Parse does.
func makeUnsignedLine(ts, event string, detail map[string]any) string {
	m := map[string]any{
		"ts":                   ts,
		"event":                event,
		"identity_fingerprint": "(none)",
		"role":                 "operator",
	}
	if detail != nil {
		m["detail"] = detail
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// makeSignedEntry returns a JSONL line with self_hash and prev_hash
// populated according to the chain protocol. prev = "" for the genesis link.
func makeSignedEntry(t *testing.T, ts, event, role, fp, prev string, detail map[string]any) string {
	t.Helper()
	body := map[string]any{
		"ts":    ts,
		"event": event,
	}
	if role != "" {
		body["role"] = role
	}
	if fp != "" {
		body["identity_fingerprint"] = fp
	}
	if detail != nil {
		body["detail"] = detail
	}
	if prev != "" {
		body["prev_hash"] = prev
	}
	self, err := canonicaljson.SHA256Hex(body)
	if err != nil {
		t.Fatalf("compute self_hash: %v", err)
	}

	full := map[string]any{
		"ts":        ts,
		"event":     event,
		"prev_hash": prev,
		"self_hash": self,
	}
	if role != "" {
		full["role"] = role
	}
	if fp != "" {
		full["identity_fingerprint"] = fp
	}
	if detail != nil {
		full["detail"] = detail
	}
	b, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	return string(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// ParseAuditJSONL
// ─────────────────────────────────────────────────────────────────────────────

func TestParseAuditJSONL_Empty(t *testing.T) {
	r, err := ParseAuditJSONL([]byte{})
	if err != nil {
		t.Fatalf("ParseAuditJSONL on empty content: %v", err)
	}
	if r.Count != 0 || r.Signed || len(r.Entries) != 0 {
		t.Errorf("empty content should yield zero entries, got: %+v", r)
	}
}

func TestParseAuditJSONL_HappyUnsigned(t *testing.T) {
	body := strings.Join([]string{
		makeUnsignedLine("2026-05-19T10:00:00+00:00", "RECORDING_STARTED", nil),
		makeUnsignedLine("2026-05-19T10:01:00+00:00", "RECORDING_FINALIZED",
			map[string]any{"duration_s": 60}),
		makeUnsignedLine("2026-05-19T10:02:00+00:00", "LEGAL_PACK_BUILT", nil),
	}, "\n") + "\n"

	r, err := ParseAuditJSONL([]byte(body))
	if err != nil {
		t.Fatalf("ParseAuditJSONL: %v", err)
	}
	if r.Count != 3 {
		t.Errorf("want 3 entries, got %d", r.Count)
	}
	if r.Signed {
		t.Errorf("unsigned audit should have Signed=false")
	}
	if r.Entries[0].Event != "RECORDING_STARTED" {
		t.Errorf("first event: got %q", r.Entries[0].Event)
	}
}

func TestParseAuditJSONL_BlankLinesAndCRLFTolerated(t *testing.T) {
	line := makeUnsignedLine("2026-05-19T10:00:00+00:00", "EVENT_A", nil)
	body := "\r\n" + line + "\r\n\r\n" + line + "\r\n"
	r, err := ParseAuditJSONL([]byte(body))
	if err != nil {
		t.Fatalf("ParseAuditJSONL CRLF+blank: %v", err)
	}
	if r.Count != 2 {
		t.Errorf("want 2 entries (blanks skipped), got %d", r.Count)
	}
}

func TestParseAuditJSONL_MalformedLineFails(t *testing.T) {
	body := makeUnsignedLine("2026-05-19T10:00:00+00:00", "OK", nil) + "\n" +
		"{ not json }\n"
	_, err := ParseAuditJSONL([]byte(body))
	if err == nil {
		t.Fatal("expected error on malformed JSON line")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error should pinpoint line 2, got: %v", err)
	}
}

func TestParseAuditJSONL_MissingTSFails(t *testing.T) {
	body := `{"event":"OK","role":"operator"}` + "\n"
	_, err := ParseAuditJSONL([]byte(body))
	if err == nil {
		t.Fatal("expected error on missing ts")
	}
	if !strings.Contains(err.Error(), "missing 'ts'") {
		t.Errorf("error should mention missing ts, got: %v", err)
	}
}

func TestParseAuditJSONL_MissingEventFails(t *testing.T) {
	body := `{"ts":"2026-05-19T10:00:00+00:00","role":"operator"}` + "\n"
	_, err := ParseAuditJSONL([]byte(body))
	if err == nil {
		t.Fatal("expected error on missing event")
	}
	if !strings.Contains(err.Error(), "missing 'event'") {
		t.Errorf("error should mention missing event, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyAuditChain — unsigned path
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyAuditChain_UnsignedIsNoOp(t *testing.T) {
	body := makeUnsignedLine("2026-05-19T10:00:00+00:00", "EVENT_A", nil) + "\n"
	r, err := ParseAuditJSONL([]byte(body))
	if err != nil {
		t.Fatalf("ParseAuditJSONL: %v", err)
	}
	if r.Signed {
		t.Fatalf("setup error: unsigned audit should have Signed=false")
	}
	if err := VerifyAuditChain(r); err != nil {
		t.Errorf("unsigned chain should be a no-op, got: %v", err)
	}
}

func TestVerifyAuditChain_NilReport(t *testing.T) {
	if err := VerifyAuditChain(nil); err == nil {
		t.Error("expected error on nil report")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyAuditChain — signed path
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyAuditChain_HappySignedChain(t *testing.T) {
	body := makeSignedEntry(t, "2026-05-19T10:00:00+00:00", "RECORDING_STARTED",
		"operator", "(none)", "", nil)

	r, err := ParseAuditJSONL([]byte(body + "\n"))
	if err != nil {
		t.Fatalf("ParseAuditJSONL: %v", err)
	}
	firstSelf := r.Entries[0].SelfHash

	body += "\n" + makeSignedEntry(t, "2026-05-19T10:01:00+00:00",
		"RECORDING_FINALIZED", "operator", "(none)", firstSelf,
		map[string]any{"duration_s": 60})

	r, err = ParseAuditJSONL([]byte(body + "\n"))
	if err != nil {
		t.Fatalf("ParseAuditJSONL 2-link: %v", err)
	}
	secondSelf := r.Entries[1].SelfHash

	body += "\n" + makeSignedEntry(t, "2026-05-19T10:02:00+00:00",
		"LEGAL_PACK_BUILT", "operator", "(none)", secondSelf, nil)

	r, err = ParseAuditJSONL([]byte(body + "\n"))
	if err != nil {
		t.Fatalf("ParseAuditJSONL 3-link: %v", err)
	}
	if !r.Signed {
		t.Fatalf("3-link audit should be Signed=true")
	}
	if err := VerifyAuditChain(r); err != nil {
		t.Errorf("happy signed chain failed verification: %v", err)
	}
}

func TestVerifyAuditChain_TamperedEventFails(t *testing.T) {
	first := makeSignedEntry(t, "2026-05-19T10:00:00+00:00", "EVENT_A",
		"operator", "(none)", "", nil)
	tampered := strings.Replace(first, `"event":"EVENT_A"`, `"event":"EVENT_TAMPERED"`, 1)

	r, err := ParseAuditJSONL([]byte(tampered + "\n"))
	if err != nil {
		t.Fatalf("ParseAuditJSONL tampered: %v", err)
	}
	err = VerifyAuditChain(r)
	if err == nil {
		t.Fatal("expected self_hash mismatch on tampered event")
	}
	if !strings.Contains(err.Error(), "self_hash MISMATCH") {
		t.Errorf("error should mention self_hash MISMATCH, got: %v", err)
	}
}

func TestVerifyAuditChain_BrokenLinkageFails(t *testing.T) {
	first := makeSignedEntry(t, "2026-05-19T10:00:00+00:00", "A",
		"operator", "(none)", "", nil)

	wrongPrev := strings.Repeat("f", 64)
	second := makeSignedEntry(t, "2026-05-19T10:01:00+00:00", "B",
		"operator", "(none)", wrongPrev, nil)

	body := first + "\n" + second + "\n"
	r, _ := ParseAuditJSONL([]byte(body))
	err := VerifyAuditChain(r)
	if err == nil {
		t.Fatal("expected linkage error")
	}
	if !strings.Contains(err.Error(), "prev_hash linkage broken") {
		t.Errorf("error should mention prev_hash linkage broken, got: %v", err)
	}
}

func TestVerifyAuditChain_PartialSignedFails(t *testing.T) {
	signed := makeSignedEntry(t, "2026-05-19T10:00:00+00:00", "A",
		"operator", "(none)", "", nil)
	unsigned := makeUnsignedLine("2026-05-19T10:01:00+00:00", "B", nil)
	body := signed + "\n" + unsigned + "\n"
	r, err := ParseAuditJSONL([]byte(body))
	if err != nil {
		t.Fatalf("ParseAuditJSONL: %v", err)
	}
	if !r.Signed {
		t.Fatalf("setup: at least one entry is signed, Signed should be true")
	}
	err = VerifyAuditChain(r)
	if err == nil {
		t.Fatal("expected error on partial chain")
	}
	if !strings.Contains(err.Error(), "missing self_hash") {
		t.Errorf("error should mention missing self_hash on partial chain, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyAuditJSONL — pack-level orchestration
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyAuditJSONL_HappyViaPack(t *testing.T) {
	body := makeUnsignedLine("2026-05-19T10:00:00+00:00", "EVENT_A", nil) + "\n"

	entries := minimalValidEntries()
	entries["audit.jsonl"] = body
	path := filepath.Join(t.TempDir(), "with_audit.zip")
	writeZip(t, path, entries)

	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pack.Close()

	report, err := VerifyAuditJSONL(pack)
	if err != nil {
		t.Fatalf("VerifyAuditJSONL: %v", err)
	}
	if report.Count != 1 || report.Signed {
		t.Errorf("expected 1 unsigned entry, got Count=%d Signed=%v", report.Count, report.Signed)
	}
}

func TestVerifyAuditJSONL_NilPack(t *testing.T) {
	if _, err := VerifyAuditJSONL(nil); err == nil {
		t.Error("expected error on nil pack")
	}
}

func TestVerifyAuditJSONL_MalformedFails(t *testing.T) {
	entries := minimalValidEntries()
	entries["audit.jsonl"] = "{ not json }\n"
	path := filepath.Join(t.TempDir(), "bad_audit.zip")
	writeZip(t, path, entries)

	pack, _ := Open(path)
	defer pack.Close()
	_, err := VerifyAuditJSONL(pack)
	if err == nil {
		t.Fatal("expected error on malformed audit.jsonl")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("error should mention 'invalid JSON', got: %v", err)
	}
}
