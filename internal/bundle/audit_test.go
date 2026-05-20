// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"fmt"
	"strings"
	"testing"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

func makeEventNoHash(eventID, prev string) AuditEventMap {
	return AuditEventMap{
		"action":                "sealed",
		"actor_device":          "mac-test",
		"actor_installation_id": "0123456789abcdef0123456789abcdef",
		"current_event_hash":    "",
		"event_id":              eventID,
		"event_time":            "2026-05-22T10:00:00.000Z",
		"event_type":            "artifact_sealed",
		"object_id":             "abc123",
		"object_type":           "artifact",
		"previous_event_hash":   prev,
	}
}

func mustEvent(t *testing.T, eventID, prev string) AuditEventMap {
	t.Helper()
	ev := makeEventNoHash(eventID, prev)
	cur, err := computeCurrentEventHash(ev)
	if err != nil {
		t.Fatalf("computeCurrentEventHash: %v", err)
	}
	ev["current_event_hash"] = cur
	return ev
}

func mustChain(t *testing.T, n int) []AuditEventMap {
	t.Helper()
	events := make([]AuditEventMap, n)
	for i := 0; i < n; i++ {
		var prev string
		if i == 0 {
			prev = ZeroHash
		} else {
			h, err := hashStoredEventLine(events[i-1])
			if err != nil {
				t.Fatalf("hashStoredEventLine[%d]: %v", i-1, err)
			}
			prev = h
		}
		events[i] = mustEvent(t, fmt.Sprintf("evt-170000000000%d-aaa%d11", i, i), prev)
	}
	return events
}

// ── ZeroHash constant ────────────────────────────────────────────────────────

func TestZeroHashIs64Zeros(t *testing.T) {
	if len(ZeroHash) != 64 {
		t.Fatalf("ZeroHash length = %d, want 64", len(ZeroHash))
	}
	if ZeroHash != strings.Repeat("0", 64) {
		t.Fatalf("ZeroHash is not 64 zeros: %q", ZeroHash)
	}
}

// ── parseAuditEventsJSONL ────────────────────────────────────────────────────

func TestParseAuditEventsJSONL_Empty(t *testing.T) {
	events, err := parseAuditEventsJSONL([]byte(""))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("len = %d, want 0", len(events))
	}
}

func TestParseAuditEventsJSONL_SingleLine(t *testing.T) {
	data := []byte(`{"event_id":"evt-1","event_type":"artifact_sealed"}`)
	events, err := parseAuditEventsJSONL(data)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len = %d, want 1", len(events))
	}
	if got := stringField(events[0], "event_id"); got != "evt-1" {
		t.Fatalf("event_id = %q, want evt-1", got)
	}
}

func TestParseAuditEventsJSONL_MultiLineWithBlanks(t *testing.T) {
	data := []byte("{\"event_id\":\"a\"}\n\n  \n{\"event_id\":\"b\"}\n")
	events, err := parseAuditEventsJSONL(data)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len = %d, want 2 (blanks must be skipped)", len(events))
	}
	if stringField(events[0], "event_id") != "a" || stringField(events[1], "event_id") != "b" {
		t.Fatalf("ids = %v %v", stringField(events[0], "event_id"), stringField(events[1], "event_id"))
	}
}

func TestParseAuditEventsJSONL_MalformedJSONReportsLine(t *testing.T) {
	data := []byte("{\"event_id\":\"ok\"}\n{not json}\n")
	_, err := parseAuditEventsJSONL(data)
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("err = %q, want line 2 reference", err)
	}
}

// ── hashStoredEventLine ──────────────────────────────────────────────────────

func TestHashStoredEventLine_Deterministic(t *testing.T) {
	ev := mustEvent(t, "evt-1700000000000-aaa011", ZeroHash)
	h1, err := hashStoredEventLine(ev)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	h2, err := hashStoredEventLine(ev)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("non-deterministic: %s vs %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("hash length = %d, want 64", len(h1))
	}
}

func TestHashStoredEventLine_DiffersPerEvent(t *testing.T) {
	ev1 := mustEvent(t, "evt-1700000000000-aaa011", ZeroHash)
	ev2 := mustEvent(t, "evt-1700000000001-aaa111", ZeroHash)
	h1, _ := hashStoredEventLine(ev1)
	h2, _ := hashStoredEventLine(ev2)
	if h1 == h2 {
		t.Fatalf("hash collision on differing event_id")
	}
}

// ── computeCurrentEventHash ──────────────────────────────────────────────────

func TestComputeCurrentEventHash_IgnoresCurrentHashField(t *testing.T) {
	ev := makeEventNoHash("evt-1700000000000-aaa011", ZeroHash)
	h1, err := computeCurrentEventHash(ev)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	ev["current_event_hash"] = "deadbeef"
	h2, err := computeCurrentEventHash(ev)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("current_event_hash not ignored: %s vs %s", h1, h2)
	}
}

func TestComputeCurrentEventHash_DoesNotMutateInput(t *testing.T) {
	ev := makeEventNoHash("evt-x", ZeroHash)
	ev["current_event_hash"] = "preset"
	_, err := computeCurrentEventHash(ev)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ev["current_event_hash"] != "preset" {
		t.Fatalf("caller map mutated; current_event_hash = %v", ev["current_event_hash"])
	}
}

// ── ValidateAuditChain ──────────────────────────────────────────────────────

func TestValidateAuditChain_Empty(t *testing.T) {
	res := ValidateAuditChain(nil)
	if !res.Valid {
		t.Fatalf("empty chain not valid: %+v", res)
	}
	if res.BrokenAtIndex != -1 {
		t.Fatalf("BrokenAtIndex = %d, want -1", res.BrokenAtIndex)
	}
}

func TestValidateAuditChain_SingleValid(t *testing.T) {
	events := mustChain(t, 1)
	res := ValidateAuditChain(events)
	if !res.Valid {
		t.Fatalf("single-event chain invalid: %+v", res)
	}
}

func TestValidateAuditChain_FiveValid(t *testing.T) {
	events := mustChain(t, 5)
	res := ValidateAuditChain(events)
	if !res.Valid {
		t.Fatalf("5-event chain invalid: %+v", res)
	}
}

func TestValidateAuditChain_BrokenPrevHashAtFirst(t *testing.T) {
	events := mustChain(t, 3)
	events[0]["previous_event_hash"] = strings.Repeat("a", 64)
	cur, err := computeCurrentEventHash(events[0])
	if err != nil {
		t.Fatalf("recompute current: %v", err)
	}
	events[0]["current_event_hash"] = cur

	res := ValidateAuditChain(events)
	if res.Valid {
		t.Fatalf("expected invalid")
	}
	if res.BrokenAtIndex != 0 {
		t.Fatalf("BrokenAtIndex = %d, want 0", res.BrokenAtIndex)
	}
	if !strings.Contains(res.Error, "previous_event_hash") {
		t.Fatalf("error %q does not mention previous_event_hash", res.Error)
	}
}

func TestValidateAuditChain_BrokenPrevHashAtSecond(t *testing.T) {
	events := mustChain(t, 3)
	events[1]["previous_event_hash"] = strings.Repeat("b", 64)
	cur, err := computeCurrentEventHash(events[1])
	if err != nil {
		t.Fatalf("recompute current: %v", err)
	}
	events[1]["current_event_hash"] = cur

	res := ValidateAuditChain(events)
	if res.Valid {
		t.Fatalf("expected invalid")
	}
	if res.BrokenAtIndex != 1 {
		t.Fatalf("BrokenAtIndex = %d, want 1", res.BrokenAtIndex)
	}
	if res.BrokenAtEventID == "" {
		t.Fatalf("BrokenAtEventID is empty")
	}
}

func TestValidateAuditChain_BrokenCurrentHash(t *testing.T) {
	events := mustChain(t, 2)
	events[1]["current_event_hash"] = strings.Repeat("c", 64)

	res := ValidateAuditChain(events)
	if res.Valid {
		t.Fatalf("expected invalid")
	}
	if res.BrokenAtIndex != 1 {
		t.Fatalf("BrokenAtIndex = %d, want 1", res.BrokenAtIndex)
	}
	if !strings.Contains(res.Error, "current_event_hash") {
		t.Fatalf("error %q does not mention current_event_hash", res.Error)
	}
}

func TestValidateAuditChain_ErrorContainsHashExcerpts(t *testing.T) {
	events := mustChain(t, 1)
	events[0]["previous_event_hash"] = strings.Repeat("a", 64)
	cur, _ := computeCurrentEventHash(events[0])
	events[0]["current_event_hash"] = cur

	res := ValidateAuditChain(events)
	if !strings.Contains(res.Error, "00000000") {
		t.Fatalf("expected ZeroHash excerpt in error: %q", res.Error)
	}
	if !strings.Contains(res.Error, "aaaaaaaa") {
		t.Fatalf("expected tampered-prev excerpt in error: %q", res.Error)
	}
}

// ── hashExcerpt + stringField edge cases ────────────────────────────────────

func TestHashExcerpt_ShortInput(t *testing.T) {
	if got := hashExcerpt("abc"); got != "abc" {
		t.Fatalf("hashExcerpt(abc) = %q, want abc", got)
	}
	if got := hashExcerpt(""); got != "" {
		t.Fatalf("hashExcerpt(empty) = %q, want empty", got)
	}
}

func TestStringField_MissingOrWrongType(t *testing.T) {
	ev := AuditEventMap{"event_id": "evt-1", "count": 42}
	if got := stringField(ev, "event_id"); got != "evt-1" {
		t.Fatalf("string key: got %q", got)
	}
	if got := stringField(ev, "missing"); got != "" {
		t.Fatalf("missing key: got %q, want empty", got)
	}
	if got := stringField(ev, "count"); got != "" {
		t.Fatalf("non-string value: got %q, want empty", got)
	}
}
