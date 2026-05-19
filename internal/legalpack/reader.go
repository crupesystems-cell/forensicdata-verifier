// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package legalpack reads and validates the structure of CKNF Legal-Pack
// ZIP containers.
//
// A v1 CKNF Legal-Pack is a 10-entry ZIP produced by `legal_pack.build_legal_pack`
// (see CKNF source `src/cknf/legal_pack.py`). The required entries are:
//
//	original.{m4a|wav}      — audio recording (m4a on macOS, wav on Windows)
//	sha256_report.txt       — SHA-256 + chain-hash + TSA-status text report
//	transcript_raw.txt      — STT-original transcript
//	transcript_clean.txt    — operator-edited transcript
//	transcript.docx         — operator-edited transcript as Word
//	transcript_history.txt  — version history of edits
//	chain_of_custody.pdf    — forensic chain-of-custody PDF
//	audit.jsonl             — JSONL audit-event chain
//	verification_qr.png     — QR code carrying chain_hash payload
//	cover.pdf               — title page with metadata
//
// This package handles ONLY the container layer: open, list, presence-check,
// extract-bytes. Inner-format parsing (sha256_report.txt structure, QR
// payload, audit chain integrity, TSR token, NTP clock-validation hash) is
// the job of the per-entry sub-packages introduced in Stages B.2 — C.
package legalpack

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
)

// Canonical entry-name constants. These must stay in lock-step with the
// CKNF Python source (`src/cknf/legal_pack.py:build_legal_pack`). If CKNF
// renames or adds an entry, this list and the parsers in B.2–C must be
// updated in the same commit.
const (
	EntryAudioMac        = "original.m4a"
	EntryAudioWin        = "original.wav"
	EntrySha256Report    = "sha256_report.txt"
	EntryTranscriptRaw   = "transcript_raw.txt"
	EntryTranscriptClean = "transcript_clean.txt"
	EntryTranscriptDocx  = "transcript.docx"
	EntryTranscriptHist  = "transcript_history.txt"
	EntryChainOfCustody  = "chain_of_custody.pdf"
	EntryAuditJsonl      = "audit.jsonl"
	EntryVerificationQR  = "verification_qr.png"
	EntryCover           = "cover.pdf"
)

// fixedRequiredEntries are the 9 entries whose names never vary.
// The audio entry (slot 10) is special: it is either m4a OR wav, never both.
var fixedRequiredEntries = []string{
	EntrySha256Report,
	EntryTranscriptRaw,
	EntryTranscriptClean,
	EntryTranscriptDocx,
	EntryTranscriptHist,
	EntryChainOfCustody,
	EntryAuditJsonl,
	EntryVerificationQR,
	EntryCover,
}

// Pack is an opened CKNF Legal-Pack. The underlying ZIP handle must be
// released by calling Close.
type Pack struct {
	rc      *zip.ReadCloser
	path    string
	entries []string // entry names in ZIP-order
	audio   string   // resolved audio entry name (m4a or wav), "" if neither present
}

// Open reads the ZIP at path and returns a *Pack. The returned Pack must
// be closed by the caller. Returns an error if the path is unreadable or
// not a valid ZIP. Does NOT error on missing required entries — that is
// the caller's responsibility (use MissingEntries / IsValidStructure).
func Open(path string) (*Pack, error) {
	rc, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open legal-pack %q: %w", path, err)
	}
	p := &Pack{rc: rc, path: path}
	for _, f := range rc.File {
		p.entries = append(p.entries, f.Name)
		switch f.Name {
		case EntryAudioMac, EntryAudioWin:
			p.audio = f.Name
		}
	}
	return p, nil
}

// Close releases the underlying ZIP handle. Safe to call multiple times.
func (p *Pack) Close() error {
	if p == nil || p.rc == nil {
		return nil
	}
	err := p.rc.Close()
	p.rc = nil
	return err
}

// Path returns the filesystem path the pack was opened from.
func (p *Pack) Path() string { return p.path }

// Entries returns the entry names in ZIP-order.
func (p *Pack) Entries() []string {
	out := make([]string, len(p.entries))
	copy(out, p.entries)
	return out
}

// AudioEntry returns the resolved audio-entry name ("original.m4a" or
// "original.wav") or "" if neither variant is present.
func (p *Pack) AudioEntry() string { return p.audio }

// RequiredEntries returns the canonical 10-slot description of a v1
// Legal-Pack. The first slot is the audio-variant slot (rendered as
// "original.m4a OR original.wav"); the remaining 9 are fixed names.
func RequiredEntries() []string {
	out := make([]string, 0, 10)
	out = append(out, EntryAudioMac+" OR "+EntryAudioWin)
	out = append(out, fixedRequiredEntries...)
	return out
}

// MissingEntries returns the list of canonical entries that are not
// present in the pack. The audio slot is reported as the m4a variant when
// neither audio file is present (since macOS is the canonical recording
// platform; a Win-only pack would still list m4a here, which the operator
// can interpret as "expected one of m4a/wav").
func (p *Pack) MissingEntries() []string {
	have := make(map[string]bool, len(p.entries))
	for _, e := range p.entries {
		have[e] = true
	}
	var missing []string
	if !have[EntryAudioMac] && !have[EntryAudioWin] {
		// Single audio slot — report both names so the caller knows it's
		// a slot-level miss, not a single-file miss.
		missing = append(missing, EntryAudioMac+" or "+EntryAudioWin)
	}
	for _, name := range fixedRequiredEntries {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

// IsValidStructure returns true iff the pack has all 10 required entry slots
// filled. Does NOT validate entry content — that is the job of later stages.
func (p *Pack) IsValidStructure() bool {
	return len(p.MissingEntries()) == 0
}

// ReadEntry returns the bytes of the named entry. Returns an error if the
// entry is not present in the ZIP or cannot be read.
func (p *Pack) ReadEntry(name string) ([]byte, error) {
	for _, f := range p.rc.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("open entry %q: %w", name, err)
			}
			defer rc.Close()
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, rc); err != nil {
				return nil, fmt.Errorf("read entry %q: %w", name, err)
			}
			return buf.Bytes(), nil
		}
	}
	return nil, fmt.Errorf("entry %q not found in legal-pack", name)
}
