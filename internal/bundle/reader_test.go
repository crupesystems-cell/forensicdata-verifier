// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// zipEntry is one (name, body) tuple used to build synthetic bundle ZIPs.
type zipEntry struct {
	name string
	body []byte
}

// writeBundleZip writes a ZIP to a temp file and returns its path.
func writeBundleZip(t *testing.T, entries []zipEntry) string {
	t.Helper()
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "bundle.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("create entry %q: %v", e.name, err)
		}
		if _, err := w.Write(e.body); err != nil {
			t.Fatalf("write entry %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return zipPath
}

// minimalBundle returns a synthetic 6-entry bundle layout suitable for
// reader-level tests (content is not validated here — only structure).
func minimalBundle(rootID string) []zipEntry {
	return []zipEntry{
		{rootID + "/" + EntryManifestJSON, []byte(`{}`)},
		{rootID + "/" + EntryManifestSHA256, []byte("")},
		{rootID + "/" + EntryManifestSig, []byte(`{}`)},
		{rootID + "/" + EntryVerifyTxt, []byte("verify")},
		{rootID + "/" + EntryAuditEventsJSON, []byte("")},
		{rootID + "/" + EntryMetaSigningKey, []byte("pem")},
	}
}

func TestOpenResolvesRootDirectory(t *testing.T) {
	root := "bnd-1745000000000-xk9m2p"
	zipPath := writeBundleZip(t, minimalBundle(root))

	r, err := Open(zipPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	if got := r.RootDir(); got != root {
		t.Errorf("RootDir = %q, want %q", got, root)
	}
	if got := r.Path(); got != zipPath {
		t.Errorf("Path = %q, want %q", got, zipPath)
	}
}

func TestOpenRejectsZeroEntries(t *testing.T) {
	zipPath := writeBundleZip(t, nil)
	if _, err := Open(zipPath); err == nil {
		t.Fatal("expected error for empty bundle")
	}
}

func TestOpenRejectsMultipleRoots(t *testing.T) {
	zipPath := writeBundleZip(t, []zipEntry{
		{"bnd-A/" + EntryManifestJSON, []byte(`{}`)},
		{"bnd-B/" + EntryManifestJSON, []byte(`{}`)},
	})
	if _, err := Open(zipPath); err == nil {
		t.Fatal("expected error for multi-root bundle")
	}
}

func TestOpenRejectsAbsolutePath(t *testing.T) {
	zipPath := writeBundleZip(t, []zipEntry{
		{"/" + EntryManifestJSON, []byte(`{}`)},
	})
	if _, err := Open(zipPath); err == nil {
		t.Fatal("expected error for absolute-path entry")
	}
}

func TestOpenRejectsParentTraversal(t *testing.T) {
	zipPath := writeBundleZip(t, []zipEntry{
		{"../escape/" + EntryManifestJSON, []byte(`{}`)},
	})
	if _, err := Open(zipPath); err == nil {
		t.Fatal("expected error for parent-traversal entry")
	}
}

func TestOpenRejectsUnreadableFile(t *testing.T) {
	if _, err := Open("/nonexistent/path/to/bundle.zip"); err == nil {
		t.Fatal("expected error opening nonexistent file")
	}
}

func TestEntriesReturnsRootRelativeNames(t *testing.T) {
	root := "bnd-1"
	zipPath := writeBundleZip(t, minimalBundle(root))

	r, err := Open(zipPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	got := r.Entries()
	sort.Strings(got)
	want := []string{
		EntryAuditEventsJSON,
		EntryManifestJSON,
		EntryManifestSHA256,
		EntryManifestSig,
		EntryMetaSigningKey,
		EntryVerifyTxt,
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Entries = %v, want %v", got, want)
	}
}

func TestHasEntryReturnsPresence(t *testing.T) {
	zipPath := writeBundleZip(t, minimalBundle("bnd-1"))

	r, err := Open(zipPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	if !r.HasEntry(EntryManifestJSON) {
		t.Error("HasEntry(manifest.json) = false, want true")
	}
	if r.HasEntry("missing.txt") {
		t.Error("HasEntry(missing.txt) = true, want false")
	}
	if r.HasEntry(EntryManifestTSR) {
		t.Error("HasEntry(manifest.tsr) = true on minimal bundle, want false")
	}
}

func TestMissingRequiredReturnsAbsentEntries(t *testing.T) {
	zipPath := writeBundleZip(t, []zipEntry{
		{"bnd-1/" + EntryManifestJSON, []byte(`{}`)},
		{"bnd-1/" + EntryManifestSig, []byte(`{}`)},
	})
	r, err := Open(zipPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	missing := r.MissingRequired()
	wantMissing := map[string]bool{
		EntryManifestSHA256:  true,
		EntryVerifyTxt:       true,
		EntryAuditEventsJSON: true,
		EntryMetaSigningKey:  true,
	}
	if len(missing) != len(wantMissing) {
		t.Fatalf("MissingRequired len = %d, want %d (got %v)", len(missing), len(wantMissing), missing)
	}
	for _, m := range missing {
		if !wantMissing[m] {
			t.Errorf("unexpected missing entry %q", m)
		}
	}
}

func TestMissingRequiredEmptyOnCompleteBundle(t *testing.T) {
	zipPath := writeBundleZip(t, minimalBundle("bnd-1"))

	r, err := Open(zipPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	if missing := r.MissingRequired(); len(missing) != 0 {
		t.Errorf("MissingRequired = %v, want []", missing)
	}
}

func TestReadEntryReturnsBytes(t *testing.T) {
	want := []byte(`{"hello":"world"}`)
	zipPath := writeBundleZip(t, []zipEntry{
		{"bnd-1/" + EntryManifestJSON, want},
		{"bnd-1/" + EntryManifestSHA256, []byte("hash")},
		{"bnd-1/" + EntryManifestSig, []byte(`{}`)},
		{"bnd-1/" + EntryVerifyTxt, []byte("verify")},
		{"bnd-1/" + EntryAuditEventsJSON, []byte("")},
		{"bnd-1/" + EntryMetaSigningKey, []byte("pem")},
	})

	r, err := Open(zipPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	got, err := r.ReadEntry(EntryManifestJSON)
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ReadEntry bytes = %q, want %q", got, want)
	}
}

func TestReadEntryReturnsErrorOnMissing(t *testing.T) {
	zipPath := writeBundleZip(t, minimalBundle("bnd-1"))

	r, err := Open(zipPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	if _, err := r.ReadEntry("does/not/exist.bin"); err == nil {
		t.Error("ReadEntry for missing entry: expected error, got nil")
	}
}

func TestEntriesUnderReturnsPrefixMatches(t *testing.T) {
	root := "bnd-1"
	zipPath := writeBundleZip(t, append(minimalBundle(root),
		zipEntry{root + "/" + DirArtifacts + "art-1.jpg", []byte("jpg-bytes")},
		zipEntry{root + "/" + DirArtifacts + "art-2.pdf", []byte("pdf-bytes")},
		zipEntry{root + "/" + DirDerived + "art-3.jpg", []byte("redacted")},
	))

	r, err := Open(zipPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	artifacts := r.EntriesUnder(DirArtifacts)
	sort.Strings(artifacts)
	wantArtifacts := []string{"artifacts/art-1.jpg", "artifacts/art-2.pdf"}
	if !reflect.DeepEqual(artifacts, wantArtifacts) {
		t.Errorf("EntriesUnder(artifacts/) = %v, want %v", artifacts, wantArtifacts)
	}

	derived := r.EntriesUnder(DirDerived)
	wantDerived := []string{"derived/art-3.jpg"}
	if !reflect.DeepEqual(derived, wantDerived) {
		t.Errorf("EntriesUnder(derived/) = %v, want %v", derived, wantDerived)
	}

	if got := r.EntriesUnder("nope/"); len(got) != 0 {
		t.Errorf("EntriesUnder(nope/) = %v, want []", got)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	zipPath := writeBundleZip(t, minimalBundle("bnd-1"))
	r, err := Open(zipPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
