// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

// reader.go — Bundle-Spec v1.0 §5 ZIP-Reader-Adapter.
//
// A v1 bundle on disk is the directory layout described in §5. When
// transported as a ZIP, the entries are flattened with a single root
// directory whose name MUST equal manifest.bundle_id (§5 rule 3).
//
// This adapter handles only the container layer: open, list, presence
// check, extract bytes. Manifest / signature / artifact verification is
// the job of verify.go.
//
// Stdlib-only: archive/zip, bytes, io.

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"
)

// Canonical entry-name constants (relative to the bundle root directory).
const (
	EntryManifestJSON    = "manifest.json"
	EntryManifestSHA256  = "manifest.json.sha256"
	EntryManifestSig     = "manifest.sig"
	EntryManifestTSR     = "manifest.tsr"
	EntryVerifyTxt       = "VERIFY.txt"
	EntryAuditEventsJSON = "audit/events.jsonl"
	EntryMetaSigningKey  = "meta/signing_key.pub.pem"

	DirArtifacts = "artifacts/"
	DirDerived   = "derived/"
	DirReports   = "reports/"
)

// requiredEntries are the §5 REQUIRED entries every bundle MUST contain.
// (`manifest.tsr` is OPTIONAL per §5.)
var requiredEntries = []string{
	EntryManifestJSON,
	EntryManifestSHA256,
	EntryManifestSig,
	EntryVerifyTxt,
	EntryAuditEventsJSON,
	EntryMetaSigningKey,
}

// Reader is an opened bundle ZIP. The underlying handle must be released
// by calling Close.
type Reader struct {
	rc      *zip.ReadCloser
	path    string
	root    string   // resolved root directory name (matches manifest.bundle_id)
	entries []string // file entries RELATIVE to root (directories excluded)
}

// Open reads the ZIP at path and resolves the bundle root directory.
//
// Returns an error if the path is unreadable, the file is not a valid ZIP,
// or the entries do not share a single root directory per §5.
func Open(p string) (*Reader, error) {
	rc, err := zip.OpenReader(p)
	if err != nil {
		return nil, fmt.Errorf("open bundle %q: %w", p, err)
	}
	root, err := resolveRoot(rc.File)
	if err != nil {
		rc.Close()
		return nil, fmt.Errorf("open bundle %q: %w", p, err)
	}
	r := &Reader{rc: rc, path: p, root: root}
	for _, f := range rc.File {
		if !strings.HasPrefix(f.Name, root+"/") {
			continue
		}
		name := strings.TrimPrefix(f.Name, root+"/")
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		r.entries = append(r.entries, name)
	}
	return r, nil
}

// Close releases the underlying ZIP handle. Safe to call multiple times.
func (r *Reader) Close() error {
	if r == nil || r.rc == nil {
		return nil
	}
	err := r.rc.Close()
	r.rc = nil
	return err
}

// Path returns the filesystem path the bundle was opened from.
func (r *Reader) Path() string { return r.path }

// RootDir returns the resolved bundle root directory name. Per §5 this
// MUST equal manifest.bundle_id; the verifier checks the equality.
func (r *Reader) RootDir() string { return r.root }

// Entries returns all file entries in the bundle, relative to the root
// directory, in ZIP-order. Directory entries are excluded.
func (r *Reader) Entries() []string {
	out := make([]string, len(r.entries))
	copy(out, r.entries)
	return out
}

// HasEntry returns true iff a file entry with the given root-relative
// name exists.
func (r *Reader) HasEntry(name string) bool {
	for _, e := range r.entries {
		if e == name {
			return true
		}
	}
	return false
}

// MissingRequired returns the §5 REQUIRED entry names that are not present.
func (r *Reader) MissingRequired() []string {
	var missing []string
	for _, name := range requiredEntries {
		if !r.HasEntry(name) {
			missing = append(missing, name)
		}
	}
	return missing
}

// ReadEntry returns the bytes of the root-relative entry. Returns an
// error if the entry is not present or cannot be read.
func (r *Reader) ReadEntry(name string) ([]byte, error) {
	full := r.root + "/" + name
	for _, f := range r.rc.File {
		if f.Name == full {
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
	return nil, fmt.Errorf("entry %q not found in bundle", name)
}

// EntriesUnder returns root-relative file entries whose name starts with
// the given prefix (which MUST end with "/"). Directory entries are
// excluded.
func (r *Reader) EntriesUnder(prefix string) []string {
	var out []string
	for _, e := range r.entries {
		if strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return out
}

// resolveRoot scans every ZIP entry and returns the single top-level
// directory name. Bundle-Spec §5 requires all entries to live under one
// root directory equal to manifest.bundle_id.
func resolveRoot(files []*zip.File) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("bundle ZIP is empty")
	}
	roots := make(map[string]struct{}, 1)
	for _, f := range files {
		clean := path.Clean(f.Name)
		if clean == "." || clean == "/" {
			continue
		}
		if strings.HasPrefix(clean, "/") {
			return "", fmt.Errorf("absolute path inside bundle: %q", f.Name)
		}
		if strings.HasPrefix(clean, "..") || strings.Contains(clean, "/../") {
			return "", fmt.Errorf("parent-traversal path inside bundle: %q", f.Name)
		}
		parts := strings.SplitN(clean, "/", 2)
		roots[parts[0]] = struct{}{}
	}
	if len(roots) != 1 {
		names := make([]string, 0, len(roots))
		for k := range roots {
			names = append(names, k)
		}
		return "", fmt.Errorf("bundle ZIP must have exactly one root directory, found %d: %v", len(roots), names)
	}
	for k := range roots {
		return k, nil
	}
	return "", fmt.Errorf("unreachable")
}
