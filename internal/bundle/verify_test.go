// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── Golden bundle factory ────────────────────────────────────────────────────
//
// Builds a fully-signed §5 bundle on disk using the zero-seed Ed25519 key
// (cross-language byte-exact reference, see signing_test.go).

type goldenSpec struct {
	bundleID       string
	packageClass   string // default "evidence"
	artifactBytes  []byte // default "hello world"
	artifactPath   string // default artifacts/<id>.txt
	policyState    string // default "export_allowed"
	skipArtifact   bool   // omit the artifact file entry
	skipMetaPubKey bool   // omit meta/signing_key.pub.pem
	skipManifest   bool   // omit manifest.json
	skipSig        bool   // omit manifest.sig
	tamperManifest bool   // mutate manifest after signing
	tamperPubKey   bool   // write a different PEM at meta/signing_key.pub.pem
	extraFile      string // optional undeclared file under artifacts/ or derived/
}

func buildGoldenBundle(t *testing.T, spec goldenSpec) string {
	t.Helper()

	if spec.bundleID == "" {
		spec.bundleID = "bnd-1745000000000-xk9m2p"
	}
	if spec.packageClass == "" {
		spec.packageClass = "evidence"
	}
	if spec.artifactBytes == nil {
		spec.artifactBytes = []byte("hello world")
	}
	if spec.artifactPath == "" {
		spec.artifactPath = "artifacts/art-1745000000000-abc123.txt"
	}
	if spec.policyState == "" {
		spec.policyState = "export_allowed"
	}

	seed := make([]byte, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	pemStr, err := SerializePublicKeyPEM(pub)
	if err != nil {
		t.Fatalf("SerializePublicKeyPEM: %v", err)
	}
	fp, err := ComputeSigningKeyFingerprint(pub)
	if err != nil {
		t.Fatalf("ComputeSigningKeyFingerprint: %v", err)
	}

	sum := sha256.Sum256(spec.artifactBytes)
	artHash := hex.EncodeToString(sum[:])

	manifest := &Manifest{
		SchemaVersion:         "1.0",
		BundleID:              spec.bundleID,
		PackageClass:          spec.packageClass,
		CreatedAt:             "2026-04-18T10:00:00.000Z",
		Product:               "CKNF",
		ProductVersion:        "1.1.0",
		InstallationID:        "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6",
		LicenseReference:      "TSOL-****-****-Z9K2",
		SigningKeyFingerprint: fp,
		HashAlgorithm:         "sha-256",
		SignatureAlgorithm:    "Ed25519",
		TimestampStatus:       "absent",
		ArtifactCount:         1,
		Artifacts: []map[string]any{
			{
				"artifact_id":       "art-1745000000000-abc123",
				"artifact_type":     "document",
				"stored_path":       spec.artifactPath,
				"original_filename": "evidence.txt",
				"mime_type":         "text/plain",
				"byte_size":         len(spec.artifactBytes),
				"sha256":            artHash,
				"created_at":        "2026-04-18T10:00:00.000Z",
				"origin":            "captured",
				"policy_state":      spec.policyState,
				"is_derived":        false,
			},
		},
	}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("manifest.Validate: %v", err)
	}

	manifestBytes, err := manifest.CanonicalJSON()
	if err != nil {
		t.Fatalf("manifest.CanonicalJSON: %v", err)
	}
	manifestHash, err := manifest.Hash()
	if err != nil {
		t.Fatalf("manifest.Hash: %v", err)
	}

	rawSig := ed25519.Sign(priv, []byte(manifestHash))
	sigB64 := base64.StdEncoding.EncodeToString(rawSig)

	sig := &ManifestSignature{
		SchemaVersion:      "1.0",
		BundleID:           spec.bundleID,
		InstallationID:     manifest.InstallationID,
		PublicKeyID:        fp,
		SignatureAlgorithm: "Ed25519",
		SignedData:         "manifest-sha256",
		ManifestHash:       manifestHash,
		Signature:          sigB64,
		PublicKeyPEM:       pemStr,
		SignedAt:           "2026-04-18T10:00:00.123Z",
	}
	if err := sig.Validate(); err != nil {
		t.Fatalf("signature.Validate: %v", err)
	}
	sigBytes, err := sig.CanonicalJSON()
	if err != nil {
		t.Fatalf("signature.CanonicalJSON: %v", err)
	}

	if spec.tamperManifest {
		s := strings.Replace(string(manifestBytes), "xk9m2p", "xk9m2q", 1)
		manifestBytes = []byte(s)
	}

	root := spec.bundleID + "/"
	var entries []zipEntry
	if !spec.skipManifest {
		entries = append(entries, zipEntry{root + EntryManifestJSON, manifestBytes})
	}
	entries = append(entries, zipEntry{
		root + EntryManifestSHA256,
		[]byte(manifestHash + "  " + EntryManifestJSON + "\n"),
	})
	if !spec.skipSig {
		entries = append(entries, zipEntry{root + EntryManifestSig, sigBytes})
	}
	entries = append(entries,
		zipEntry{root + EntryVerifyTxt, []byte("To verify this bundle, run: verifier verify bundle <path>\n")},
		zipEntry{root + EntryAuditEventsJSON, []byte("")},
	)
	if !spec.skipMetaPubKey {
		metaPEM := pemStr
		if spec.tamperPubKey {
			altSeed := make([]byte, ed25519.SeedSize)
			altSeed[0] = 0x01
			altPriv := ed25519.NewKeyFromSeed(altSeed)
			altPub := altPriv.Public().(ed25519.PublicKey)
			alt, err := SerializePublicKeyPEM(altPub)
			if err != nil {
				t.Fatalf("alt SerializePublicKeyPEM: %v", err)
			}
			metaPEM = alt
		}
		entries = append(entries, zipEntry{root + EntryMetaSigningKey, []byte(metaPEM)})
	}
	if !spec.skipArtifact {
		entries = append(entries, zipEntry{root + spec.artifactPath, spec.artifactBytes})
	}
	if spec.extraFile != "" {
		entries = append(entries, zipEntry{root + spec.extraFile, []byte("undeclared")})
	}

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

// ── Verdict happy path ───────────────────────────────────────────────────────

func TestVerifyBundleHappyPathReturnsValid(t *testing.T) {
	path := buildGoldenBundle(t, goldenSpec{})

	v, err := VerifyBundle(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if v.ResultCode != CodeValid {
		t.Errorf("ResultCode = %q, want %q (verdict=%s, summary=%s)",
			v.ResultCode, CodeValid, v.OverallResult, v.Summary)
	}
	if v.OverallResult != "PASS" {
		t.Errorf("OverallResult = %q, want PASS", v.OverallResult)
	}
	if v.BundleID != "bnd-1745000000000-xk9m2p" {
		t.Errorf("BundleID = %q", v.BundleID)
	}
	if v.PackageClass != "evidence" {
		t.Errorf("PackageClass = %q", v.PackageClass)
	}
	if v.ArtifactCount != 1 {
		t.Errorf("ArtifactCount = %d, want 1", v.ArtifactCount)
	}
	for _, c := range v.Checks {
		if c.Result == "FAIL" {
			t.Errorf("unexpected FAIL on check %q: %s", c.Name, c.Error)
		}
	}
}

func TestVerifyBundleChecksHaveStableNames(t *testing.T) {
	path := buildGoldenBundle(t, goldenSpec{})
	v, err := VerifyBundle(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	wantNames := []string{
		checkManifestPresent,
		checkSignaturePresent,
		checkSignatureValid,
		checkManifestHashMatches,
		checkArtifactsPresent,
		checkArtifactHashes,
		checkNoUndeclaredFiles,
		checkAuditChain,
		checkTimestamp,
		checkPolicyCompliance,
	}
	if len(v.Checks) != len(wantNames) {
		t.Fatalf("len(Checks) = %d, want %d", len(v.Checks), len(wantNames))
	}
	for i, c := range v.Checks {
		if c.Name != wantNames[i] {
			t.Errorf("Checks[%d].Name = %q, want %q", i, c.Name, wantNames[i])
		}
	}
}

// ── §12.3 failure-code coverage ──────────────────────────────────────────────

func TestVerifyBundleManifestMissingProducesManifestMissing(t *testing.T) {
	path := buildGoldenBundle(t, goldenSpec{skipManifest: true})
	v, err := VerifyBundle(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if v.ResultCode != CodeManifestMissing {
		t.Errorf("ResultCode = %q, want %q", v.ResultCode, CodeManifestMissing)
	}
	if v.OverallResult != "FAIL" {
		t.Errorf("OverallResult = %q, want FAIL", v.OverallResult)
	}
}

func TestVerifyBundleSigMissingProducesSignatureMissing(t *testing.T) {
	path := buildGoldenBundle(t, goldenSpec{skipSig: true})
	v, err := VerifyBundle(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if v.ResultCode != CodeSignatureMissing {
		t.Errorf("ResultCode = %q, want %q", v.ResultCode, CodeSignatureMissing)
	}
}

func TestVerifyBundleTamperedManifestProducesTamperedOrMissing(t *testing.T) {
	path := buildGoldenBundle(t, goldenSpec{tamperManifest: true})
	v, err := VerifyBundle(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	// Tampering the bundle_id changes the canonical hash AND breaks the
	// root-dir match. Either failure mode is acceptable; both are correct
	// detections of "what was signed ≠ what's on disk".
	if v.ResultCode != CodeManifestMissing && v.ResultCode != CodeManifestTampered {
		t.Errorf("ResultCode = %q, want MANIFEST_MISSING or MANIFEST_TAMPERED",
			v.ResultCode)
	}
}

func TestVerifyBundleTamperedPubKeyProducesInvalidSignature(t *testing.T) {
	path := buildGoldenBundle(t, goldenSpec{tamperPubKey: true})
	v, err := VerifyBundle(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if v.ResultCode != CodeInvalidSignature {
		t.Errorf("ResultCode = %q, want %q", v.ResultCode, CodeInvalidSignature)
	}
}

func TestVerifyBundleMissingMetaPubKeyProducesInvalidSignature(t *testing.T) {
	path := buildGoldenBundle(t, goldenSpec{skipMetaPubKey: true})
	v, err := VerifyBundle(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if v.ResultCode != CodeInvalidSignature {
		t.Errorf("ResultCode = %q, want %q", v.ResultCode, CodeInvalidSignature)
	}
}

func TestVerifyBundleMissingArtifactProducesFileMissing(t *testing.T) {
	path := buildGoldenBundle(t, goldenSpec{skipArtifact: true})
	v, err := VerifyBundle(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if v.ResultCode != CodeFileMissing {
		t.Errorf("ResultCode = %q, want %q", v.ResultCode, CodeFileMissing)
	}
}

func TestVerifyBundleMutatedArtifactProducesHashMismatch(t *testing.T) {
	path := buildGoldenBundle(t, goldenSpec{})
	mutated := rewriteEntry(t, path,
		"bnd-1745000000000-xk9m2p/artifacts/art-1745000000000-abc123.txt",
		[]byte("HELLO WORLD"))
	v, err := VerifyBundle(mutated, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if v.ResultCode != CodeHashMismatch {
		t.Errorf("ResultCode = %q, want %q", v.ResultCode, CodeHashMismatch)
	}
}

func TestVerifyBundleUndeclaredFileProducesFileAdded(t *testing.T) {
	path := buildGoldenBundle(t, goldenSpec{extraFile: "artifacts/sneaky.txt"})
	v, err := VerifyBundle(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if v.ResultCode != CodeFileAdded {
		t.Errorf("ResultCode = %q, want %q", v.ResultCode, CodeFileAdded)
	}
}

func TestVerifyBundleInternalOnlyInDisclosureProducesPolicyViolation(t *testing.T) {
	path := buildGoldenBundle(t, goldenSpec{
		packageClass: "disclosure",
		policyState:  "internal_only",
	})
	v, err := VerifyBundle(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if v.ResultCode != CodePolicyViolation {
		t.Errorf("ResultCode = %q, want %q", v.ResultCode, CodePolicyViolation)
	}
}

// ── §12.3 priority introspection ─────────────────────────────────────────────

func TestPriorityOfOrdering(t *testing.T) {
	if PriorityOf(CodeSchemaUnsupported) <= PriorityOf(CodeManifestMissing) {
		t.Errorf("SCHEMA_UNSUPPORTED must dominate MANIFEST_MISSING")
	}
	if PriorityOf(CodeManifestMissing) <= PriorityOf(CodeSignatureMissing) {
		t.Errorf("MANIFEST_MISSING must dominate SIGNATURE_MISSING")
	}
	if PriorityOf(CodeInvalidSignature) <= PriorityOf(CodeManifestTampered) {
		t.Errorf("INVALID_SIGNATURE must dominate MANIFEST_TAMPERED")
	}
	if PriorityOf(CodeValid) != 0 {
		t.Errorf("VALID priority = %d, want 0", PriorityOf(CodeValid))
	}
}

// ── Error path: bundle not openable ──────────────────────────────────────────

func TestVerifyBundleUnreadableReturnsVerdictNotError(t *testing.T) {
	v, err := VerifyBundle("/nonexistent/path/to/missing.zip", VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBundle returned error %v; expected Verdict carrying the failure", err)
	}
	if v.ResultCode != CodeManifestMissing {
		t.Errorf("ResultCode = %q, want %q", v.ResultCode, CodeManifestMissing)
	}
	if v.OverallResult != "FAIL" {
		t.Errorf("OverallResult = %q, want FAIL", v.OverallResult)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// rewriteEntry copies srcPath to a new temp ZIP, replacing the bytes of
// the named entry with newBody. All other entries are preserved verbatim.
func rewriteEntry(t *testing.T, srcPath, entryName string, newBody []byte) string {
	t.Helper()
	rc, err := zip.OpenReader(srcPath)
	if err != nil {
		t.Fatalf("open src zip: %v", err)
	}
	defer rc.Close()

	dir := t.TempDir()
	dstPath := filepath.Join(dir, "mutated.zip")
	f, err := os.Create(dstPath)
	if err != nil {
		t.Fatalf("create dst zip: %v", err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, src := range rc.File {
		w, err := zw.Create(src.Name)
		if err != nil {
			t.Fatalf("create entry %q: %v", src.Name, err)
		}
		var body []byte
		if src.Name == entryName {
			body = newBody
		} else {
			r, err := src.Open()
			if err != nil {
				t.Fatalf("open src entry %q: %v", src.Name, err)
			}
			body, err = io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatalf("read src entry %q: %v", src.Name, err)
			}
		}
		if _, err := w.Write(body); err != nil {
			t.Fatalf("write entry %q: %v", src.Name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close dst zip writer: %v", err)
	}
	return dstPath
}
