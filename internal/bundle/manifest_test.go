// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"strings"
	"testing"
)

// validManifestJSON — exact canonical JSON for a minimal Bundle-Spec §6.4
// manifest, locked against Python
// test_manifest.test_canonical_manifest_json_byte_exact_for_minimal_manifest.
const validManifestJSON = `{"artifact_count":0,"artifacts":[],"bundle_id":"bnd-1745000000000-xk9m2p","created_at":"2026-05-21T10:00:00.000Z","hash_algorithm":"sha-256","installation_id":"a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6","license_reference":"TSOL-****-****-Z9K2","package_class":"evidence","product":"CKNF","product_version":"2.3.0","schema_version":"1.0","signature_algorithm":"Ed25519","signing_key_fingerprint":"f1e2d3c4b5a697880123456789abcdef","timestamp_status":"present"}`

// ── Round-trip via ParseManifest ─────────────────────────────────────────────

func TestParseManifest_ValidMinimal(t *testing.T) {
	m, err := ParseManifest([]byte(validManifestJSON))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.BundleID != "bnd-1745000000000-xk9m2p" {
		t.Errorf("bundle_id = %q", m.BundleID)
	}
	if m.PackageClass != "evidence" {
		t.Errorf("package_class = %q", m.PackageClass)
	}
	if m.ArtifactCount != 0 {
		t.Errorf("artifact_count = %d", m.ArtifactCount)
	}
	if m.TimestampTokenRef != nil {
		t.Errorf("timestamp_token_ref should be nil")
	}
}

func TestParseManifest_RoundTripCanonicalJSONByteExact(t *testing.T) {
	m, err := ParseManifest([]byte(validManifestJSON))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	canonical, err := m.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(canonical) != validManifestJSON {
		t.Fatalf(
			"byte mismatch:\n  got: %s\n want: %s",
			string(canonical), validManifestJSON,
		)
	}
}

func TestParseManifest_HashLockedValue(t *testing.T) {
	m, err := ParseManifest([]byte(validManifestJSON))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	got, err := m.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	expected, _ := SHA256Hex(m.ToMap())
	if got != expected {
		t.Fatalf("Hash() = %q, manual compute = %q", got, expected)
	}
	if len(got) != 64 {
		t.Fatalf("hash length %d, want 64", len(got))
	}
}

// ── Required-field / extra-key rejection ─────────────────────────────────────

func TestParseManifest_RejectsMissingRequiredKey(t *testing.T) {
	bad := strings.Replace(
		validManifestJSON,
		`"bundle_id":"bnd-1745000000000-xk9m2p",`,
		``,
		1,
	)
	_, err := ParseManifest([]byte(bad))
	if err == nil {
		t.Fatal("expected error for missing bundle_id")
	}
	if !strings.Contains(err.Error(), "missing required keys") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseManifest_RejectsExtraKey(t *testing.T) {
	bad := strings.Replace(
		validManifestJSON,
		`{"artifact_count":0,`,
		`{"artifact_count":0,"unknown_extra_field":"bad",`,
		1,
	)
	_, err := ParseManifest([]byte(bad))
	if err == nil {
		t.Fatal("expected error for extra key")
	}
	if !strings.Contains(err.Error(), "extra keys") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ── Field validators ─────────────────────────────────────────────────────────

func TestParseManifest_RejectsBadSchemaVersion(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"schema_version":"1.0"`, `"schema_version":"2.0"`, 1)
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("expected schema_version error, got: %v", err)
	}
}

func TestParseManifest_RejectsBadBundleID(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"bundle_id":"bnd-1745000000000-xk9m2p"`,
		`"bundle_id":"bundle_invalid"`, 1)
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "bundle_id") {
		t.Fatalf("expected bundle_id error, got: %v", err)
	}
}

func TestParseManifest_RejectsBadPackageClass(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"package_class":"evidence"`, `"package_class":"unknown"`, 1)
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "package_class") {
		t.Fatalf("expected package_class error, got: %v", err)
	}
}

func TestParseManifest_RejectsBadProduct(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"product":"CKNF"`, `"product":"NotACKNF"`, 1)
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "product") {
		t.Fatalf("expected product error, got: %v", err)
	}
}

func TestParseManifest_RejectsBadInstallationID(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"installation_id":"a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6"`,
		`"installation_id":"short"`, 1)
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "installation_id") {
		t.Fatalf("expected installation_id error, got: %v", err)
	}
}

func TestParseManifest_RejectsUppercaseInstallationID(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"installation_id":"a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6"`,
		`"installation_id":"A3F1B2C4D5E6F7A8B9C0D1E2F3A4B5C6"`, 1)
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "installation_id") {
		t.Fatalf("expected installation_id error, got: %v", err)
	}
}

func TestParseManifest_RejectsBadLicenseReference(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"license_reference":"TSOL-****-****-Z9K2"`,
		`"license_reference":"lowercase-****-****-z9k2"`, 1)
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "license_reference") {
		t.Fatalf("expected license_reference error, got: %v", err)
	}
}

func TestParseManifest_RejectsBadCreatedAt(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"created_at":"2026-05-21T10:00:00.000Z"`,
		`"created_at":"2026-05-21T10:00:00Z"`, 1) // missing ms
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "created_at") {
		t.Fatalf("expected created_at error, got: %v", err)
	}
}

func TestParseManifest_RejectsBadHashAlgorithm(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"hash_algorithm":"sha-256"`, `"hash_algorithm":"SHA-256"`, 1)
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "hash_algorithm") {
		t.Fatalf("expected hash_algorithm error, got: %v", err)
	}
}

func TestParseManifest_RejectsBadSignatureAlgorithm(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"signature_algorithm":"Ed25519"`, `"signature_algorithm":"RSA"`, 1)
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "signature_algorithm") {
		t.Fatalf("expected signature_algorithm error, got: %v", err)
	}
}

func TestParseManifest_RejectsBadTimestampStatus(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"timestamp_status":"present"`, `"timestamp_status":"yes"`, 1)
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "timestamp_status") {
		t.Fatalf("expected timestamp_status error, got: %v", err)
	}
}

func TestParseManifest_RejectsArtifactCountMismatch(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"artifact_count":0,"artifacts":[]`,
		`"artifact_count":1,"artifacts":[]`, 1)
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "artifact_count") {
		t.Fatalf("expected artifact_count error, got: %v", err)
	}
}

func TestParseManifest_AcceptsArtifactsWithMatchingCount(t *testing.T) {
	withArt := strings.Replace(validManifestJSON,
		`"artifact_count":0,"artifacts":[]`,
		`"artifact_count":1,"artifacts":[{"artifact_id":"art-x-aaaaaa"}]`, 1)
	m, err := ParseManifest([]byte(withArt))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.ArtifactCount != 1 {
		t.Errorf("artifact_count = %d, want 1", m.ArtifactCount)
	}
	if len(m.Artifacts) != 1 {
		t.Errorf("len(Artifacts) = %d, want 1", len(m.Artifacts))
	}
}

// ── Optional fields ──────────────────────────────────────────────────────────

func TestParseManifest_AcceptsOptionalTimestampTokenRef(t *testing.T) {
	withOpt := strings.Replace(validManifestJSON,
		`"timestamp_status":"present"`,
		`"timestamp_status":"present","timestamp_token_ref":"manifest.tsr"`, 1)
	m, err := ParseManifest([]byte(withOpt))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.TimestampTokenRef == nil || *m.TimestampTokenRef != "manifest.tsr" {
		t.Errorf("timestamp_token_ref not set correctly")
	}
}

func TestParseManifest_RejectsWrongTimestampTokenRef(t *testing.T) {
	bad := strings.Replace(validManifestJSON,
		`"timestamp_status":"present"`,
		`"timestamp_status":"present","timestamp_token_ref":"wrong.tsr"`, 1)
	_, err := ParseManifest([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "timestamp_token_ref") {
		t.Fatalf("expected timestamp_token_ref error, got: %v", err)
	}
}

func TestParseManifest_AcceptsOptionalCaseReferenceAndPolicy(t *testing.T) {
	withOpts := strings.Replace(validManifestJSON,
		`"timestamp_status":"present"`,
		`"case_reference":"C-42","policy_profile":"legal-v1","timestamp_status":"present"`, 1)
	m, err := ParseManifest([]byte(withOpts))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.CaseReference == nil || *m.CaseReference != "C-42" {
		t.Errorf("case_reference not set correctly")
	}
	if m.PolicyProfile == nil || *m.PolicyProfile != "legal-v1" {
		t.Errorf("policy_profile not set correctly")
	}
}

// ── Optional-field omission preserved in canonical form ──────────────────────

func TestCanonicalJSON_OmitsOptionalWhenNil(t *testing.T) {
	m, _ := ParseManifest([]byte(validManifestJSON))
	canonical, _ := m.CanonicalJSON()
	if strings.Contains(string(canonical), "timestamp_token_ref") {
		t.Error("nil TimestampTokenRef leaked into canonical form")
	}
	if strings.Contains(string(canonical), "case_reference") {
		t.Error("nil CaseReference leaked into canonical form")
	}
	if strings.Contains(string(canonical), "policy_profile") {
		t.Error("nil PolicyProfile leaked into canonical form")
	}
}

func TestCanonicalJSON_IncludesOptionalWhenSet(t *testing.T) {
	withOpt := strings.Replace(validManifestJSON,
		`"timestamp_status":"present"`,
		`"timestamp_status":"present","timestamp_token_ref":"manifest.tsr"`, 1)
	m, _ := ParseManifest([]byte(withOpt))
	canonical, _ := m.CanonicalJSON()
	if !strings.Contains(string(canonical), `"timestamp_token_ref":"manifest.tsr"`) {
		t.Errorf("optional did not survive: %s", string(canonical))
	}
}

// ── Validate() callable on a freshly-built struct ────────────────────────────

func TestValidate_OnProgrammaticallyBuiltStruct(t *testing.T) {
	tsRef := "manifest.tsr"
	m := &Manifest{
		SchemaVersion:         "1.0",
		BundleID:              "bnd-1700000000000-zzz000",
		PackageClass:          "evidence",
		CreatedAt:             "2026-01-01T00:00:00.000Z",
		Product:               "FDS",
		ProductVersion:        "2.1.0",
		InstallationID:        "0123456789abcdef0123456789abcdef",
		LicenseReference:      "AAAA-****-****-BBBB",
		SigningKeyFingerprint: "fedcba9876543210fedcba9876543210",
		HashAlgorithm:         "sha-256",
		SignatureAlgorithm:    "Ed25519",
		TimestampStatus:       "absent",
		ArtifactCount:         0,
		Artifacts:             []map[string]any{},
		TimestampTokenRef:     &tsRef,
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("expected valid manifest, got error: %v", err)
	}
}

func TestValidate_NilArtifactsRejected(t *testing.T) {
	m := &Manifest{
		SchemaVersion:         "1.0",
		BundleID:              "bnd-1700000000000-zzz000",
		PackageClass:          "evidence",
		CreatedAt:             "2026-01-01T00:00:00.000Z",
		Product:               "FDS",
		ProductVersion:        "2.1.0",
		InstallationID:        "0123456789abcdef0123456789abcdef",
		LicenseReference:      "AAAA-****-****-BBBB",
		SigningKeyFingerprint: "fedcba9876543210fedcba9876543210",
		HashAlgorithm:         "sha-256",
		SignatureAlgorithm:    "Ed25519",
		TimestampStatus:       "absent",
		ArtifactCount:         0,
		Artifacts:             nil,
	}
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "artifacts") {
		t.Fatalf("expected artifacts-nil error, got: %v", err)
	}
}
