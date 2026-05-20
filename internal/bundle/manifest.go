// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

// manifest.go — Bundle-Spec v1.0 §6 canonical Manifest, Go-side verifier.
//
// Byte-exact Go mirror of:
//
//	/Volumes/FDC_MASTER/SIS/packages/forensicdata_audit/src/forensicdata_audit/manifest.py
//
// This Go side is verify-focused (the Verifier-CLI never produces manifests
// — that's the producer-side Python library). The API:
//
//   - ParseManifest(data) → validates the §6.2 schema and returns a Manifest
//   - (*Manifest).CanonicalJSON() → byte-exact §6.1 form (uses canonical.go)
//   - (*Manifest).Hash() → §8.1 manifest_hash (64 lowercase hex)

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
)

// ── Bundle-Spec §6.2 / §4 enumerations ───────────────────────────────────────

var PackageClasses = map[string]struct{}{
	"evidence":     {},
	"disclosure":   {},
	"verification": {},
	"sanitized":    {},
	"snapshot":     {},
}

var Products = map[string]struct{}{
	"CKNF": {},
	"FDS":  {},
	"FDC":  {},
}

var TimestampStatuses = map[string]struct{}{
	"present": {},
	"absent":  {},
	"offline": {},
}

const (
	manifestSchemaVersion = "1.0"
	manifestHashAlgorithm = "sha-256"
	manifestSignatureAlgo = "Ed25519"
	manifestTSRFileName   = "manifest.tsr"
)

var (
	reBundleID   = regexp.MustCompile(`^bnd-\d+-[a-z0-9]{6}$`)
	reHex32      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reISOUtcMs   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
	reLicenseRef = regexp.MustCompile(`^[A-Z0-9]{4}-\*{4}-\*{4}-[A-Z0-9]{4}$`)
)

// ── ManifestError ────────────────────────────────────────────────────────────

type ManifestError struct {
	Field string
	Value any
	Hint  string
}

func (e *ManifestError) Error() string {
	return fmt.Sprintf("manifest: %s: %s (got %v)", e.Field, e.Hint, e.Value)
}

func mfErr(field string, value any, hint string) error {
	return &ManifestError{Field: field, Value: value, Hint: hint}
}

// ── Manifest struct ──────────────────────────────────────────────────────────

// Manifest mirrors Python forensicdata_audit.manifest.Manifest. OPTIONAL
// pointer fields encode "absent" (nil) so the canonical form omits them
// exactly like Python's to_dict().
type Manifest struct {
	// MUST per §6.2
	SchemaVersion         string           `json:"schema_version"`
	BundleID              string           `json:"bundle_id"`
	PackageClass          string           `json:"package_class"`
	CreatedAt             string           `json:"created_at"`
	Product               string           `json:"product"`
	ProductVersion        string           `json:"product_version"`
	InstallationID        string           `json:"installation_id"`
	LicenseReference      string           `json:"license_reference"`
	SigningKeyFingerprint string           `json:"signing_key_fingerprint"`
	HashAlgorithm         string           `json:"hash_algorithm"`
	SignatureAlgorithm    string           `json:"signature_algorithm"`
	TimestampStatus       string           `json:"timestamp_status"`
	ArtifactCount         int              `json:"artifact_count"`
	Artifacts             []map[string]any `json:"artifacts"`

	// OPTIONAL per §6.2 (nil → omitted in canonical form)
	TimestampTokenRef *string `json:"timestamp_token_ref,omitempty"`
	CaseReference     *string `json:"case_reference,omitempty"`
	PolicyProfile     *string `json:"policy_profile,omitempty"`
}

// ── Validation ───────────────────────────────────────────────────────────────

func (m *Manifest) Validate() error {
	if m.SchemaVersion != manifestSchemaVersion {
		return mfErr("schema_version", m.SchemaVersion,
			fmt.Sprintf("must be exactly %q", manifestSchemaVersion))
	}
	if !reBundleID.MatchString(m.BundleID) {
		return mfErr("bundle_id", m.BundleID,
			"must match bnd-<unix_ms>-<6 lowercase alphanum>")
	}
	if _, ok := PackageClasses[m.PackageClass]; !ok {
		return mfErr("package_class", m.PackageClass,
			"must be one of evidence/disclosure/verification/sanitized/snapshot")
	}
	if !reISOUtcMs.MatchString(m.CreatedAt) {
		return mfErr("created_at", m.CreatedAt,
			"must be ISO 8601 UTC ms (YYYY-MM-DDTHH:mm:ss.sssZ)")
	}
	if _, ok := Products[m.Product]; !ok {
		return mfErr("product", m.Product, "must be one of CKNF/FDS/FDC")
	}
	if m.ProductVersion == "" {
		return mfErr("product_version", m.ProductVersion, "must be non-empty string")
	}
	if !reHex32.MatchString(m.InstallationID) {
		return mfErr("installation_id", m.InstallationID,
			"must be 32 lowercase hex chars")
	}
	if !reLicenseRef.MatchString(m.LicenseReference) {
		return mfErr("license_reference", m.LicenseReference,
			"must match <4 alnum>-****-****-<4 alnum>")
	}
	if !reHex32.MatchString(m.SigningKeyFingerprint) {
		return mfErr("signing_key_fingerprint", m.SigningKeyFingerprint,
			"must be 32 lowercase hex chars")
	}
	if m.HashAlgorithm != manifestHashAlgorithm {
		return mfErr("hash_algorithm", m.HashAlgorithm,
			fmt.Sprintf("must be %q in v1.0", manifestHashAlgorithm))
	}
	if m.SignatureAlgorithm != manifestSignatureAlgo {
		return mfErr("signature_algorithm", m.SignatureAlgorithm,
			fmt.Sprintf("must be %q in v1.0", manifestSignatureAlgo))
	}
	if _, ok := TimestampStatuses[m.TimestampStatus]; !ok {
		return mfErr("timestamp_status", m.TimestampStatus,
			"must be one of present/absent/offline")
	}
	if m.Artifacts == nil {
		return mfErr("artifacts", "nil", "must be a list (use empty slice for none)")
	}
	if m.ArtifactCount != len(m.Artifacts) {
		return mfErr("artifact_count", m.ArtifactCount,
			fmt.Sprintf("must equal len(artifacts) (%d)", len(m.Artifacts)))
	}
	if m.TimestampTokenRef != nil && *m.TimestampTokenRef != manifestTSRFileName {
		return mfErr("timestamp_token_ref", *m.TimestampTokenRef,
			fmt.Sprintf("must be %q if present", manifestTSRFileName))
	}
	return nil
}

// ── Parsing ──────────────────────────────────────────────────────────────────

var manifestRequiredKeys = map[string]struct{}{
	"schema_version":          {},
	"bundle_id":               {},
	"package_class":           {},
	"created_at":              {},
	"product":                 {},
	"product_version":         {},
	"installation_id":         {},
	"license_reference":       {},
	"signing_key_fingerprint": {},
	"hash_algorithm":          {},
	"signature_algorithm":     {},
	"timestamp_status":        {},
	"artifact_count":          {},
	"artifacts":               {},
}

var manifestOptionalKeys = map[string]struct{}{
	"timestamp_token_ref": {},
	"case_reference":      {},
	"policy_profile":      {},
}

// ParseManifest parses canonical or pretty-printed manifest.json bytes and
// returns a validated Manifest. Strict: missing required keys or
// Bundle-Spec-foreign extra keys → ManifestError.
func ParseManifest(data []byte) (*Manifest, error) {
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("manifest: parse JSON: %w", err)
	}

	got := make(map[string]struct{}, len(raw))
	for k := range raw {
		got[k] = struct{}{}
	}
	var missing []string
	for k := range manifestRequiredKeys {
		if _, ok := got[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, mfErr("schema", missing, "missing required keys")
	}
	var extra []string
	for k := range got {
		_, req := manifestRequiredKeys[k]
		_, opt := manifestOptionalKeys[k]
		if !req && !opt {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		return nil, mfErr("schema", extra, "extra keys not in Bundle-Spec §6.2")
	}

	m := &Manifest{}
	for _, kv := range []struct {
		key string
		dst *string
	}{
		{"schema_version", &m.SchemaVersion},
		{"bundle_id", &m.BundleID},
		{"package_class", &m.PackageClass},
		{"created_at", &m.CreatedAt},
		{"product", &m.Product},
		{"product_version", &m.ProductVersion},
		{"installation_id", &m.InstallationID},
		{"license_reference", &m.LicenseReference},
		{"signing_key_fingerprint", &m.SigningKeyFingerprint},
		{"hash_algorithm", &m.HashAlgorithm},
		{"signature_algorithm", &m.SignatureAlgorithm},
		{"timestamp_status", &m.TimestampStatus},
	} {
		if err := assignStringField(raw, kv.key, kv.dst); err != nil {
			return nil, err
		}
	}

	count, err := jsonNumberAsInt(raw["artifact_count"])
	if err != nil {
		return nil, mfErr("artifact_count", raw["artifact_count"], err.Error())
	}
	m.ArtifactCount = count

	arts, err := jsonArrayOfObjects(raw["artifacts"])
	if err != nil {
		return nil, mfErr("artifacts", raw["artifacts"], err.Error())
	}
	m.Artifacts = arts

	// Optional fields — assign only if present
	if v, ok := raw["timestamp_token_ref"]; ok {
		s, err := jsonOptionalString(v)
		if err != nil {
			return nil, mfErr("timestamp_token_ref", v, err.Error())
		}
		m.TimestampTokenRef = &s
	}
	if v, ok := raw["case_reference"]; ok {
		s, err := jsonOptionalString(v)
		if err != nil {
			return nil, mfErr("case_reference", v, err.Error())
		}
		m.CaseReference = &s
	}
	if v, ok := raw["policy_profile"]; ok {
		s, err := jsonOptionalString(v)
		if err != nil {
			return nil, mfErr("policy_profile", v, err.Error())
		}
		m.PolicyProfile = &s
	}

	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// ── Canonical / Hash ─────────────────────────────────────────────────────────

// ToMap returns the §6.2 map representation. OPTIONAL nil pointers are
// omitted to match Python forensicdata_audit.manifest.Manifest.to_dict().
func (m *Manifest) ToMap() map[string]any {
	out := map[string]any{
		"schema_version":          m.SchemaVersion,
		"bundle_id":               m.BundleID,
		"package_class":           m.PackageClass,
		"created_at":              m.CreatedAt,
		"product":                 m.Product,
		"product_version":         m.ProductVersion,
		"installation_id":         m.InstallationID,
		"license_reference":       m.LicenseReference,
		"signing_key_fingerprint": m.SigningKeyFingerprint,
		"hash_algorithm":          m.HashAlgorithm,
		"signature_algorithm":     m.SignatureAlgorithm,
		"timestamp_status":        m.TimestampStatus,
		"artifact_count":          m.ArtifactCount,
	}
	arts := make([]any, len(m.Artifacts))
	for i, a := range m.Artifacts {
		arts[i] = a
	}
	out["artifacts"] = arts

	if m.TimestampTokenRef != nil {
		out["timestamp_token_ref"] = *m.TimestampTokenRef
	}
	if m.CaseReference != nil {
		out["case_reference"] = *m.CaseReference
	}
	if m.PolicyProfile != nil {
		out["policy_profile"] = *m.PolicyProfile
	}
	return out
}

// CanonicalJSON returns the §6.1 canonical-JSON byte form of the manifest.
func (m *Manifest) CanonicalJSON() ([]byte, error) {
	return CanonicalJSON(m.ToMap())
}

// Hash returns §8.1 manifest_hash (lowercase hex SHA-256 of canonical bytes).
func (m *Manifest) Hash() (string, error) {
	return SHA256Hex(m.ToMap())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func assignStringField(raw map[string]any, key string, dst *string) error {
	v, ok := raw[key]
	if !ok {
		return mfErr(key, nil, "missing field")
	}
	s, ok := v.(string)
	if !ok {
		return mfErr(key, v, fmt.Sprintf("must be string, got %T", v))
	}
	*dst = s
	return nil
}

func jsonNumberAsInt(v any) (int, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, fmt.Errorf("must be JSON number, got %T", v)
	}
	i, err := n.Int64()
	if err != nil {
		return 0, fmt.Errorf("must be an integer (no decimals): %w", err)
	}
	return int(i), nil
}

func jsonArrayOfObjects(v any) ([]map[string]any, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("must be a JSON array, got %T", v)
	}
	out := make([]map[string]any, 0, len(arr))
	for i, e := range arr {
		obj, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("artifacts[%d] must be an object, got %T", i, e)
		}
		out = append(out, obj)
	}
	return out, nil
}

func jsonOptionalString(v any) (string, error) {
	if v == nil {
		return "", fmt.Errorf("must not be null (omit the key instead)")
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("must be string, got %T", v)
	}
	return s, nil
}
