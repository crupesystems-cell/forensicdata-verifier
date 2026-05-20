// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

// signing.go — Bundle-Spec v1.0 §8 Ed25519 signing primitives, Go-side
// verifier.
//
// Byte-exact Go mirror of:
//
//	/Volumes/FDC_MASTER/SIS/packages/forensicdata_audit/src/forensicdata_audit/signing.py
//
// This Go side is verify-focused (the Verifier-CLI never produces signatures
// — that's the producer-side Python library). The API:
//
//   - LoadPublicKeyPEM(pem) → ed25519.PublicKey
//   - SerializePublicKeyPEM(pub) → SPKI PEM string
//   - ComputeSigningKeyFingerprint(pub) → §6.2 + §8.2 ``public_key_id``
//                              (first 32 hex chars of SHA-256(DER SPKI))
//   - VerifySignature(pub, manifest_hash, signature_b64) → §8.5 step 5
//   - ManifestSignature struct (10-field §8.2)
//   - ParseManifestSignature(bytes) → strict schema validate + Validate()
//   - (*ManifestSignature).ToMap() / CanonicalJSON()
//
// Stdlib-only: crypto/ed25519, crypto/x509, encoding/pem, encoding/base64,
// crypto/sha256. No third-party dependencies.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
)

// ── Constants pinned to Bundle-Spec v1.0 §8.2 ────────────────────────────────

const (
	signatureSchemaVersion = "1.0"
	signatureAlgorithmName = "Ed25519"
	signatureSignedData    = "manifest-sha256"
	pemBlockTypePublicKey  = "PUBLIC KEY"
)

var (
	reHex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reB64Sig88  = regexp.MustCompile(`^[A-Za-z0-9+/]{86}==$`)
	rePEMPublic = regexp.MustCompile(`(?s)^-----BEGIN PUBLIC KEY-----\s.*?\s-----END PUBLIC KEY-----\s*\z`)
)

// ── ManifestSignatureError ───────────────────────────────────────────────────

type ManifestSignatureError struct {
	Field string
	Value any
	Hint  string
}

func (e *ManifestSignatureError) Error() string {
	return fmt.Sprintf("manifest.sig: %s: %s (got %v)", e.Field, e.Hint, e.Value)
}

func sigErr(field string, value any, hint string) error {
	return &ManifestSignatureError{Field: field, Value: value, Hint: hint}
}

// ── PEM serialise + load (§8.4) ──────────────────────────────────────────────

// SerializePublicKeyPEM returns the SPKI PEM form of an Ed25519 public key,
// byte-exact with Python “cryptography“'s “serialize_public_key_pem“.
func SerializePublicKeyPEM(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", sigErr("public_key", len(pub),
			fmt.Sprintf("must be %d bytes, got %d", ed25519.PublicKeySize, len(pub)))
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", sigErr("public_key", nil, fmt.Sprintf("DER marshal failed: %v", err))
	}
	block := &pem.Block{Type: pemBlockTypePublicKey, Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

// LoadPublicKeyPEM parses an SPKI PEM-encoded Ed25519 public key. Mirrors
// Python “load_public_key_pem“ — non-Ed25519 keys or malformed PEM raise
// ManifestSignatureError.
func LoadPublicKeyPEM(pemStr string) (ed25519.PublicKey, error) {
	if pemStr == "" {
		return nil, sigErr("public_key_pem", pemStr, "empty input")
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, sigErr("public_key_pem", pemStr, "could not decode PEM block")
	}
	if block.Type != pemBlockTypePublicKey {
		return nil, sigErr("public_key_pem", block.Type,
			fmt.Sprintf("must be %q PEM block", pemBlockTypePublicKey))
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, sigErr("public_key_pem", nil,
			fmt.Sprintf("could not parse SPKI: %v", err))
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, sigErr("public_key_pem", fmt.Sprintf("%T", key),
			"is not an Ed25519 public key")
	}
	return pub, nil
}

// ── Fingerprint (§6.2 + §8.2 public_key_id) ──────────────────────────────────

// ComputeSigningKeyFingerprint mirrors Python compute_signing_key_fingerprint:
// first 32 hex chars of SHA-256(DER SubjectPublicKeyInfo).
func ComputeSigningKeyFingerprint(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", sigErr("public_key", len(pub),
			fmt.Sprintf("must be %d bytes, got %d", ed25519.PublicKeySize, len(pub)))
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", sigErr("public_key", nil, fmt.Sprintf("DER marshal failed: %v", err))
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:32], nil
}

// ── Verify (§8.1 + §8.5 step 5) ──────────────────────────────────────────────

// VerifySignature returns true iff the Ed25519 signature is valid over the
// UTF-8 bytes of the 64-char hex “manifest_hash“. Bundle-Spec §8.1 lock:
// signature is over the hex string bytes, NOT raw SHA-256 bytes.
//
// Mirrors Python “verify_signature“ semantics: malformed input returns
// false (no panic, no error).
func VerifySignature(pub ed25519.PublicKey, manifestHash, signatureB64 string) bool {
	if !reHex64.MatchString(manifestHash) {
		return false
	}
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	rawSig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}
	if len(rawSig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, []byte(manifestHash), rawSig)
}

// ── ManifestSignature struct (§8.2) ──────────────────────────────────────────

// ManifestSignature mirrors Python forensicdata_audit.signing.ManifestSignature
// — ten mandatory fields per Bundle-Spec §8.2.
type ManifestSignature struct {
	SchemaVersion      string `json:"schema_version"`
	BundleID           string `json:"bundle_id"`
	InstallationID     string `json:"installation_id"`
	PublicKeyID        string `json:"public_key_id"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	SignedData         string `json:"signed_data"`
	ManifestHash       string `json:"manifest_hash"`
	Signature          string `json:"signature"`
	PublicKeyPEM       string `json:"public_key_pem"`
	SignedAt           string `json:"signed_at"`
}

// Validate enforces §8.2 per-field constraints. Returns
// *ManifestSignatureError on first failure.
func (s *ManifestSignature) Validate() error {
	if s.SchemaVersion != signatureSchemaVersion {
		return sigErr("schema_version", s.SchemaVersion,
			fmt.Sprintf("must be exactly %q", signatureSchemaVersion))
	}
	if !reBundleID.MatchString(s.BundleID) {
		return sigErr("bundle_id", s.BundleID,
			"must match bnd-<unix_ms>-<6 lowercase alphanum>")
	}
	if !reHex32.MatchString(s.InstallationID) {
		return sigErr("installation_id", s.InstallationID,
			"must be 32 lowercase hex chars")
	}
	if !reHex32.MatchString(s.PublicKeyID) {
		return sigErr("public_key_id", s.PublicKeyID,
			"must be 32 lowercase hex chars")
	}
	if s.SignatureAlgorithm != signatureAlgorithmName {
		return sigErr("signature_algorithm", s.SignatureAlgorithm,
			fmt.Sprintf("must be %q", signatureAlgorithmName))
	}
	if s.SignedData != signatureSignedData {
		return sigErr("signed_data", s.SignedData,
			fmt.Sprintf("must be %q", signatureSignedData))
	}
	if !reHex64.MatchString(s.ManifestHash) {
		return sigErr("manifest_hash", s.ManifestHash,
			"must be 64 lowercase hex chars")
	}
	if !reB64Sig88.MatchString(s.Signature) {
		return sigErr("signature", s.Signature,
			"must be 88-char base64 (64-byte Ed25519 signature)")
	}
	if !rePEMPublic.MatchString(s.PublicKeyPEM) {
		return sigErr("public_key_pem", s.PublicKeyPEM,
			"must be SPKI PEM (-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----)")
	}
	if !reISOUtcMs.MatchString(s.SignedAt) {
		return sigErr("signed_at", s.SignedAt,
			"must be ISO 8601 UTC ms (YYYY-MM-DDTHH:mm:ss.sssZ)")
	}
	return nil
}

// ── Parsing ──────────────────────────────────────────────────────────────────

var manifestSigRequiredKeys = map[string]struct{}{
	"schema_version":      {},
	"bundle_id":           {},
	"installation_id":     {},
	"public_key_id":       {},
	"signature_algorithm": {},
	"signed_data":         {},
	"manifest_hash":       {},
	"signature":           {},
	"public_key_pem":      {},
	"signed_at":           {},
}

// ParseManifestSignature parses manifest.sig bytes and returns a validated
// ManifestSignature. Strict: missing or extra keys → ManifestSignatureError.
func ParseManifestSignature(data []byte) (*ManifestSignature, error) {
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("manifest.sig: parse JSON: %w", err)
	}

	got := make(map[string]struct{}, len(raw))
	for k := range raw {
		got[k] = struct{}{}
	}
	var missing []string
	for k := range manifestSigRequiredKeys {
		if _, ok := got[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, sigErr("schema", missing, "missing required keys")
	}
	var extra []string
	for k := range got {
		if _, req := manifestSigRequiredKeys[k]; !req {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		return nil, sigErr("schema", extra, "extra keys not in Bundle-Spec §8.2")
	}

	s := &ManifestSignature{}
	for _, kv := range []struct {
		key string
		dst *string
	}{
		{"schema_version", &s.SchemaVersion},
		{"bundle_id", &s.BundleID},
		{"installation_id", &s.InstallationID},
		{"public_key_id", &s.PublicKeyID},
		{"signature_algorithm", &s.SignatureAlgorithm},
		{"signed_data", &s.SignedData},
		{"manifest_hash", &s.ManifestHash},
		{"signature", &s.Signature},
		{"public_key_pem", &s.PublicKeyPEM},
		{"signed_at", &s.SignedAt},
	} {
		v, ok := raw[kv.key]
		if !ok {
			return nil, sigErr(kv.key, nil, "missing field")
		}
		str, ok := v.(string)
		if !ok {
			return nil, sigErr(kv.key, v, fmt.Sprintf("must be string, got %T", v))
		}
		*kv.dst = str
	}

	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// ── ToMap / CanonicalJSON ────────────────────────────────────────────────────

// ToMap returns the §8.2 map representation in field order (canonical-JSON
// is responsible for sorting; this preserves field-insertion stability).
func (s *ManifestSignature) ToMap() map[string]any {
	return map[string]any{
		"schema_version":      s.SchemaVersion,
		"bundle_id":           s.BundleID,
		"installation_id":     s.InstallationID,
		"public_key_id":       s.PublicKeyID,
		"signature_algorithm": s.SignatureAlgorithm,
		"signed_data":         s.SignedData,
		"manifest_hash":       s.ManifestHash,
		"signature":           s.Signature,
		"public_key_pem":      s.PublicKeyPEM,
		"signed_at":           s.SignedAt,
	}
}

// CanonicalJSON returns the §6.1 canonical-JSON byte form of the manifest.sig
// payload via the shared canonical.go (cross-language byte-exact).
func (s *ManifestSignature) CanonicalJSON() ([]byte, error) {
	return CanonicalJSON(s.ToMap())
}
