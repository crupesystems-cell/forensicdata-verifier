// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Golden vectors generated from Python forensicdata_audit.signing using the
// zero-seed Ed25519 private key (32 zero bytes). Locking these in Go proves
// byte-exact cross-language signature compatibility for Bundle-Spec §8.
const (
	goldenZeroSeedFingerprint = "339e2ff917630507b6a423b5ce084e28"
	goldenZeroSeedRawPubHex   = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
	goldenZeroSeedPEM         = "-----BEGIN PUBLIC KEY-----\n" +
		"MCowBQYDK2VwAyEAO2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=\n" +
		"-----END PUBLIC KEY-----\n"
	goldenManifestHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	goldenSigB64       = "PpHNcbCqAX2hAUhP5U8rBvXQ3pScnl/K3nscMd+co1lob1inprwRiwljajdNPK+id0TlYjC9ow9FN/xk9eBeCA=="
)

// zeroSeedKeypair returns the deterministic Ed25519 keypair derived from a
// 32-byte zero seed (mirrors Python's
// “Ed25519PrivateKey.from_private_bytes(bytes(32))“).
func zeroSeedKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// ── LoadPublicKeyPEM ─────────────────────────────────────────────────────────

func TestLoadPublicKeyPEMAcceptsZeroSeedSPKI(t *testing.T) {
	pub, err := LoadPublicKeyPEM(goldenZeroSeedPEM)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM error: %v", err)
	}
	want, _ := hex.DecodeString(goldenZeroSeedRawPubHex)
	if !bytesEqual(pub, want) {
		t.Errorf("raw public key mismatch\n  got:  %x\n  want: %x", pub, want)
	}
}

func TestLoadPublicKeyPEMRoundTrip(t *testing.T) {
	originalPub, _ := zeroSeedKeypair(t)
	pem, err := SerializePublicKeyPEM(originalPub)
	if err != nil {
		t.Fatalf("SerializePublicKeyPEM: %v", err)
	}
	loaded, err := LoadPublicKeyPEM(pem)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM: %v", err)
	}
	if !bytesEqual(loaded, originalPub) {
		t.Errorf("round-trip mismatch:\n  got:  %x\n  want: %x", loaded, originalPub)
	}
}

func TestSerializePublicKeyPEMByteExactWithPython(t *testing.T) {
	pub, _ := zeroSeedKeypair(t)
	pem, err := SerializePublicKeyPEM(pub)
	if err != nil {
		t.Fatalf("SerializePublicKeyPEM: %v", err)
	}
	if pem != goldenZeroSeedPEM {
		t.Errorf("PEM not byte-exact with Python reference\n  got:  %q\n  want: %q", pem, goldenZeroSeedPEM)
	}
}

func TestLoadPublicKeyPEMRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		pem  string
	}{
		{"not_a_pem", "not a PEM"},
		{"empty", ""},
		{"truncated_header", "-----BEGIN PUBLIC KEY-----\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := LoadPublicKeyPEM(c.pem); err == nil {
				t.Errorf("expected error for malformed PEM (%s)", c.name)
			}
		})
	}
}

// ── ComputeSigningKeyFingerprint ─────────────────────────────────────────────

func TestComputeSigningKeyFingerprintZeroSeedKnownValue(t *testing.T) {
	pub, _ := zeroSeedKeypair(t)
	fp, err := ComputeSigningKeyFingerprint(pub)
	if err != nil {
		t.Fatalf("ComputeSigningKeyFingerprint: %v", err)
	}
	if fp != goldenZeroSeedFingerprint {
		t.Errorf("fingerprint not byte-exact with Python reference\n  got:  %q\n  want: %q", fp, goldenZeroSeedFingerprint)
	}
}

func TestComputeSigningKeyFingerprintIs32LowercaseHex(t *testing.T) {
	pub, _ := zeroSeedKeypair(t)
	fp, err := ComputeSigningKeyFingerprint(pub)
	if err != nil {
		t.Fatalf("ComputeSigningKeyFingerprint: %v", err)
	}
	if len(fp) != 32 {
		t.Errorf("expected 32 chars, got %d", len(fp))
	}
	if !reHex32.MatchString(fp) {
		t.Errorf("not 32 lowercase hex: %q", fp)
	}
}

func TestComputeSigningKeyFingerprintDeterministicForSameKey(t *testing.T) {
	pub, _ := zeroSeedKeypair(t)
	fp1, err := ComputeSigningKeyFingerprint(pub)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	fp2, err := ComputeSigningKeyFingerprint(pub)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if fp1 != fp2 {
		t.Errorf("non-deterministic: %q vs %q", fp1, fp2)
	}
}

func TestComputeSigningKeyFingerprintDiffersPerKey(t *testing.T) {
	pub1, _ := zeroSeedKeypair(t)
	seed2 := make([]byte, 32)
	seed2[0] = 1
	priv2 := ed25519.NewKeyFromSeed(seed2)
	pub2 := priv2.Public().(ed25519.PublicKey)

	fp1, _ := ComputeSigningKeyFingerprint(pub1)
	fp2, _ := ComputeSigningKeyFingerprint(pub2)
	if fp1 == fp2 {
		t.Errorf("fingerprints should differ for different keys; both = %q", fp1)
	}
}

func TestComputeSigningKeyFingerprintRejectsInvalidPubLen(t *testing.T) {
	tooShort := ed25519.PublicKey(make([]byte, 16))
	if _, err := ComputeSigningKeyFingerprint(tooShort); err == nil {
		t.Errorf("expected error for non-Ed25519 public key length")
	}
}

// ── VerifySignature (§8.5 step 5) ────────────────────────────────────────────

func TestVerifySignatureAcceptsZeroSeedGoldenSignature(t *testing.T) {
	pub, _ := zeroSeedKeypair(t)
	if !VerifySignature(pub, goldenManifestHash, goldenSigB64) {
		t.Errorf("zero-seed Python-generated signature should verify in Go (cross-language byte-exact)")
	}
}

func TestVerifySignatureSignsUTF8BytesOfHexStringPerSpec81(t *testing.T) {
	// Bundle-Spec §8.1 lock: signature is over UTF-8 bytes of the hex string,
	// NOT over the raw SHA-256 bytes. We assert this by signing the same
	// hex string in Go and getting the same base64 sig as Python.
	pub, priv := zeroSeedKeypair(t)
	rawSig := ed25519.Sign(priv, []byte(goldenManifestHash))
	sigB64 := base64.StdEncoding.EncodeToString(rawSig)
	if sigB64 != goldenSigB64 {
		t.Errorf("cross-language sig mismatch (Go vs Python)\n  got:  %s\n  want: %s", sigB64, goldenSigB64)
	}
	if !VerifySignature(pub, goldenManifestHash, sigB64) {
		t.Errorf("Go-signed signature should verify")
	}
}

func TestVerifySignatureFailsOnTamperedHash(t *testing.T) {
	pub, _ := zeroSeedKeypair(t)
	otherHash := strings.Repeat("b", 64)
	if VerifySignature(pub, otherHash, goldenSigB64) {
		t.Errorf("tampered hash should fail verification")
	}
}

func TestVerifySignatureFailsOnWrongPublicKey(t *testing.T) {
	seed2 := make([]byte, 32)
	seed2[0] = 1
	otherPriv := ed25519.NewKeyFromSeed(seed2)
	otherPub := otherPriv.Public().(ed25519.PublicKey)
	if VerifySignature(otherPub, goldenManifestHash, goldenSigB64) {
		t.Errorf("wrong public key should fail verification")
	}
}

func TestVerifySignatureFailsOnCorruptSignature(t *testing.T) {
	pub, _ := zeroSeedKeypair(t)
	corrupted := "A"
	if goldenSigB64[0] == 'A' {
		corrupted = "B"
	}
	corrupted += goldenSigB64[1:]
	if VerifySignature(pub, goldenManifestHash, corrupted) {
		t.Errorf("corrupt signature should fail verification")
	}
}

func TestVerifySignatureFailsOnInvalidBase64(t *testing.T) {
	pub, _ := zeroSeedKeypair(t)
	if VerifySignature(pub, goldenManifestHash, "not-valid-b64!!") {
		t.Errorf("invalid base64 must return false (not panic)")
	}
}

func TestVerifySignatureFailsOnWrongSignatureLength(t *testing.T) {
	pub, _ := zeroSeedKeypair(t)
	short := base64.StdEncoding.EncodeToString(make([]byte, 47))
	if VerifySignature(pub, goldenManifestHash, short) {
		t.Errorf("short signature must return false")
	}
}

func TestVerifySignatureRejectsNonHex64Hash(t *testing.T) {
	pub, _ := zeroSeedKeypair(t)
	bad := []string{
		"",
		"too-short",
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		strings.Repeat("A", 64), // uppercase rejected per §8.1 lowercase rule
		strings.Repeat("z", 64), // non-hex char
	}
	for _, h := range bad {
		t.Run(h, func(t *testing.T) {
			if VerifySignature(pub, h, goldenSigB64) {
				t.Errorf("invalid manifest_hash %q must return false", h)
			}
		})
	}
}

// ── ManifestSignature struct + Validate ──────────────────────────────────────

func validSigKwargs() map[string]any {
	return map[string]any{
		"schema_version":      "1.0",
		"bundle_id":           "bnd-1745000000000-xk9m2p",
		"installation_id":     "a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6",
		"public_key_id":       "f1e2d3c4b5a697880123456789abcdef",
		"signature_algorithm": "Ed25519",
		"signed_data":         "manifest-sha256",
		"manifest_hash":       goldenManifestHash,
		"signature":           base64.StdEncoding.EncodeToString(bytesRepeat(0x01, 64)),
		"public_key_pem":      goldenZeroSeedPEM,
		"signed_at":           "2026-05-21T10:00:00.000Z",
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestManifestSignatureValidateAcceptsValid(t *testing.T) {
	data, _ := json.Marshal(validSigKwargs())
	sig, err := ParseManifestSignature(data)
	if err != nil {
		t.Fatalf("ParseManifestSignature: %v", err)
	}
	if sig.ManifestHash != goldenManifestHash {
		t.Errorf("manifest_hash mismatch")
	}
}

func TestManifestSignatureRejectsMissingKey(t *testing.T) {
	m := validSigKwargs()
	delete(m, "manifest_hash")
	data, _ := json.Marshal(m)
	if _, err := ParseManifestSignature(data); err == nil {
		t.Errorf("expected error for missing manifest_hash")
	}
}

func TestManifestSignatureRejectsExtraKey(t *testing.T) {
	m := validSigKwargs()
	m["bogus_field"] = "x"
	data, _ := json.Marshal(m)
	if _, err := ParseManifestSignature(data); err == nil {
		t.Errorf("expected error for extra key not in §8.2")
	}
}

func TestManifestSignatureValidatesFieldByField(t *testing.T) {
	cases := []struct {
		field string
		value string
	}{
		{"schema_version", "2.0"},
		{"bundle_id", "not-a-bundle"},
		{"installation_id", "TOOSHORT"},
		{"public_key_id", "TOOSHORT"},
		{"signature_algorithm", "RSA"},
		{"signed_data", "raw-sha256"},
		{"manifest_hash", "tooshort"},
		{"signature", "not-base64-88-chars"},
		{"public_key_pem", "not a PEM"},
		{"signed_at", "2026-05-21"},
	}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			m := validSigKwargs()
			m[c.field] = c.value
			data, _ := json.Marshal(m)
			if _, err := ParseManifestSignature(data); err == nil {
				t.Errorf("expected error for invalid %s=%q", c.field, c.value)
			}
		})
	}
}

// ── ToMap / CanonicalJSON ────────────────────────────────────────────────────

func TestManifestSignatureCanonicalJSONStartsWithBundleID(t *testing.T) {
	data, _ := json.Marshal(validSigKwargs())
	sig, err := ParseManifestSignature(data)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	canonical, err := sig.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if !strings.HasPrefix(string(canonical), `{"bundle_id":`) {
		end := 40
		if len(canonical) < end {
			end = len(canonical)
		}
		t.Errorf("canonical should start with {\"bundle_id\": (sorted keys); got prefix %q",
			string(canonical[:end]))
	}
}

func TestManifestSignatureCanonicalJSONNoWhitespace(t *testing.T) {
	data, _ := json.Marshal(validSigKwargs())
	sig, _ := ParseManifestSignature(data)
	canonical, _ := sig.CanonicalJSON()
	s := string(canonical)
	if strings.Contains(s, ": ") {
		t.Errorf("canonical JSON should not contain `: `")
	}
	if strings.Contains(s, ", ") {
		t.Errorf("canonical JSON should not contain `, `")
	}
	if strings.Contains(s, "\n") {
		t.Errorf("canonical JSON should not contain newlines")
	}
}

func TestManifestSignatureRoundTrip(t *testing.T) {
	data, _ := json.Marshal(validSigKwargs())
	sig, err := ParseManifestSignature(data)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	canonical, _ := sig.CanonicalJSON()
	sig2, err := ParseManifestSignature(canonical)
	if err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	canonical2, _ := sig2.CanonicalJSON()
	if string(canonical) != string(canonical2) {
		t.Errorf("round-trip not byte-stable")
	}
}

// ── End-to-end: parse + verify ───────────────────────────────────────────────

func TestEndToEndParseAndVerifyZeroSeedSignature(t *testing.T) {
	m := validSigKwargs()
	m["signature"] = goldenSigB64
	m["public_key_pem"] = goldenZeroSeedPEM
	m["public_key_id"] = goldenZeroSeedFingerprint
	data, _ := json.Marshal(m)

	sig, err := ParseManifestSignature(data)
	if err != nil {
		t.Fatalf("ParseManifestSignature: %v", err)
	}
	pub, err := LoadPublicKeyPEM(sig.PublicKeyPEM)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM: %v", err)
	}

	// Cross-check fingerprint matches public_key_id
	fp, err := ComputeSigningKeyFingerprint(pub)
	if err != nil {
		t.Fatalf("ComputeSigningKeyFingerprint: %v", err)
	}
	if fp != sig.PublicKeyID {
		t.Errorf("fingerprint mismatch: got %q, sig.public_key_id %q", fp, sig.PublicKeyID)
	}

	if !VerifySignature(pub, sig.ManifestHash, sig.Signature) {
		t.Errorf("end-to-end verify failed for zero-seed Python-generated signature")
	}
}
