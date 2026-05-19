// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Stage C.3 — RFC 3161 TSR parse + digest match.
//
// To produce realistic test fixtures we synthesise a self-signed TSA
// certificate + RSA key in-process and let the digitorus/timestamp
// library issue an actual TimeStampResponse. The resulting DER bytes are
// then fed back to our Parse / VerifyDigest pipeline as a closed
// round-trip — exercising the exact code path that runs against real
// freetsa.org / DigiCert tokens in production.

package tsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

// testTSAPolicy is a placeholder OID used by the synthetic TSR fixtures.
// Real CKNF recordings carry the policy OID assigned by the issuing TSA
// (e.g. 1.2.3.4.1 for freetsa.org). The verifier does not check policy
// values in v0.1.0.
var testTSAPolicy = asn1.ObjectIdentifier{1, 2, 3, 4, 1}

func buildTestTSACert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Verifier Test TSA",
			Organization: []string{"WBR IP & License Holding Pte. Ltd."},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, priv
}

func makeTSR(t *testing.T, digest []byte) []byte {
	t.Helper()
	cert, priv := buildTestTSACert(t)
	ts := &timestamp.Timestamp{
		HashedMessage:     digest,
		HashAlgorithm:     crypto.SHA256,
		Time:              time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC),
		Nonce:             big.NewInt(0x1234),
		Policy:            testTSAPolicy,
		Certificates:      []*x509.Certificate{cert},
		AddTSACertificate: true,
	}
	tsr, err := ts.CreateResponseWithOpts(cert, priv, crypto.SHA256)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	return tsr
}

func TestParse_Happy(t *testing.T) {
	audio := []byte("the actual audio bytes")
	sum := sha256.Sum256(audio)
	digest := sum[:]

	tsr := makeTSR(t, digest)
	info, err := Parse(tsr)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(info.HashedMessage, digest) {
		t.Errorf("HashedMessage mismatch\n  want: %x\n  got:  %x", digest, info.HashedMessage)
	}
	if info.HashAlgorithm == "" {
		t.Error("HashAlgorithm should be populated")
	}
	if info.SerialNumber == "" {
		t.Error("SerialNumber should be populated (TSA assigns its own)")
	}
	if !strings.HasPrefix(info.GenTime, "2026-05-19T10:00:00") {
		t.Errorf("GenTime: want '2026-05-19T10:00:00…', got %q", info.GenTime)
	}
	if !strings.Contains(info.SigningCertSubject, "Verifier Test TSA") {
		t.Errorf("SigningCertSubject should mention test TSA, got: %q", info.SigningCertSubject)
	}
}

func TestParse_EmptyBytes(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Error("expected error on nil TSR")
	}
	if _, err := Parse([]byte{}); err == nil {
		t.Error("expected error on empty TSR")
	}
}

func TestParse_GarbageBytes(t *testing.T) {
	_, err := Parse([]byte("this is definitely not DER-encoded ASN.1"))
	if err == nil {
		t.Error("expected error on non-DER garbage")
	}
}

func TestParseFile_RoundTrip(t *testing.T) {
	audio := []byte("file-tsr test audio")
	sum := sha256.Sum256(audio)
	tsr := makeTSR(t, sum[:])

	path := filepath.Join(t.TempDir(), "original.tsr")
	if err := os.WriteFile(path, tsr, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	info, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if !bytes.Equal(info.HashedMessage, sum[:]) {
		t.Error("ParseFile round-trip lost digest")
	}
}

func TestParseFile_MissingPath(t *testing.T) {
	_, err := ParseFile(filepath.Join(t.TempDir(), "does-not-exist.tsr"))
	if err == nil {
		t.Error("expected error on missing file")
	}
}

func TestVerifyDigest_Happy(t *testing.T) {
	audio := []byte("audio-for-digest-match")
	sum := sha256.Sum256(audio)
	hexDigest := hex.EncodeToString(sum[:])

	tsr := makeTSR(t, sum[:])
	info, err := Parse(tsr)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := VerifyDigest(info, hexDigest); err != nil {
		t.Errorf("VerifyDigest on matching digest: %v", err)
	}
}

func TestVerifyDigest_Mismatch(t *testing.T) {
	audio := []byte("audio-A")
	sum := sha256.Sum256(audio)
	tsr := makeTSR(t, sum[:])
	info, _ := Parse(tsr)

	wrong := hex.EncodeToString(sha256.New().Sum(nil))
	err := VerifyDigest(info, wrong)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "MISMATCH") {
		t.Errorf("error should mention MISMATCH, got: %v", err)
	}
}

func TestVerifyDigest_NilInfo(t *testing.T) {
	if err := VerifyDigest(nil, "x"); err == nil {
		t.Error("expected error on nil info")
	}
}

func TestVerifyDigest_EmptyHashedMessage(t *testing.T) {
	info := &TimestampInfo{}
	if err := VerifyDigest(info, "x"); err == nil {
		t.Error("expected error on empty HashedMessage")
	}
}

func TestVerifyBytes_Happy(t *testing.T) {
	audio := []byte("verify-bytes-happy")
	sum := sha256.Sum256(audio)
	tsr := makeTSR(t, sum[:])

	info, err := VerifyBytes(tsr, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("VerifyBytes: %v", err)
	}
	if info == nil {
		t.Fatal("VerifyBytes returned nil info on success")
	}
}

func TestVerifyBytes_MismatchReturnsInfoAndError(t *testing.T) {
	audio := []byte("audio-A")
	sum := sha256.Sum256(audio)
	tsr := makeTSR(t, sum[:])

	info, err := VerifyBytes(tsr, strings.Repeat("0", 64))
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if info == nil {
		t.Error("info should be non-nil on digest mismatch — parse succeeded")
	}
}

func TestSHA256OfBytes_KnownVector(t *testing.T) {
	got := SHA256OfBytes([]byte(""))
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("empty-input SHA-256: want %s, got %s", got, want)
	}
}
