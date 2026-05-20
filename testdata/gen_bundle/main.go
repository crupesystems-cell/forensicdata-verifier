//go:build ignore

// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// gen_bundle/main.go produces a synthetic Bundle-Spec v1.0 ZIP signed
// with the zero-seed Ed25519 reference key. Mirrors goldenSpec{} default
// in internal/bundle/verify_test.go. Used for smoke-testing the built
// `verifier verify bundle` binary against a known-good input.
//
// Run:
//
//	cd /Volumes/FDC_MASTER/source/verifier
//	go run ./testdata/gen_bundle /tmp/golden_bundle.zip
//	./verifier verify bundle /tmp/golden_bundle.zip   # expect exit 0, VALID
package main

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/crupesystems-cell/forensicdata-verifier/internal/bundle"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen_bundle <out.zip>")
		os.Exit(2)
	}
	outPath := os.Args[1]

	seed := make([]byte, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	pem, err := bundle.SerializePublicKeyPEM(pub)
	mustOK(err)
	fp, err := bundle.ComputeSigningKeyFingerprint(pub)
	mustOK(err)

	artBytes := []byte("hello world")
	sum := sha256.Sum256(artBytes)
	artHash := hex.EncodeToString(sum[:])

	m := &bundle.Manifest{
		SchemaVersion:         "1.0",
		BundleID:              "bnd-1745000000000-xk9m2p",
		PackageClass:          "evidence",
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
		Artifacts: []map[string]any{{
			"artifact_id":       "art-1745000000000-abc123",
			"artifact_type":     "document",
			"stored_path":       "artifacts/art-1745000000000-abc123.txt",
			"original_filename": "evidence.txt",
			"mime_type":         "text/plain",
			"byte_size":         len(artBytes),
			"sha256":            artHash,
			"created_at":        "2026-04-18T10:00:00.000Z",
			"origin":            "captured",
			"policy_state":      "export_allowed",
			"is_derived":        false,
		}},
	}
	mustOK(m.Validate())
	mb, err := m.CanonicalJSON()
	mustOK(err)
	mh, err := m.Hash()
	mustOK(err)

	rawSig := ed25519.Sign(priv, []byte(mh))
	sig := &bundle.ManifestSignature{
		SchemaVersion:      "1.0",
		BundleID:           m.BundleID,
		InstallationID:     m.InstallationID,
		PublicKeyID:        fp,
		SignatureAlgorithm: "Ed25519",
		SignedData:         "manifest-sha256",
		ManifestHash:       mh,
		Signature:          base64.StdEncoding.EncodeToString(rawSig),
		PublicKeyPEM:       pem,
		SignedAt:           "2026-04-18T10:00:00.123Z",
	}
	mustOK(sig.Validate())
	sb, err := sig.CanonicalJSON()
	mustOK(err)

	f, err := os.Create(outPath)
	mustOK(err)
	defer f.Close()
	zw := zip.NewWriter(f)
	root := m.BundleID + "/"
	add := func(name string, body []byte) {
		w, err := zw.Create(name)
		mustOK(err)
		_, err = w.Write(body)
		mustOK(err)
	}
	add(root+"manifest.json", mb)
	add(root+"manifest.json.sha256", []byte(mh+"  manifest.json\n"))
	add(root+"manifest.sig", sb)
	add(root+"VERIFY.txt", []byte("verifier verify bundle <path>\n"))
	add(root+"audit/events.jsonl", []byte(""))
	add(root+"meta/signing_key.pub.pem", []byte(pem))
	add(root+"artifacts/art-1745000000000-abc123.txt", artBytes)
	mustOK(zw.Close())
	fmt.Println(outPath)
}

func mustOK(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
