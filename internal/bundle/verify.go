// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

// verify.go — Bundle-Spec v1.0 §12 mandatory-checks orchestrator.
//
// Implements the verifier-side ordered check pipeline producing a single
// primary result code (§12.3 priority order) plus per-check details.
//
// In-scope for Verifier v0.2.0 (Stage E.1.d):
//
//	§12.1 check  1  manifest.json present                     MANIFEST_MISSING
//	§12.1 check  3  manifest.sig present                      SIGNATURE_MISSING
//	§12.1 check  4  Ed25519 signature valid                   INVALID_SIGNATURE
//	§12.1 check  5  canonical manifest hash matches .sig      MANIFEST_TAMPERED
//	§12.1 check  6  artifacts[].stored_path present           FILE_MISSING
//	§12.1 check  7  artifacts[].sha256 matches stored file    HASH_MISMATCH
//	§12.1 check  8  no undeclared files in artifacts/derived  FILE_ADDED
//	§12.1 check 11  root directory name == manifest.bundle_id (folded into manifest_present)
//	§12.1 check 12  .sig.public_key_pem == meta/signing_key   (folded into signature_valid)
//	§12.1 check 13  no internal_only in disclosure/sanitized  POLICY_VIOLATION
//
// Deferred to Stage E.1.f (audit + TSR layer):
//
//	§12.1 check  9  audit/events.jsonl chain unbroken         AUDIT_CHAIN_BROKEN
//	§12.1 check 10  manifest.tsr RFC 3161 structural          TIMESTAMP_INVALID

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ── Result codes (§12.3) ─────────────────────────────────────────────────────

const (
	CodeValid             = "VALID"
	CodeSchemaUnsupported = "SCHEMA_UNSUPPORTED"
	CodeManifestMissing   = "MANIFEST_MISSING"
	CodeSignatureMissing  = "SIGNATURE_MISSING"
	CodeInvalidSignature  = "INVALID_SIGNATURE"
	CodeManifestTampered  = "MANIFEST_TAMPERED"
	CodeHashMismatch      = "HASH_MISMATCH"
	CodeFileMissing       = "FILE_MISSING"
	CodeFileAdded         = "FILE_ADDED"
	CodeAuditChainBroken  = "AUDIT_CHAIN_BROKEN"
	CodeTimestampInvalid  = "TIMESTAMP_INVALID"
	CodeTimestampMissing  = "TIMESTAMP_MISSING"
	CodePolicyViolation   = "POLICY_VIOLATION"
	CodeDerivedArtifact   = "DERIVED_ARTIFACT"

	resultPass = "PASS"
	resultFail = "FAIL"
	resultSkip = "SKIPPED"

	verdictPass = "PASS"
	verdictFail = "FAIL"

	formatV1 = "Evidence Bundle v1.0"
)

// codePriority maps §12.3 priority order (highest dominates).
var codePriority = map[string]int{
	CodeSchemaUnsupported: 100,
	CodeManifestMissing:   90,
	CodeSignatureMissing:  80,
	CodeInvalidSignature:  70,
	CodeManifestTampered:  60,
	CodeHashMismatch:      50,
	CodeFileMissing:       40,
	CodeFileAdded:         30,
	CodeAuditChainBroken:  25,
	CodeTimestampInvalid:  20,
	CodeTimestampMissing:  15,
	CodePolicyViolation:   10,
	CodeDerivedArtifact:   5,
	CodeValid:             0,
}

// ── Check / Verdict structs ──────────────────────────────────────────────────

// CheckResult is the verdict on one §12.1 check. Field order matches the
// CKNF legalpack.CheckResult so JSON consumers can share a renderer.
type CheckResult struct {
	Name    string `json:"name"`
	Result  string `json:"result"`            // "PASS" / "FAIL" / "SKIPPED"
	Detail  string `json:"detail,omitempty"`  // populated on PASS
	Error   string `json:"error,omitempty"`   // populated only on FAIL
	Skipped string `json:"skipped,omitempty"` // populated only on SKIPPED
}

// Verdict is the full result of one bundle verification run.
type Verdict struct {
	Format        string        `json:"format"`
	BundleID      string        `json:"bundle_id,omitempty"`
	PackageClass  string        `json:"package_class,omitempty"`
	Product       string        `json:"product,omitempty"`
	ResultCode    string        `json:"result_code"`
	OverallResult string        `json:"verdict"` // PASS / FAIL
	Checks        []CheckResult `json:"checks"`
	Summary       string        `json:"summary"`
	ArtifactCount int           `json:"artifact_count"`
}

// VerifyOptions controls bundle-verify orchestration. Reserved for future
// flags (e.g. trust-root path, strict mode).
type VerifyOptions struct{}

// Check names (stable across releases — JSON consumers may key off these).
const (
	checkManifestPresent     = "manifest_present"
	checkSignaturePresent    = "signature_present"
	checkSignatureValid      = "signature_valid"
	checkManifestHashMatches = "manifest_hash_matches"
	checkArtifactsPresent    = "artifacts_present"
	checkArtifactHashes      = "artifact_hashes"
	checkNoUndeclaredFiles   = "no_undeclared_files"
	checkAuditChain          = "audit_chain"
	checkTimestamp           = "timestamp_token"
	checkPolicyCompliance    = "policy_compliance"
)

// ── Public entry point ───────────────────────────────────────────────────────

// VerifyBundle runs every §12.1 check in scope and returns a Verdict. The
// function never panics on a malformed bundle: structural errors at Open /
// manifest-read stage are reflected as FAIL checks inside the Verdict.
func VerifyBundle(bundlePath string, _ VerifyOptions) (*Verdict, error) {
	r, err := Open(bundlePath)
	if err != nil {
		return &Verdict{
			Format:        formatV1,
			ResultCode:    CodeManifestMissing,
			OverallResult: verdictFail,
			Checks: []CheckResult{{
				Name:   checkManifestPresent,
				Result: resultFail,
				Error:  err.Error(),
			}},
			Summary: "bundle could not be opened",
		}, nil
	}
	defer r.Close()

	v := &Verdict{Format: formatV1}

	// §12.1 check 1 + §5 root-dir name (folds in check 11).
	manifest, mfCheck := loadAndCheckManifest(r)
	v.Checks = append(v.Checks, mfCheck)
	if mfCheck.Result == resultFail {
		v.finalize(CodeManifestMissing)
		return v, nil
	}
	v.BundleID = manifest.BundleID
	v.PackageClass = manifest.PackageClass
	v.Product = manifest.Product
	v.ArtifactCount = manifest.ArtifactCount

	// §12.1 check 3.
	sig, sigPresent := loadAndCheckSignature(r)
	v.Checks = append(v.Checks, sigPresent)
	if sigPresent.Result == resultFail {
		v.finalize(CodeSignatureMissing)
		return v, nil
	}

	// §12.1 check 4 (+ folded check 12: meta/signing_key.pub.pem match).
	sigValid := checkSignatureCryptography(r, sig)
	v.Checks = append(v.Checks, sigValid)
	if sigValid.Result == resultFail {
		v.finalize(CodeInvalidSignature)
		return v, nil
	}

	// §12.1 check 5.
	hashMatch := checkManifestHash(manifest, sig)
	v.Checks = append(v.Checks, hashMatch)
	if hashMatch.Result == resultFail {
		v.finalize(CodeManifestTampered)
		return v, nil
	}

	// §12.1 check 6.
	filesPresent := checkArtifactFilesPresent(r, manifest)
	v.Checks = append(v.Checks, filesPresent)
	if filesPresent.Result == resultFail {
		v.finalize(CodeFileMissing)
		return v, nil
	}

	// §12.1 check 7.
	hashes := checkArtifactSHA256(r, manifest)
	v.Checks = append(v.Checks, hashes)
	if hashes.Result == resultFail {
		v.finalize(CodeHashMismatch)
		return v, nil
	}

	// §12.1 check 8.
	noExtra := checkNoExtraFiles(r, manifest)
	v.Checks = append(v.Checks, noExtra)
	if noExtra.Result == resultFail {
		v.finalize(CodeFileAdded)
		return v, nil
	}

	// §12.1 checks 9 + 10 — deferred to Stage E.1.f.
	v.Checks = append(v.Checks, CheckResult{
		Name:    checkAuditChain,
		Result:  resultSkip,
		Skipped: "audit chain verification deferred to Stage E.1.f",
	})
	v.Checks = append(v.Checks, timestampSkippedFor(r))

	// §12.1 check 13.
	policy := checkPolicyState(manifest)
	v.Checks = append(v.Checks, policy)
	if policy.Result == resultFail {
		v.finalize(CodePolicyViolation)
		return v, nil
	}

	v.finalize(CodeValid)
	return v, nil
}

// ── Individual checks ────────────────────────────────────────────────────────

func loadAndCheckManifest(r *Reader) (*Manifest, CheckResult) {
	if !r.HasEntry(EntryManifestJSON) {
		return nil, CheckResult{
			Name:   checkManifestPresent,
			Result: resultFail,
			Error:  fmt.Sprintf("required entry %q not in bundle", EntryManifestJSON),
		}
	}
	data, err := r.ReadEntry(EntryManifestJSON)
	if err != nil {
		return nil, CheckResult{
			Name:   checkManifestPresent,
			Result: resultFail,
			Error:  fmt.Sprintf("read manifest.json: %v", err),
		}
	}
	m, err := ParseManifest(data)
	if err != nil {
		return nil, CheckResult{
			Name:   checkManifestPresent,
			Result: resultFail,
			Error:  fmt.Sprintf("parse manifest.json: %v", err),
		}
	}
	// §5 rule 3 / §12.1 check 11: root dir name == manifest.bundle_id.
	if r.RootDir() != m.BundleID {
		return nil, CheckResult{
			Name:   checkManifestPresent,
			Result: resultFail,
			Error: fmt.Sprintf(
				"bundle root directory %q does not match manifest.bundle_id %q",
				r.RootDir(), m.BundleID),
		}
	}
	return m, CheckResult{
		Name:   checkManifestPresent,
		Result: resultPass,
		Detail: fmt.Sprintf("manifest.json valid, bundle_id=%s, %d artifact(s)", m.BundleID, m.ArtifactCount),
	}
}

func loadAndCheckSignature(r *Reader) (*ManifestSignature, CheckResult) {
	if !r.HasEntry(EntryManifestSig) {
		return nil, CheckResult{
			Name:   checkSignaturePresent,
			Result: resultFail,
			Error:  fmt.Sprintf("required entry %q not in bundle", EntryManifestSig),
		}
	}
	data, err := r.ReadEntry(EntryManifestSig)
	if err != nil {
		return nil, CheckResult{
			Name:   checkSignaturePresent,
			Result: resultFail,
			Error:  fmt.Sprintf("read manifest.sig: %v", err),
		}
	}
	sig, err := ParseManifestSignature(data)
	if err != nil {
		return nil, CheckResult{
			Name:   checkSignaturePresent,
			Result: resultFail,
			Error:  fmt.Sprintf("parse manifest.sig: %v", err),
		}
	}
	return sig, CheckResult{
		Name:   checkSignaturePresent,
		Result: resultPass,
		Detail: fmt.Sprintf("manifest.sig valid (signer=%s)", sig.PublicKeyID),
	}
}

func checkSignatureCryptography(r *Reader, sig *ManifestSignature) CheckResult {
	if !r.HasEntry(EntryMetaSigningKey) {
		return CheckResult{
			Name:   checkSignatureValid,
			Result: resultFail,
			Error:  fmt.Sprintf("required entry %q not in bundle", EntryMetaSigningKey),
		}
	}
	metaPEM, err := r.ReadEntry(EntryMetaSigningKey)
	if err != nil {
		return CheckResult{
			Name:   checkSignatureValid,
			Result: resultFail,
			Error:  fmt.Sprintf("read meta/signing_key.pub.pem: %v", err),
		}
	}
	if !bytes.Equal(bytes.TrimRight(metaPEM, "\r\n "), bytes.TrimRight([]byte(sig.PublicKeyPEM), "\r\n ")) {
		return CheckResult{
			Name:   checkSignatureValid,
			Result: resultFail,
			Error:  "embedded manifest.sig.public_key_pem does not match meta/signing_key.pub.pem",
		}
	}
	pub, err := LoadPublicKeyPEM(sig.PublicKeyPEM)
	if err != nil {
		return CheckResult{
			Name:   checkSignatureValid,
			Result: resultFail,
			Error:  fmt.Sprintf("load public key: %v", err),
		}
	}
	if !VerifySignature(pub, sig.ManifestHash, sig.Signature) {
		return CheckResult{
			Name:   checkSignatureValid,
			Result: resultFail,
			Error:  "Ed25519 signature verification failed",
		}
	}
	return CheckResult{
		Name:   checkSignatureValid,
		Result: resultPass,
		Detail: fmt.Sprintf("Ed25519 signature valid (signed_at=%s)", sig.SignedAt),
	}
}

func checkManifestHash(m *Manifest, sig *ManifestSignature) CheckResult {
	computed, err := m.Hash()
	if err != nil {
		return CheckResult{
			Name:   checkManifestHashMatches,
			Result: resultFail,
			Error:  fmt.Sprintf("compute canonical manifest hash: %v", err),
		}
	}
	if computed != sig.ManifestHash {
		return CheckResult{
			Name:   checkManifestHashMatches,
			Result: resultFail,
			Error: fmt.Sprintf(
				"canonical manifest_hash mismatch:\n  computed: %s\n  signed:   %s",
				computed, sig.ManifestHash),
		}
	}
	return CheckResult{
		Name:   checkManifestHashMatches,
		Result: resultPass,
		Detail: fmt.Sprintf("canonical manifest_hash matches signed value (%s…)", computed[:16]),
	}
}

func checkArtifactFilesPresent(r *Reader, m *Manifest) CheckResult {
	var missing []string
	for i, a := range m.Artifacts {
		storedPath, _ := a["stored_path"].(string)
		if storedPath == "" {
			return CheckResult{
				Name:   checkArtifactsPresent,
				Result: resultFail,
				Error:  fmt.Sprintf("artifacts[%d].stored_path is missing or not a string", i),
			}
		}
		if !r.HasEntry(storedPath) {
			missing = append(missing, storedPath)
		}
	}
	if len(missing) > 0 {
		return CheckResult{
			Name:   checkArtifactsPresent,
			Result: resultFail,
			Error:  fmt.Sprintf("%d artifact file(s) missing on disk: %v", len(missing), missing),
		}
	}
	return CheckResult{
		Name:   checkArtifactsPresent,
		Result: resultPass,
		Detail: fmt.Sprintf("all %d artifact file(s) present", len(m.Artifacts)),
	}
}

func checkArtifactSHA256(r *Reader, m *Manifest) CheckResult {
	var mismatches []string
	for i, a := range m.Artifacts {
		storedPath, _ := a["stored_path"].(string)
		want, _ := a["sha256"].(string)
		if want == "" {
			return CheckResult{
				Name:   checkArtifactHashes,
				Result: resultFail,
				Error:  fmt.Sprintf("artifacts[%d].sha256 is missing or not a string", i),
			}
		}
		data, err := r.ReadEntry(storedPath)
		if err != nil {
			return CheckResult{
				Name:   checkArtifactHashes,
				Result: resultFail,
				Error:  fmt.Sprintf("read artifact %q: %v", storedPath, err),
			}
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if got != want {
			mismatches = append(mismatches,
				fmt.Sprintf("%s: want=%s got=%s", storedPath, want, got))
		}
	}
	if len(mismatches) > 0 {
		return CheckResult{
			Name:   checkArtifactHashes,
			Result: resultFail,
			Error:  fmt.Sprintf("%d artifact hash mismatch(es):\n  %s", len(mismatches), strings.Join(mismatches, "\n  ")),
		}
	}
	return CheckResult{
		Name:   checkArtifactHashes,
		Result: resultPass,
		Detail: fmt.Sprintf("all %d artifact SHA-256 value(s) match", len(m.Artifacts)),
	}
}

func checkNoExtraFiles(r *Reader, m *Manifest) CheckResult {
	declared := make(map[string]struct{}, len(m.Artifacts))
	for _, a := range m.Artifacts {
		if p, ok := a["stored_path"].(string); ok {
			declared[p] = struct{}{}
		}
	}
	var extras []string
	for _, e := range r.Entries() {
		if !strings.HasPrefix(e, DirArtifacts) && !strings.HasPrefix(e, DirDerived) {
			continue
		}
		if _, ok := declared[e]; !ok {
			extras = append(extras, e)
		}
	}
	if len(extras) > 0 {
		sort.Strings(extras)
		return CheckResult{
			Name:   checkNoUndeclaredFiles,
			Result: resultFail,
			Error:  fmt.Sprintf("%d undeclared file(s) in artifacts/ or derived/: %v", len(extras), extras),
		}
	}
	return CheckResult{
		Name:   checkNoUndeclaredFiles,
		Result: resultPass,
		Detail: "no undeclared files under artifacts/ or derived/",
	}
}

func checkPolicyState(m *Manifest) CheckResult {
	if m.PackageClass != "disclosure" && m.PackageClass != "sanitized" {
		return CheckResult{
			Name:   checkPolicyCompliance,
			Result: resultPass,
			Detail: fmt.Sprintf("package_class=%s — no internal_only restriction", m.PackageClass),
		}
	}
	var offenders []string
	for _, a := range m.Artifacts {
		if s, _ := a["policy_state"].(string); s == "internal_only" {
			id, _ := a["artifact_id"].(string)
			offenders = append(offenders, id)
		}
	}
	if len(offenders) > 0 {
		return CheckResult{
			Name:   checkPolicyCompliance,
			Result: resultFail,
			Error: fmt.Sprintf(
				"%d artifact(s) marked internal_only in %s package: %v",
				len(offenders), m.PackageClass, offenders),
		}
	}
	return CheckResult{
		Name:   checkPolicyCompliance,
		Result: resultPass,
		Detail: fmt.Sprintf("no internal_only artifacts in %s package", m.PackageClass),
	}
}

func timestampSkippedFor(r *Reader) CheckResult {
	if r.HasEntry(EntryManifestTSR) {
		return CheckResult{
			Name:    checkTimestamp,
			Result:  resultSkip,
			Skipped: "manifest.tsr present; RFC 3161 verification deferred to Stage E.1.f",
		}
	}
	return CheckResult{
		Name:    checkTimestamp,
		Result:  resultSkip,
		Skipped: "no manifest.tsr in bundle (timestamp absent)",
	}
}

// ── Finalisation ─────────────────────────────────────────────────────────────

func (v *Verdict) finalize(primary string) {
	v.ResultCode = primary
	if primary == CodeValid {
		v.OverallResult = verdictPass
	} else {
		v.OverallResult = verdictFail
	}
	failed, skipped := 0, 0
	for _, c := range v.Checks {
		switch c.Result {
		case resultFail:
			failed++
		case resultSkip:
			skipped++
		}
	}
	switch {
	case failed == 0 && skipped == 0:
		v.Summary = fmt.Sprintf("All %d checks passed. Bundle %s is forensically intact.",
			len(v.Checks), v.BundleID)
	case failed == 0:
		v.Summary = fmt.Sprintf("%d checks passed, %d skipped. Bundle %s is intact within verifiable scope.",
			len(v.Checks)-skipped, skipped, v.BundleID)
	default:
		v.Summary = fmt.Sprintf("%d check(s) FAILED — primary code %s.", failed, primary)
	}
}

// PriorityOf returns the §12.3 priority of a result code (higher dominates).
func PriorityOf(code string) int {
	return codePriority[code]
}
