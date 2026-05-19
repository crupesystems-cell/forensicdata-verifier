// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package legalpack

import (
	"fmt"

	"github.com/crupesystems-cell/forensicdata-verifier/internal/tsa"
)

// CheckResult is the verdict on one individual verification step. Results
// are reported in a fixed order so JSON and human output remain stable.
type CheckResult struct {
	Name    string `json:"name"`
	Result  string `json:"result"`            // "PASS" / "FAIL" / "SKIPPED"
	Detail  string `json:"detail,omitempty"`  // short success summary
	Error   string `json:"error,omitempty"`   // populated only on FAIL
	Skipped string `json:"skipped,omitempty"` // populated only on SKIPPED
}

// Verdict summarises the full Legal-Pack verification.
type Verdict struct {
	Format        string             `json:"format"`
	OverallResult string             `json:"verdict"` // "PASS" / "FAIL"
	Checks        []CheckResult      `json:"checks"`
	Summary       string             `json:"summary"`
	AuditCount    int                `json:"audit_event_count"`
	AuditSigned   bool               `json:"audit_signed"`
	TSAReport     *tsa.TimestampInfo `json:"tsa,omitempty"`
	RecordingID   string             `json:"recording_id,omitempty"`
}

// VerifyOptions controls the legal-pack orchestration.
type VerifyOptions struct {
	// TSRPath is optional. When set, the orchestrator parses the TSR and
	// verifies its hashed-message field equals the audio SHA-256 from
	// sha256_report.txt. When empty, the TSA check is SKIPPED — TSR absence
	// is a legal state of CKNF recordings.
	TSRPath string
}

const (
	checkAudio = "audio_sha256"
	checkQR    = "verification_qr"
	checkAudit = "audit_jsonl_chain"
	checkTSA   = "tsa_rfc3161"
	formatV1   = "CKNF Legal-Pack v1"

	resultPass = "PASS"
	resultFail = "FAIL"
	resultSkip = "SKIPPED"

	verdictPass = "PASS"
	verdictFail = "FAIL"
)

// VerifyLegalPack runs every check in the v0.1.0 scope and returns a
// Verdict. The function never panics on a malformed pack: structural
// errors at Open / sha256_report-read stage are surfaced via the returned
// error (with no Verdict). Per-check failures are reported inside the
// Verdict with OverallResult="FAIL".
func VerifyLegalPack(packPath string, opts VerifyOptions) (*Verdict, error) {
	pack, err := Open(packPath)
	if err != nil {
		return nil, fmt.Errorf("verify legal-pack: %w", err)
	}
	defer pack.Close()

	if !pack.IsValidStructure() {
		return nil, fmt.Errorf(
			"verify legal-pack: pack is missing required entries: %v",
			pack.MissingEntries(),
		)
	}

	reportBytes, err := pack.ReadEntry(EntrySha256Report)
	if err != nil {
		return nil, fmt.Errorf("verify legal-pack: read sha256_report: %w", err)
	}
	report, err := ParseSha256Report(reportBytes)
	if err != nil {
		return nil, fmt.Errorf("verify legal-pack: parse sha256_report: %w", err)
	}

	verdict := &Verdict{
		Format:      formatV1,
		RecordingID: report.RecordingID,
	}

	verdict.appendCheck(runAudio(pack, report))
	verdict.appendCheck(runQR(pack, report))

	auditReport, auditCheck := runAudit(pack)
	verdict.appendCheck(auditCheck)
	if auditReport != nil {
		verdict.AuditCount = auditReport.Count
		verdict.AuditSigned = auditReport.Signed
	}

	tsaInfo, tsaCheck := runTSA(opts.TSRPath, report.SHA256)
	verdict.appendCheck(tsaCheck)
	verdict.TSAReport = tsaInfo

	verdict.finalize()
	return verdict, nil
}

func (v *Verdict) appendCheck(c CheckResult) {
	v.Checks = append(v.Checks, c)
}

func (v *Verdict) finalize() {
	failed := 0
	skipped := 0
	for _, c := range v.Checks {
		switch c.Result {
		case resultFail:
			failed++
		case resultSkip:
			skipped++
		}
	}
	if failed == 0 {
		v.OverallResult = verdictPass
	} else {
		v.OverallResult = verdictFail
	}
	switch {
	case failed == 0 && skipped == 0:
		v.Summary = fmt.Sprintf("All %d checks passed. Legal-Pack is forensically intact.", len(v.Checks))
	case failed == 0:
		v.Summary = fmt.Sprintf("%d checks passed, %d skipped. Legal-Pack is intact within verifiable scope.",
			len(v.Checks)-skipped, skipped)
	default:
		v.Summary = fmt.Sprintf("%d check(s) FAILED. Legal-Pack is NOT forensically intact.", failed)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Individual check wrappers
// ─────────────────────────────────────────────────────────────────────────────

func runAudio(pack *Pack, report *Sha256Report) CheckResult {
	if err := VerifyAudioSHA256(pack, report); err != nil {
		return CheckResult{Name: checkAudio, Result: resultFail, Error: err.Error()}
	}
	return CheckResult{
		Name:   checkAudio,
		Result: resultPass,
		Detail: fmt.Sprintf("SHA-256 of %s matches sha256_report.txt", pack.AudioEntry()),
	}
}

func runQR(pack *Pack, report *Sha256Report) CheckResult {
	if err := VerifyQR(pack, report); err != nil {
		return CheckResult{Name: checkQR, Result: resultFail, Error: err.Error()}
	}
	return CheckResult{
		Name:   checkQR,
		Result: resultPass,
		Detail: "verification_qr.png payload is consistent with sha256_report.txt",
	}
}

func runAudit(pack *Pack) (*AuditReport, CheckResult) {
	report, err := VerifyAuditJSONL(pack)
	if err != nil {
		return report, CheckResult{Name: checkAudit, Result: resultFail, Error: err.Error()}
	}
	if report.Count == 0 {
		return report, CheckResult{
			Name:    checkAudit,
			Result:  resultSkip,
			Skipped: "audit.jsonl is empty (legacy pack)",
		}
	}
	if !report.Signed {
		return report, CheckResult{
			Name:    checkAudit,
			Result:  resultSkip,
			Skipped: fmt.Sprintf("%d events present but no per-event hash chain (CKNF v2.3 schema)", report.Count),
		}
	}
	return report, CheckResult{
		Name:   checkAudit,
		Result: resultPass,
		Detail: fmt.Sprintf("%d events, hash chain valid", report.Count),
	}
}

func runTSA(tsrPath, expectedSHA256 string) (*tsa.TimestampInfo, CheckResult) {
	if tsrPath == "" {
		return nil, CheckResult{
			Name:    checkTSA,
			Result:  resultSkip,
			Skipped: "no --tsr path provided (CKNF stores original.tsr alongside the pack, not inside it)",
		}
	}
	info, err := tsa.ParseFile(tsrPath)
	if err != nil {
		return nil, CheckResult{Name: checkTSA, Result: resultFail, Error: err.Error()}
	}
	if err := tsa.VerifyDigest(info, expectedSHA256); err != nil {
		return info, CheckResult{Name: checkTSA, Result: resultFail, Error: err.Error()}
	}
	detail := fmt.Sprintf("TSA serial=%s, genTime=%s", info.SerialNumber, info.GenTime)
	if info.SigningCertSubject != "" {
		detail += ", signer=" + info.SigningCertSubject
	}
	return info, CheckResult{Name: checkTSA, Result: resultPass, Detail: detail}
}
