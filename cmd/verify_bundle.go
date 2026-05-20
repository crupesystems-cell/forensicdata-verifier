// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/crupesystems-cell/forensicdata-verifier/internal/bundle"
	"github.com/crupesystems-cell/forensicdata-verifier/internal/report"
)

// exitCodeFor maps Bundle-Spec v1.0 §12.3 result codes to CLI exit codes.
// Values copied verbatim from the spec table.
var exitCodeFor = map[string]int{
	bundle.CodeValid:             0,
	bundle.CodeSchemaUnsupported: 10,
	bundle.CodeManifestMissing:   11,
	bundle.CodeSignatureMissing:  12,
	bundle.CodeInvalidSignature:  20,
	bundle.CodeHashMismatch:      21,
	bundle.CodeFileMissing:       22,
	bundle.CodeFileAdded:         23,
	bundle.CodeManifestTampered:  24,
	bundle.CodeAuditChainBroken:  25,
	bundle.CodeTimestampInvalid:  26,
	bundle.CodeTimestampMissing:  30,
	bundle.CodePolicyViolation:   32,
	bundle.CodeDerivedArtifact:   40,
}

// VerifyBundleCmd returns the `verifier verify bundle <path.zip>` subcommand.
//
// Implements Bundle-Spec v1.0 §12 verification — the manifest / signature /
// artifact integrity layer. Audit-chain (§12.1 #9) and RFC 3161 (§12.1 #10)
// verification are deferred to Stage E.1.f and reported as SKIPPED.
//
// Exit codes follow §12.3 verbatim.
func VerifyBundleCmd() *cobra.Command {
	var (
		format  string
		noColor bool
	)
	cmd := &cobra.Command{
		Use:   "bundle <path.zip>",
		Short: "Verify an Evidence Bundle (Bundle-Spec v1.0)",
		Long: `Verify the forensic integrity of an Evidence Bundle ZIP per
Bundle-Spec v1.0.

Checks performed (in scope for v0.2.0):
  - manifest_present       : manifest.json is present, schema-valid, and the
                             bundle root directory matches manifest.bundle_id.
  - signature_present      : manifest.sig is present and schema-valid.
  - signature_valid        : embedded public_key_pem matches
                             meta/signing_key.pub.pem, and the Ed25519
                             signature over the manifest hash verifies.
  - manifest_hash_matches  : the canonical hash of manifest.json equals
                             manifest.sig.manifest_hash (detects
                             MANIFEST_TAMPERED).
  - artifacts_present      : every artifacts[].stored_path exists in the ZIP.
  - artifact_hashes        : every artifacts[].sha256 matches the SHA-256
                             of the stored file.
  - no_undeclared_files    : nothing under artifacts/ or derived/ is
                             absent from manifest.artifacts[].
  - policy_compliance      : in disclosure/sanitized packages, no
                             artifact carries policy_state=internal_only.

Deferred to Stage E.1.f (reported as SKIPPED):
  - audit_chain            : audit/events.jsonl hash-chain integrity.
  - timestamp_token        : manifest.tsr RFC 3161 structural validation.

Exit codes (Bundle-Spec §12.3):
   0  VALID
  10  SCHEMA_UNSUPPORTED
  11  MANIFEST_MISSING
  12  SIGNATURE_MISSING
  20  INVALID_SIGNATURE
  21  HASH_MISMATCH
  22  FILE_MISSING
  23  FILE_ADDED
  24  MANIFEST_TAMPERED
  32  POLICY_VIOLATION
   2  input/format error`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			v, err := bundle.VerifyBundle(args[0], bundle.VerifyOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "✗ %s\n", err)
				os.Exit(2)
			}

			useColor := !noColor && isTerminal(os.Stdout)
			switch format {
			case "json":
				if err := report.JSONBundle(os.Stdout, v); err != nil {
					return fmt.Errorf("render json: %w", err)
				}
			case "human", "":
				if err := report.HumanBundle(os.Stdout, v, useColor); err != nil {
					return fmt.Errorf("render human: %w", err)
				}
			default:
				return fmt.Errorf("unknown --format %q (expected 'human' or 'json')", format)
			}

			exit, ok := exitCodeFor[v.ResultCode]
			if !ok {
				exit = 2
			}
			if exit != 0 {
				os.Exit(exit)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "human",
		"output format: human or json")
	cmd.Flags().BoolVar(&noColor, "no-color", false,
		"disable ANSI color codes even on a TTY")
	return cmd
}
