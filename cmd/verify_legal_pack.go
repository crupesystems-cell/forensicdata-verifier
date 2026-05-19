// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/crupesystems-cell/forensicdata-verifier/internal/legalpack"
	"github.com/crupesystems-cell/forensicdata-verifier/internal/report"
)

// VerifyLegalPackCmd returns the `verifier verify legal-pack <path.zip>`
// subcommand.
//
// Exit codes:
//
//	0  verification PASS
//	1  verification FAIL (one or more checks failed)
//	2  input format error (pack unreadable / structurally invalid)
func VerifyLegalPackCmd() *cobra.Command {
	var (
		tsrPath string
		format  string
		noColor bool
	)
	cmd := &cobra.Command{
		Use:   "legal-pack <path.zip>",
		Short: "Verify a CKNF Legal-Pack ZIP",
		Long: `Verify the forensic integrity of a CKNF Legal-Pack ZIP.

Checks performed (v0.1.0):
  - audio_sha256       : audio bytes inside the ZIP hash to the value
                         claimed in sha256_report.txt.
  - verification_qr    : the QR's id/sha256/chain_hash payload matches
                         sha256_report.txt.
  - audit_jsonl_chain  : audit.jsonl is well-formed; if per-event
                         hash-chain fields are present, the chain is
                         cryptographically verified. CKNF v2.3 packs
                         use an unsigned schema; this check then
                         reports SKIPPED.
  - tsa_rfc3161        : when --tsr is provided, the RFC 3161 token's
                         hashed-message field matches the audio
                         SHA-256. Without --tsr the check is SKIPPED;
                         CKNF stores original.tsr alongside the pack,
                         not inside it.

NOT in v0.1.0 (deferred to v0.2.0+):
  - TSR signature verification against a bundled trust-root list
  - License HMAC-authenticity (kept out by design — see README §Risk #1)
  - FDS-Seal / FDC-Diff / Sovereign-Pack formats

Exit codes:
  0  PASS
  1  FAIL
  2  input format error`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			v, err := legalpack.VerifyLegalPack(args[0], legalpack.VerifyOptions{
				TSRPath: tsrPath,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "✗ %s\n", err)
				os.Exit(2)
			}

			useColor := !noColor && isTerminal(os.Stdout)
			switch format {
			case "json":
				if err := report.JSON(os.Stdout, v); err != nil {
					return fmt.Errorf("render json: %w", err)
				}
			case "human", "":
				if err := report.Human(os.Stdout, v, useColor); err != nil {
					return fmt.Errorf("render human: %w", err)
				}
			default:
				return fmt.Errorf("unknown --format %q (expected 'human' or 'json')", format)
			}

			if v.OverallResult != "PASS" {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tsrPath, "tsr", "",
		"path to the RFC 3161 .tsr file that accompanies this Legal-Pack (optional)")
	cmd.Flags().StringVar(&format, "format", "human",
		"output format: human or json")
	cmd.Flags().BoolVar(&noColor, "no-color", false,
		"disable ANSI color codes even on a TTY")
	return cmd
}

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
