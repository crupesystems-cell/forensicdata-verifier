// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/crupesystems-cell/forensicdata-verifier/internal/license"
)

// VerifyLicenseCmd returns the `verifier verify license <string>` subcommand.
//
// Scope reminder: per 12_PLAN_VERIFIER_CLI__v1.md §7 Risk #1 Option β, this
// command checks STRUCTURAL FORMAT ONLY. It deliberately does not verify
// HMAC authenticity — shipping the issuing secret in an open-source binary
// would expose it. Operators who need authenticity verification must call
// the CKNF issuing service.
func VerifyLicenseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "license <license-string>",
		Short: "Validate a license string's structural format (NOT HMAC authenticity)",
		Long: `Validate the structural format of a Consilium / FORensicData
license string.

This checks that the string matches the expected layout:
  PREFIX(4 A-Z)-TIER(L|T)PROGRAMS(3 A-Z)SERIAL(5 digits)-CHECKSUM(8 hex)

Example: CKNF-LCFS15022-6FBF59ED

This command does NOT verify that the license was actually issued by the
CKNF service. Authenticity verification requires the issuing service's
HMAC secret, which is deliberately not bundled in this open-source
binary. Use this command to catch transcription errors and obviously
malformed inputs; use the issuing service to confirm authenticity.

Exit codes:
  0  format valid
  1  format invalid (or serial below canonical range)
  2  no argument provided`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			lic, err := license.Parse(args[0])
			if err != nil {
				fmt.Fprintf(os.Stderr, "✗ %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("✓ %s\n", lic.Describe())
			fmt.Println("  (authenticity verification requires the CKNF issuing service)")
			if lic.SerialOutOfRange {
				// SerialOutOfRange is a soft warning, not a hard failure —
				// the format is technically valid. Still surface it.
				os.Exit(1)
			}
			return nil
		},
	}
}

// VerifyCmd returns the top-level `verifier verify <subcommand>` grouping.
// Additional subcommands (legal-pack, seal, …) are added by their own files.
func VerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a license string, legal-pack, or seal",
	}
	cmd.AddCommand(VerifyLicenseCmd())
	cmd.AddCommand(VerifyLegalPackCmd())
	return cmd
}
