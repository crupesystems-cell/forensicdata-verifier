// Copyright 2026 WBR IP & License Holding Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// forensicdata-verifier — Independent verifier for CKNF / FDC / FDS forensic packs.
//
// See README.md for the full scope and `verifier --help` for the CLI surface.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/crupesystems-cell/forensicdata-verifier/cmd"
)

// version is overridden at build time via -ldflags "-X main.version=v0.2.0".
// The identifier is lowercase to match the goreleaser ldflags injection
// declared in .goreleaser.yaml. Default reflects local-dev builds.
var version = "v0.0.0-dev"

func main() {
	root := &cobra.Command{
		Use:   "verifier",
		Short: "Independent verifier for CKNF / FDC / FDS forensic packs",
		Long: `forensicdata-verifier

Cryptographically verifies forensic evidence packs produced by the
Consilium CKNF / FORensicData Clean / FORensicData Seal suite — with no
suite software installation required.

A single static binary, offline, no account, no telemetry.

Verification scope (v0.2.0):
  verify legal-pack <path.zip>   Full CKNF Legal-Pack integrity check
  verify bundle <path.zip>       Evidence Bundle (Bundle-Spec v1.0)
                                 manifest + Ed25519 signature + artifact hashes
  verify license <string>        License format + checksum (NOT authenticity)
  inspect <path>                 Schema-only output, no verification

See https://github.com/<placeholder>/forensicdata-verifier for full docs.`,
	}

	root.AddCommand(versionCmd())
	root.AddCommand(cmd.VerifyCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print verifier version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println(version)
		},
	}
}
