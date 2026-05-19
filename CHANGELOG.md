# Changelog

All notable changes to `forensicdata-verifier` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — feature-complete for v0.1.0 on 2026-05-19

- `verifier verify license <string>` — license format-and-checksum check
  (Option β, NOT HMAC authenticity — see README §Risk #1).
- `verifier verify legal-pack <path.zip> [--tsr <path>] [--format=human|json]`
  — orchestrator covering four checks:
  - `audio_sha256`        : audio bytes hash to sha256_report.txt claim
  - `verification_qr`     : QR payload matches sha256_report.txt
  - `audit_jsonl_chain`   : audit.jsonl well-formed; chain validated if signed
  - `tsa_rfc3161`         : RFC 3161 TSR hashed-message matches audio SHA-256
- `internal/canonicaljson` — byte-exact Go port of CKNF Python
  `cknf.ntp_trust.canonical_json`. 18 golden vectors verified against
  Python output (byte-exact + SHA-256 hash-exact).
- `internal/tsa` — RFC 3161 TSR parser using digitorus/timestamp
  (battle-tested in Sigstore/Cosign). Verifies hashed-message;
  signature/trust-chain verification deferred to v0.2.0.
- `internal/report` — human (color/ANSI) and JSON renderers.

### Not in v0.1.0 (deferred to v0.2.0+)

- TSR cryptographic signature verification against a bundled trust-root
  list (freetsa, DigiCert). v0.1.0 verifies the digest binding only.
- License HMAC-authenticity — kept out by design to avoid secret exposure
  in the open-source binary.
- FDS-Seal JSON verification, FDC-Diff verification.
- Sovereign-Pack v1/v2/v3 (Hebel-4 container format, post-CKNF v2.5.0).

### Test count

112 tests passing across 4 packages:
- `internal/license`        : 23 tests (format parse + boundary)
- `internal/legalpack`      : 65 tests (reader + sha256_report + verify_audio + QR + audit_chain + orchestrator)
- `internal/canonicaljson`  : 41 sub-tests (golden vectors + defensive)
- `internal/tsa`            : 12 tests (parse + digest match + round-trip)

## [0.1.0] — TBD (target: 2026-07-01 with CKNF Suite v2.4.0-Final)

Pending: cross-platform binaries (darwin-amd64/arm64, linux-amd64/arm64,
windows-amd64) via goreleaser + GitHub Release.
