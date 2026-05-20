# Changelog

All notable changes to `forensicdata-verifier` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.2.1] — 2026-05-22

### Added — Stage E.1.f: audit-chain + RFC 3161 TSR-digest verification

Completes the two Bundle-Spec v1.0 §12.1 mandatory checks that were
deferred in v0.2.0:

- §12.1 check  9 — `audit/events.jsonl` hash-chain unbroken
  → `AUDIT_CHAIN_BROKEN` (Exit 25) on first broken link, with
  diagnostic that names the offending event_id and 8-hex excerpts of
  expected vs got hashes.
- §12.1 check 10 — `manifest.tsr` RFC 3161 structural validation
  → `TIMESTAMP_INVALID` (Exit 26) on parse failure or imprint mismatch.
  Checks `hashAlgorithm == SHA-256` and `hashedMessage` matches the
  SHA-256 of the canonical manifest.

New files:

- `internal/bundle/audit.go` — byte-exact Go mirror of the Python
  reference (`forensicdata_audit/chain.py`). Canonical-JSON + SHA-256
  chain validator; preserves additive future fields by hashing the
  full parsed event map rather than a fixed struct.
- `internal/bundle/tsr.go` — RFC 3161 structural validator built on
  the existing `internal/tsa/` package (digitorus/timestamp library).
  Pure imprint comparison is factored out (`verifyTSRImprint`) so it
  is unit-testable without constructing a real TSR token.
- `internal/bundle/audit_test.go` (16 tests) and
  `internal/bundle/tsr_test.go` (7 tests).

Behaviour changes:

- A bundle that previously reported `VALID, 8 checks PASS, 2 SKIPPED`
  now reports `VALID, 10 checks PASS` — the two §12.1 checks are no
  longer deferred. Bundles without `audit/events.jsonl` or
  `manifest.tsr` still PASS the corresponding checks with
  informational detail (absence is a presence-layer concern, handled
  by the existing required-entry list, not chain validity).

Out of scope (deferred, honestly):

- RFC 3161 cryptographic signature verification against a bundled
  TSA-CA trust root (Bundle-Spec §12.2 OPTIONAL). Requires curating
  a trust-root set; not blocking forensic claims because structural
  validation already detects TSR substitution and content tampering.
- `TIMESTAMP_MISSING` (Exit 30) warning when a TSR is expected for a
  given package class. Per-class policy is a higher-level concern;
  revisit when bundle producers start writing the relevant manifest
  field.

### Internal

- `go test ./...` — all green; 23 new bundle tests.
- `go vet ./...` clean.

## [0.2.0] — 2026-05-22

### Added — Evidence Bundle verifier (Bundle-Spec v1.0)

- `verifier verify bundle <path.zip> [--format=human|json] [--no-color]`
  — orchestrator covering the in-scope subset of Bundle-Spec §12.1
  mandatory checks:
  - `manifest_present`       : `manifest.json` is present, schema-valid,
                               and the bundle root directory equals
                               `manifest.bundle_id`.
  - `signature_present`      : `manifest.sig` is present and schema-valid
                               (10-field §8.2 record).
  - `signature_valid`        : embedded `public_key_pem` matches
                               `meta/signing_key.pub.pem` and the Ed25519
                               signature verifies per §8.5.
  - `manifest_hash_matches`  : canonical manifest hash equals
                               `manifest.sig.manifest_hash` (detects
                               `MANIFEST_TAMPERED`).
  - `artifacts_present`      : every `artifacts[].stored_path` exists.
  - `artifact_hashes`        : every `artifacts[].sha256` matches the
                               stored file.
  - `no_undeclared_files`    : nothing under `artifacts/` or `derived/`
                               is absent from `manifest.artifacts[]`.
  - `policy_compliance`      : in `disclosure`/`sanitized` packages, no
                               artifact carries `policy_state=internal_only`.
- `internal/bundle/canonical.go` — Go port of Bundle-Spec §6.1 canonical
  JSON (JS-`JSON.stringify`-compatible: U+2028/U+2029 escaped). Designed
  to produce byte-identical output to the Python `forensicdata_audit`
  reference for every supported value type.
- `internal/bundle/manifest.go` — §6.2 manifest schema + canonical hash
  (`SHA-256` of canonical bytes, lowercase hex). Strict field validation:
  unknown keys are rejected.
- `internal/bundle/signing.go` — §8 Ed25519 verify-only API
  (`LoadPublicKeyPEM`, `SerializePublicKeyPEM`, `ComputeSigningKeyFingerprint`,
  `VerifySignature`, `ParseManifestSignature`). Stdlib only:
  `crypto/ed25519`, `crypto/x509`, `encoding/pem`. No third-party crypto.
- `internal/bundle/reader.go` — §5 ZIP-reader adapter: single-root
  validation, path-traversal rejection, root-relative entry access.
- `internal/bundle/verify.go` — §12.1 check sequencer with §12.3
  priority-ordered result codes.
- `internal/report` — `HumanBundle` and `JSONBundle` renderers parallel to
  the v0.1.0 legalpack renderers.
- `testdata/gen_bundle/main.go` — `//go:build ignore` generator that
  produces a synthetic golden bundle signed with a zero-seed Ed25519
  reference key, for end-to-end smoke testing the built binary.

### Exit codes (Bundle-Spec §12.3)

`verify bundle` exit codes match the spec table verbatim:

|  Code | Meaning                                              |
|------:|------------------------------------------------------|
|     0 | `VALID`                                              |
|    10 | `SCHEMA_UNSUPPORTED`                                 |
|    11 | `MANIFEST_MISSING`                                   |
|    12 | `SIGNATURE_MISSING`                                  |
|    20 | `INVALID_SIGNATURE`                                  |
|    21 | `HASH_MISMATCH`                                      |
|    22 | `FILE_MISSING`                                       |
|    23 | `FILE_ADDED`                                         |
|    24 | `MANIFEST_TAMPERED`                                  |
|    32 | `POLICY_VIOLATION`                                   |
|     2 | input/format error (unmapped code, malformed args)   |

### Deferred (in scope of a v0.2.x patch series)

- `audit_chain` (§12.1 #9, `AUDIT_CHAIN_BROKEN`) — reported as `SKIPPED`
  with reason "deferred to Stage E.1.f".
- `timestamp_token` (§12.1 #10, `TIMESTAMP_INVALID` / `TIMESTAMP_MISSING`)
  — `manifest.tsr` parsing and digest match deferred to Stage E.1.f.
- TSR cryptographic signature verification against a bundled trust-root
  list (freetsa, DigiCert) — same posture as v0.1.0.
- License HMAC-authenticity — out of scope by design (open-source binary
  cannot ship the issuing secret; see README §Risk #1).
- FDS-Seal JSON verification, FDC-Diff verification.
- Sovereign-Pack v1/v2/v3 (Hebel-4 container format).

### Cross-language byte-exact design

All three new layers (canonical JSON, manifest hash, signature) are
designed to produce byte-identical output to the Python
`forensicdata_audit` reference. The signing layer is anchored by a
zero-seed Ed25519 reference key (32 zero bytes), producing a fixed
public-key fingerprint `339e2ff917630507b6a423b5ce084e28` that both
Python and Go reach. This is a property of the implementations as
written, not an external certification — independent re-verification
against the spec is encouraged.

### Fixed

- `verifier version` now reports the goreleaser-injected version string
  (e.g. `v0.2.0`) instead of the hardcoded `v0.0.0-dev` default. The
  `main.Version` identifier was renamed to lowercase `main.version` to
  match the `-X main.version=…` ldflag declared in `.goreleaser.yaml`.
  Pre-existing v0.1.0 binary built via goreleaser is affected by the
  same silent miss; this fix lands in v0.2.0.

### Test count

Approximately 280 tests passing across 5 packages (around 170 new vs
v0.1.0):

- `internal/bundle`         : ~170 tests across canonical / manifest /
                              signing / reader / verify orchestrator.
- `internal/canonicaljson`  : 41 sub-tests (unchanged from v0.1.0).
- `internal/legalpack`      : 65 tests (unchanged).
- `internal/license`        : 23 tests (unchanged).
- `internal/tsa`            : 12 tests (unchanged).

## [0.1.0] — 2026-05-19

### Added — feature-complete CKNF Legal-Pack verifier

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
  signature/trust-chain verification deferred.
- `internal/report` — human (color/ANSI) and JSON renderers.

### Test count

112 tests passing across 4 packages.
