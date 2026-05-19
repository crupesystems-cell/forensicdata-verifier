# forensicdata-verifier

Independent, open-source CLI to verify forensic evidence packs produced by the
**Consilium CKNF / FORensicData Clean / FORensicData Seal** suite — with **no
suite software installation required**.

A single ~5–6 MB static binary for macOS, Linux, and Windows. Offline. No
account. No telemetry.

> **Status:** v0.1.0-pre. First public release targeted at CKNF Suite
> v2.4.0-Final (2026-07-01).

## Verify in 30 seconds

Download the binary for your OS from the [Releases](#) page, extract, then:

```bash
verifier verify legal-pack ./my-recording.zip
```

Expected output on a forensically intact pack:

```
Format:  CKNF Legal-Pack v1
ID:      My_Recording_2026-05-19_aaaaaaaa

✓ audio_sha256         SHA-256 of original.m4a matches sha256_report.txt
✓ verification_qr      verification_qr.png payload is consistent with sha256_report.txt
○ audit_jsonl_chain    1 events present but no per-event hash chain (CKNF v2.3 schema)
○ tsa_rfc3161          no --tsr path provided (CKNF stores original.tsr alongside the pack, not inside it)

Audit log: 1 event(s), chain unsigned (CKNF v2.3 schema)

VERDICT: PASS
2 checks passed, 2 skipped. Legal-Pack is intact within verifiable scope.
```

If any check fails, the verifier exits with status `1` and prints which check
failed and what the mismatch was — with the expected and computed values side
by side so the failure is actionable.

## What it verifies (v0.1.0)

| Check | What it confirms |
|---|---|
| `audio_sha256` | The audio bytes inside the ZIP hash to the SHA-256 claimed in `sha256_report.txt`. A mismatch means the audio file was modified after the recording was sealed. |
| `verification_qr` | The QR code inside the ZIP carries a payload whose `id`, `sha256`, and `chain_hash` match `sha256_report.txt`. A mismatch means pack pieces were not sealed together (substitution attack). |
| `audit_jsonl_chain` | The `audit.jsonl` log is well-formed. If per-event `self_hash` / `prev_hash` chain fields are present, the chain is cryptographically verified. CKNF v2.3 packs use an unsigned schema; this check then reports `SKIPPED`. |
| `tsa_rfc3161` | When `--tsr <path>` is provided, the RFC 3161 TimeStampResponse token is parsed and its hashed-message field is verified to equal the audio's SHA-256. Without `--tsr` the check reports `SKIPPED` — CKNF stores `original.tsr` alongside the pack, not inside it. |

```bash
# Pack + accompanying TSR file (full forensic check):
verifier verify legal-pack ./my-recording.zip --tsr ./original.tsr

# Machine-readable output for downstream tooling:
verifier verify legal-pack ./my-recording.zip --format=json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed (or passed with allowed `SKIPPED` items). |
| `1` | One or more checks `FAIL`ed. |
| `2` | Input could not be opened or is structurally invalid. |

### Coming in future versions

| Input | Since |
|---|---|
| TSR cryptographic signature verification (against bundled CA trust roots) | v0.2.0 |
| FDS SealResult JSON | v0.2.0 |
| FDC Diff-Export | v0.3.0 |
| Sovereign-Pack v1/v2/v3 cross-program container | v1.0.0 (post CKNF Suite v2.5.0) |

## Authenticity vs. format validity

The CLI also offers `verifier verify license <string>` to validate a CKNF
license-string's **structural format** (correct prefix, tier, programs,
serial range, checksum field):

```bash
verifier verify license CKNF-LCFS15022-6FBF59ED
✓ Format valid: Prefix=CKNF, Tier=Lifetime, Programs=CFS, Serial=15022, Checksum=6FBF59ED
  (authenticity verification requires the CKNF issuing service)
```

This does **not** check that the license was actually issued by the CKNF
service. Authenticity requires the issuing service's HMAC secret, which is
deliberately not bundled in this open-source binary — shipping it here would
expose the secret to anyone who downloads the binary and let third parties
clone the license generator. Format validity catches transcription errors and
obviously malformed inputs; the issuing service confirms authenticity.

For a Legal-Pack, every check IS cryptographic — a `PASS` means the pack has
not been tampered with after the recording was finalized.

## Why open-source?

The Consilium / FORensicData suite produces forensic evidence that may be used
in court. The recipient of such evidence — defense counsel, judge, auditor,
regulator — must be able to verify it independently, without trusting any
single vendor.

By publishing this verifier under the Apache License 2.0, we make that
independence **verifiable** rather than just claimed: anyone can build the
binary from source, inspect every line, and confirm what it reports.

## Build from source

Requires Go 1.21 or newer.

```bash
git clone <repo-url> && cd forensicdata-verifier
go build -o verifier .
./verifier version
```

Cross-platform build via `goreleaser`:

```bash
goreleaser build --snapshot --clean
# Produces dist/verifier_{snapshot}_{os}_{arch}/verifier{.exe} — 5 targets.
```

### Run the test suite

```bash
go test ./...
# 112 tests across 4 internal packages.
```

The repository includes a fixture generator for offline smoke-testing:

```bash
go run testdata/gen/main.go
./dist/verifier_darwin_arm64_v8.0/verifier verify legal-pack \
    testdata/golden_legal_pack/valid-2026-05-19.zip
```

## Contributing

Issues and pull requests welcome. By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).

Security issues: see [SECURITY.md](SECURITY.md) for the responsible-disclosure
address — please do **not** open public issues for vulnerabilities.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2026 WBR IP & License Holding Pte. Ltd.
