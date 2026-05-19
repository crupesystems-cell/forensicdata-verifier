# Security Policy

## Supported versions

The latest published `v0.1.x` release receives security fixes. Older versions
are not maintained.

| Version | Supported |
|---|---|
| v0.1.x (latest) | ✅ |
| < v0.1.0 | ❌ |

## Reporting a vulnerability

If you believe you have found a security vulnerability in
`forensicdata-verifier`, please **do not** open a public GitHub issue.

Report privately to:

> **security@crupesystems.com**

Please include:

- A description of the issue and its impact.
- A minimal reproducer (input file or command line) where possible.
- Your assessment of severity and any suggested mitigation.

We aim to acknowledge receipt within **3 business days** and to provide a
remediation plan within **14 days** for high-severity issues. We will
coordinate with you on disclosure timing before publishing any fix.

## Threat model — what this verifier is and is not

`forensicdata-verifier` is a **read-only** integrity checker. It opens a ZIP,
parses fields, computes hashes, and prints a verdict. It does **not**:

- modify the pack it inspects,
- network-call any remote service (no telemetry, no auto-update, no online
  trust-root fetch),
- store any state on disk other than what the operator's `--format=json`
  output redirect places there.

In v0.1.0 the verifier confirms:

- audio bytes hash to the SHA-256 claimed in the report,
- the verification QR carries a payload consistent with the report,
- `audit.jsonl` is well-formed (and chain-verified if hash-signed),
- when a `.tsr` is provided alongside, the RFC 3161 hashed-message field
  equals the audio SHA-256.

It does **not** in v0.1.0:

- verify the cryptographic signature of the RFC 3161 TSR (deferred to v0.2.0,
  pending a bundled trust-root list),
- verify the HMAC authenticity of a license string (kept out by design — see
  README "Authenticity vs. format validity"),
- verify FDS-Seal JSON or FDC-Diff exports (planned for v0.2.0 / v0.3.0).

A `VERDICT: PASS` from this binary means **every cryptographic check we
perform passed** — operators relying on the result for legal proceedings
should match this scope against their evidentiary requirements.

## Coordinated disclosure preference

We prefer a 90-day coordinated-disclosure window. If a vulnerability is
already publicly known or actively exploited, we may publish faster.

Thank you for helping keep the forensic-verification chain trustworthy.
