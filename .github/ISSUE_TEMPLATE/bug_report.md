---
name: Bug report
about: Report a verification result that looks wrong, or a crash.
labels: bug
---

## Summary

<!-- One sentence describing what went wrong. -->

## Steps to reproduce

```bash
verifier --version
verifier verify legal-pack <pack.zip> ...
```

## Observed output

<!-- Paste the actual output (or attach via gist). -->

## Expected output

<!-- What you expected to see and why. -->

## Environment

- OS:                 <!-- e.g. macOS 14.4 arm64 / Ubuntu 22.04 amd64 / Windows 11 amd64 -->
- Binary version:     <!-- output of `verifier version` -->
- Pack producer:      <!-- e.g. CKNF v2.3.0 macOS -->

## Sensitive data

Do **not** attach packs that contain real evidence. If reproduction needs the
real pack, contact security@crupesystems.com privately.
