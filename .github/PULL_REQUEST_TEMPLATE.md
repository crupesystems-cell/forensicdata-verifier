<!--
Thanks for contributing! Please fill in the sections below.
By submitting this PR you agree to the project's CODE_OF_CONDUCT.md
and license your contribution under the Apache License 2.0.
-->

## Summary

<!-- One or two sentences: what changes, why. -->

## Type of change

- [ ] Bug fix (PASS/FAIL verdict was wrong)
- [ ] New check (cryptographic property added)
- [ ] Output / CLI change
- [ ] Documentation
- [ ] Internal refactor (no behaviour change)

## How was this verified?

- [ ] `go vet ./...` clean
- [ ] `go test -race ./...` clean
- [ ] Smoke against `testdata/golden_legal_pack/valid-2026-05-19.zip` → PASS
- [ ] Smoke against `testdata/golden_legal_pack/tampered-*.zip` → FAIL with
      a clear actionable error message

## Forensic-correctness check

<!-- If this changes how a verdict is computed, explain:
     - What new claim is being verified (or which existing claim is changed)?
     - What does a FAIL now mean that it did not mean before?
     - Does this change keep the binary deterministic and offline?
-->

## Notes for reviewers

<!-- Anything reviewers should pay extra attention to. -->
