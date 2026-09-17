# Phase 03: Resolve overlapping HTML findings

Status: Not started. Depends on Phase 02. Suggested size: 1 to 2 focused blocks.

Resolve the third problem: the same `innerHTML` assignment can produce overlapping findings and multiple score deductions.

## Batch A: One assignment, one applicable HTML finding

For overlapping findings on the same assignment, prefer the template-specific rule `OWASP-A03-004`, then the function-result rule `OWASP-A03-005`, then the general rule `OWASP-A03-006`.

Resolve this in scanner output before counts, scoring, history, and exports consume it. Do not merge separate assignments or unrelated vulnerabilities just because they share a line or rule ID.

Relevant code includes the injection and XSS rule modules, `src/utils/scannerEngine.js`, `vscode-extension/src/scanner/rules.js`, and `vscode-extension/src/scanner/scannerEngine.js`. Choose the smallest change that produces consistent results in both engines.

## Batch B: Follow the finding through the product

Check web cards, extension diagnostics and sidebar, severity counts, false-positive handling, saved new scans, PDF output, and JSON output. The surviving finding keeps its location, source evidence, guidance, severity, and a single applicable deduction.

Keep the project's existing severity-to-penalty weights for eligible vulnerability findings. Apply Phase 01's advisory policy: informational A06 review signals remain visible separately and do not enter vulnerability totals or deduct score points. Explain that this aggregate score is a JSentinel heuristic; it is not detection accuracy or a FIRST-issued project score. Do not silently recalculate historical scans under the new behavior.

## Checks and stopping point

- [ ] One dynamic template assignment produces one applicable HTML finding and deduction.
- [ ] One function-result assignment produces one applicable HTML finding and deduction.
- [ ] A generic assignment still receives its applicable check.
- [ ] Two separate unsafe assignments remain two findings.
- [ ] An unrelated vulnerability at the same location is retained.
- [ ] Both scanners and their report consumers agree on counts and deductions.
- [ ] Advisory-only A06 signals are shown separately and do not alter vulnerability totals or the project score in new scans.

Deliver the correction and focused verification. Record any remaining HTML false positives as limitations for the later benchmark. Stop before modifying the 116-file dataset.
