# Phase 01: Align browser scope and rule categories

Status: Not started. Depends on Phase 00. Suggested size: 2 to 3 focused blocks.

Resolve two of the four problems: browser requests being reported as SSRF, and server-header or dynamic-request checks being classified under A06.

## Batch A: Active rule inventory

Record which checks run in the web app and extension. Retire `OWASP-A10-001`, `OWASP-A05-002`, and `OWASP-A05-004` from active browser scans. Remove A06's `express-headers` and `dynamic-request-target` detection branches.

The expected result is 24 active base checks, including an A06 component-review check, in 8 modules across A01, A02, A03, A05, A06, A07, and A08. Count from active rule registration, not guidance-catalog entries. Identify vulnerability-pattern and advisory checks separately. `auth.js` contains both A02 and A07 checks, while two modules map to A03.

Keep A06 browser-relevant component review clearly described as a review signal. An import does not establish an affected package version. Document any remaining broad import heuristic as a limitation; do not turn this phase into a dependency-audit service.

The planned policy is to keep advisory-only A06 signals informational and separate from vulnerability totals, severity-based deductions, and vulnerability accuracy metrics. Do not present the legacy MEDIUM rating or CVSS value as evidence of a confirmed affected component. Apply this distinction to new scan results in both interfaces and their reports, while keeping historical results identifiable under their original version. Phase 03 checks the downstream counts and scoring.

## Batch B: Both implementations and presentation

Apply the scope change to `src/scanner/rules/`, rule registration in `src/App.jsx`, and `vscode-extension/src/scanner/rules.js`. Check both scanner engines and both copies of `guidanceCatalog.js` for matching active behavior and wording.

Retain surviving rule IDs. Historical guidance can remain resolvable without counting retired checks as active coverage. Browser findings can still recommend server-side remediation when that is where the problem must be fixed.

Check counts and claims in the app, extension, README, and exports. Replace claims of confirmed breaches where the evidence is only a static finding. Identify the revised scanner version in new results and exports. Preserve the meaning and version of older saved results.

## Checks and stopping point

- [ ] Ordinary browser `fetch` and Axios calls do not receive SSRF or vulnerable-component labels merely because their request target is a variable.
- [ ] Express header and response-side CORS checks are absent from active coverage in both interfaces.
- [ ] Browser-relevant checks, including sensitive HTTP endpoints, still run as intended.
- [ ] Active IDs and OWASP mappings agree between scanners and reports.
- [ ] A06 wording does not claim a confirmed vulnerable dependency from an import alone.
- [ ] Advisory-only A06 signals remain visible for review but do not inflate vulnerability totals, deduct project-score points, or enter vulnerability accuracy calculations.
- [ ] Run the existing guidance checks and build checks appropriate to the changed code. Add focused scope regressions without treating them as research accuracy results.

Deliver the changes and an active-rule inventory. Stop before validation refactoring or dataset regeneration.
