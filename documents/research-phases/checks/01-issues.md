# Phase 01: Independent findings and unresolved work

Branch: `work/phase-01-scope`. Review date: September 11, 2026.
Audited implementation: `59387bf`; audited HEAD: `88c89ac`; base: `348a107`.

**Status: Changes required. Independent verification has not passed.**

## P2-01: Exclude component advisories from vulnerability scoring

Location: `src/scanner/rules/knownVulns.js:94` and the mirrored finding in `vscode-extension/src/scanner/rules.js:1055`.

Reproduction input:

```javascript
import axios from "axios";
axios.get("/api/profile");
```

Before Phase 01, this input produced no finding. Now both engines emit `OWASP-A06-001:component-review` with MEDIUM severity and CVSS 4.8. The actual JSON formatter reports one active issue and a file score of 95. App and extension scoring paths likewise apply a five-point deduction.

Expected: show the informational review signal separately, with no vulnerability count or score deduction. An import does not establish an affected package version. The rule now emits this signal for cases that previously produced no finding, so this is more than an unchanged pre-existing penalty.

Required correction: implement the agreed advisory distinction consistently in new scan output, totals, scoring, and report consumers in both interfaces. Preserve historical-version meaning. The Phase 01 guide requires this behavior; Phase 03 checks the downstream behavior. It is not an approved deferral to Phase 03.

## P2-02: Preserve category summaries for historical A10 findings

Location: `src/App.jsx:370`, where A10 was removed from the shared category map.

Reproduction: load an existing historical result containing one HIGH `OWASP-A10-001` finding. The Load Scan handler supplies the stored issues to the current results state. The current category callback drops the unknown category.

Observed: totalIssues remains 1, while the sum of category counts changes from 1 to 0. The JSON category profile omits A10 even though the issue is exported.

Required correction: retain category representation for stored legacy findings while excluding A10 from active new-scan coverage. Add a historical-load/export regression; historical guidance lookup alone does not test this path.

## Remaining Phase 01 completion gaps

- New scan/export records still lack an updated rule-set version identifier. JSON continues to label the engine `JSentinel Core v1.0.0`; ensure changed coverage can be distinguished from historical results as the phase requires.
- `vscode-extension/README.md` still advertises 27 rules and nine categories. Update its coverage claims from the verified registry, distinguishing advisory coverage. The nine-category claim was already wrong before this change.
- The web PDF still uses confirmed-breach wording such as "Total Vulnerability Breaches Detected". The phase calls for reviewing these claims; informational imports must not be presented as confirmed breaches.
- The branch contains no new persistent focused regression tests. Add coverage for retired checks, retained HTTP detection, advisory totals/penalties, and historical category reporting.

These gaps are listed separately from the two reproduced regressions. Do not report them as newly discovered vulnerabilities.

## Accepted behavior and later work

- Keep historical guidance entries resolvable. Adding a retirement label is not necessary to fix the demonstrated category-loss bug.
- The remaining access-control validation helper belongs to Phase 02. Its presence is not a new Phase 01 defect; the retired SSRF file no longer contains that helper.
- The bundle-size warning is a disclosed build limitation. It is not evidence that Phase 01 failed compilation.
- A06 exclusion from vulnerability accuracy metrics is already decided in the phase guides. Apply and verify it when Phase 05's evaluator exists; do not reopen it as an undecided policy.
- Later dataset and chapter updates must use the verified inventory and retain the distinction between active checks and demonstrated vulnerability coverage.

## Return to independent review

1. Correct Phase 01's unmet requirements on this branch.
2. Add and run focused regressions, then rerun guidance/build checks and the affected historical/report checks.
3. Update these records with the new target commit and actual evidence. Preserve the distinction between earlier failures and subsequent results.
4. Request independent verification again. Merge only after the user confirms it passed, following [WORKFLOW.md](../WORKFLOW.md).

This report does not authorize a merge, branch deletion, push, or progression to Phase 02. No production fix was made while recording this audit.
