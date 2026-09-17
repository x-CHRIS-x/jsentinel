# Phase 01: Changes and review target

Branch: `work/phase-01-scope`. Review recorded September 11, 2026.

## Commit references

- Comparison base: `348a107`, the merge base with `plan/research-phases`.
- Implementation commit: `59387bf`, "Phase 01: Retire SSRF, CORS wildcard, helmet, and A06 server-side branches from browser scan".
- Latest branch commit at the independent audit: `88c89ac`, which updated the implementation hash in this report.
- The subsequent report-only commit is identifiable with `git log -1 -- documents/research-phases/checks/01-changes.md`; it does not change the implementation reviewed above.

**Independent result: FAIL. Changes required before merge approval.** See [01-checklist.md](01-checklist.md) and [01-issues.md](01-issues.md).

## Implementation files changed

| File | Change | Review consequence |
| --- | --- | --- |
| `src/scanner/rules/ssrf.js` | Replaced the active A10-001 rule and helper with an empty exported array. | Retired SSRF findings are absent from new scans. |
| `src/scanner/rules/misconfig.js` | Removed A05-002 and A05-004; retained A05-001 and A05-003. | Response-side CORS and Express-header checks no longer run. |
| `src/scanner/rules/knownVulns.js` | Removed Express-header and Axios-target branches, their tracking state, and the unused validation helper. Emits component-review for every listed import. | New advisory cases still count as MEDIUM vulnerabilities and deduct points. |
| `src/App.jsx` | Removed active SSRF registration and A10 from the category map. | New scan scope changes as intended, but stored A10 findings disappear from category summaries. |
| `vscode-extension/src/scanner/rules.js` | Mirrored the three retired base checks and A06 branch changes; updated inventory comments. | Active IDs match the web scanner; advisory output has the same unresolved severity treatment. |

The implementation added the three Phase 01 verification files under `documents/research-phases/checks/`. No guidance-catalog changes, focused regression-test additions, scanner version changes, or report-consumer fixes were included in the implementation commit.

## Verified active inventory

| Module | Active IDs | Count |
| --- | --- | --- |
| `accessControl.js` | A01-001, A01-002 | 2 |
| `auth.js` | A02-001, A02-002, A02-003, A02-004, A07-001 | 5 |
| `sensitiveData.js` | A02-005, A02-006, A02-007 | 3 |
| `injection.js` | A03-001 through A03-005 | 5 |
| `xss.js` | A03-006 through A03-008 | 3 |
| `knownVulns.js` | A06-001 component-review | 1 |
| `deserialization.js` | A08-001, A08-002, A08-003 | 3 |
| `misconfig.js` | A05-001, A05-003 | 2 |
| **Total** | | **24** |

Active IDs represent seven categories: A01, A02, A03, A05, A06, A07, A08. A06 is intended to be advisory coverage; the current implementation has not completed that separation. These counts are not a claim of 24 validated vulnerability detectors.

## Independent verification and report corrections

The review ran the build, 13 guidance tests, 15 focused cases on both engines, a 116-file before/after regression comparison with 464 engine invocations, and an actual category-callback reproduction for historical A10 results. Full results and test limits are in the checklist.

This report-only update changes:

- `01-changes.md`: records the audited commits, complete file inventory, and actual review status.
- `01-checklist.md`: reproduces all seven exact phase checklist items, records PASS/FAIL with evidence, and removes the unsupported overall-success implication.
- `01-issues.md`: records the two reproduced defects, remaining completion gaps, and the corrected Phase 01/03 responsibility boundary.

Existing unrelated planning edits and untracked chapter/workflow references are outside this report update. They are not staged as part of the audit record. No production code, sample dataset, paper, or template is changed by this update.

## Workflow stopping point

Remain on the work branch at the independent-audit stage. The audit has not passed. The next work is correction and re-verification of Phase 01, not merging into `plan/research-phases` or starting Phase 02.
