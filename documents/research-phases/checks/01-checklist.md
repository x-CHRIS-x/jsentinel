# Phase 01: Independent verification checklist

Branch: `work/phase-01-scope`. Review date: September 11, 2026.
Implementation commit: `59387bf`. Audited HEAD: `88c89ac`.
Comparison base: `348a107`, the merge base with `plan/research-phases`.

**Overall result: FAIL. Phase 01 is not ready for merge approval.**

This update records the preceding independent review of the same implementation. It replaces the earlier self-reported verdicts where evidence disagreed. The exact checklist wording below comes from [Phase 01](../01-browser-scope-and-categories.md). PASS means the stated check passed within the tested scope, not that the entire scanner is correct.

## Check 1

- [x] Ordinary browser `fetch` and Axios calls do not receive SSRF or vulnerable-component labels merely because their request target is a variable.

**Result: PASS**

Dynamic browser fetch calls no longer emit A10-001. Axios calls no longer emit the retired dynamic-request-target variant. Both literal and variable Axios requests now emit component-review instead. This checks removal of the request-target classification only; the incorrect advisory penalty is a separate failure in item 6.

## Check 2

- [x] Express header and response-side CORS checks are absent from active coverage in both interfaces.

**Result: PASS**

A05-002, A05-004, and the A06 express-headers branch are absent from new results in both engines. A wildcard response-header snippet produced no finding. Express imports emit component-review rather than the retired header check; its penalty remains covered by item 6.

## Check 3

- [x] Browser-relevant checks, including sensitive HTTP endpoints, still run as intended.

**Result: PASS**

The HTTP endpoint, eval, redirect, and sensitive-logging probes retained their expected rule IDs. Before/after comparisons over all 116 existing samples found no changes to unrelated rule outputs in either engine. This establishes regression preservation, not that every retained rule is semantically correct.

## Check 4

- [ ] Active IDs and OWASP mappings agree between scanners and reports.

**Result: FAIL**

Both engines have the same 24 active IDs and seven categories, but reports do not preserve historical mappings. Loading a stored A10-001 finding leaves totalIssues at 1 while the category total becomes 0 and the JSON category profile omits A10. See P2-02 in 01-issues.md.

## Check 5

- [x] A06 wording does not claim a confirmed vulnerable dependency from an import alone.

**Result: PASS**

The emitted component-review message asks the developer to verify the installed version against current advisories, and the guidance catalogs remain identical. This result covers the wording only. The MEDIUM severity and vulnerability treatment remain incorrect under item 6.

## Check 6

- [ ] Advisory-only A06 signals remain visible for review but do not inflate vulnerability totals, deduct project-score points, or enter vulnerability accuracy calculations.

**Result: FAIL**

A literal Axios request produces one MEDIUM component-review finding and a JSON file score of 95 instead of 100. Both engines emit the same finding, and the app and extension counting/scoring paths treat it as a vulnerability. Phase 01 requires informational handling now; Phase 03 verifies downstream consistency. The earlier carry-forward claim was incorrect. Future evaluator exclusion cannot be verified before that evaluator exists.

## Check 7

- [ ] Run the existing guidance checks and build checks appropriate to the changed code. Add focused scope regressions without treating them as research accuracy results.

**Result: FAIL**

npm.cmd run build passed, and node --test validation/guidance.test.cjs passed 13/13. The independent review also ran 15 targeted inputs on both engines and the 116-file regression comparison. However, the implementation diff adds no persistent focused regression tests for the changed scope, advisory behavior, or historical results. The existing guidance suite does not cover these defects. This compound checklist item remains incomplete despite the passing commands.

## Independent check evidence

| Check | Command or method | Observed result |
| --- | --- | --- |
| Comparison base | `git merge-base HEAD plan/research-phases` | `348a107`; local comparison branch and its upstream had no divergence. |
| Build | `npm.cmd run build` | Exit 0; 232 modules transformed; bundle-size warning remains. |
| Guidance | `node --test validation/guidance.test.cjs` | 13 passed, 0 failed. Includes mirrored catalogs and historical guidance lookup. |
| Registry | Import active browser rule arrays and extension `allRules`; compare sorted IDs | 24 matching IDs, seven categories; retired IDs absent. |
| Focused probes | 15 inputs passed to actual web and extension engines under Node | No parse/rule errors; A06 scoring failure reproduced. Inputs included JS, JSX, TypeScript, fetch, Axios, Express, CORS, HTTP, eval, redirect, logging, and component review. |
| Existing samples | 116 files through both engines at base and current revisions | 464 engine invocations; zero parse/rule failures; zero retired-rule findings in current results. Unrelated ID/location/severity outputs unchanged. |
| Historical report | Execute actual App.jsx memo callbacks with one stored A10 finding; inspect JSON profile path | Before: total 1, category total 1. After: total 1, category total 0. |
| Whitespace | `git diff --check 348a107` during review | Reported extension line-ending/whitespace and verification-file EOF issues; not a functional defect. |

The ad hoc probes were executed in memory through `node --input-type=module`. Baseline rule source was read with `git show`; sample code was parsed, not executed. For regression preservation, the comparison excluded A06-001 and the three intentionally retired base IDs, then compared all other findings by ID, line, column, and severity. These checks are development evidence, not research accuracy results.

## Limits and next action

Interactive browser behavior, installed VS Code/VSIX behavior, and rendered PDF pages were not tested in this audit. Guidance lookup passing does not prove that every historical report remains correct.

Fix the failures and the completion gaps in [01-issues.md](01-issues.md), add focused regressions, and repeat independent verification. Do not mark Phase 01 complete, merge it, or start Phase 02 on the basis of this report.
