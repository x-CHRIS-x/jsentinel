# Phase 01 independent re-review — 2026-09-13

## Identity and scope

- Reviewer/session: fresh AO implementation-worker session `jsentinel-6`; this session did not implement the candidate.
- Harness/model: Codex harness; underlying model identity is not independently exposed by the session and is therefore **unverified**. The runtime instructions identify the agent family as GPT-5, but this is not treated as independently verified model telemetry.
- Reason for stronger verifier: Phase 01 corrections cross security classification, score denominators, historical-result semantics, and multiple report/history consumers. These require deeper scoring/history/security reasoning than registration-count confirmation alone.
- Review date/time zone: 2026-09-13, Asia/Manila.
- Assigned workspace: `C:\Users\johnc\.ao\data\worktrees\jsentinel\jsentinel-6`.
- Initial branch/HEAD: `ao/jsentinel-6/root` at `fcd79efff7d35597a23228a156a67c668fdfebf5`.
- Development-check HEAD: detached exactly at `e72d34df77a7e42877feb38770100a8b16df7ff0`.
- Exact comparison: `348a107feb91fb956f3572df5a521b4247c177f2..e72d34df77a7e42877feb38770100a8b16df7ff0`.
- Correction report revision: `c3e95e493b3f31c428c232537cfe7bc2702ee70f`.
- Failed-audit revision: `324de9a75cd4b6bcf126c0c7cb0c8260e2f962a5`.
- Relationship: `git merge-base 348a107 e72d34d` returned the full base hash above; `git merge-base --is-ancestor 348a107 e72d34d` exited 0.
- Refs were **not fetched or refreshed**. All branch and remote-tracking names observed in this review were local refs.

The current `WORKFLOW.md`, project `README.md`, Phase 01 guide, and checks README were read from `C:\Users\johnc\OneDrive\Desktop\school archive\1.1 antigrav\github repo\jsentinel`. Historical `01-changes.md`, `01-checklist.md`, and `01-issues.md` were read with `git show` at both report revisions. The correction self-check PASS was treated as unverified supporting evidence.

## Reviewed implementation

`git diff --name-status 348a107..e72d34d` contains 23 files: both rule implementations, web registration, scanner versions, mirrored finding policies, app/history presentation, JSON and both PDF paths, extension status/diagnostics/hover/sidebar, README claims, guidance schema coverage, focused regressions, and historical check records. The actual diff was inspected rather than substituting the current planning ancestry.

Observed active inventory is 24 IDs in 8 modules and 7 categories: access control 2, auth 5, sensitive data 3, injection 5, XSS 3, A06 component review 1, deserialization 3, and misconfiguration 2. Twenty-three are vulnerability-pattern rules; `OWASP-A06-001` is the one advisory rule. Both engines register matching IDs. `OWASP-A10-001`, `OWASP-A05-002`, and `OWASP-A05-004` are absent from active registration; retired guidance remains available.

## Commands and observed results

| Command | Exit | Observed result |
| --- | ---: | --- |
| `git status --short --branch`; `git rev-parse HEAD`; `git symbolic-ref -q --short HEAD` | 0 | Initially clean on `ao/jsentinel-6/root`, HEAD `fcd79efff7d35597a23228a156a67c668fdfebf5`. |
| `git rev-parse 348a107 e72d34d c3e95e4 324de9a` | 0 | Resolved to the four full hashes recorded above. |
| `git merge-base 348a107 e72d34d`; `git merge-base --is-ancestor 348a107 e72d34d` | 0 / 0 | Exact merge base is `348a107feb91fb956f3572df5a521b4247c177f2`; range is linear. |
| `git switch --detach e72d34d`; `git rev-parse HEAD` | 0 / 0 | Detached at exact candidate `e72d34df77a7e42877feb38770100a8b16df7ff0`. |
| `git show 324de9a:<each Phase 01 report>` and `git show c3e95e4:<each Phase 01 report>` | 0 | Read the failed audit and subsequent correction/self-check record without modifying them. |
| `git diff --stat 348a107..e72d34d`; `git diff --name-status 348a107..e72d34d`; focused `git diff`/`rg`/line inspection | 0 | Inspected exact implementation range and all requested consumer areas. |
| First `node --test validation/browser-scope.test.mjs validation/guidance.test.cjs` | 1 | Dependencies were absent: `@babel/standalone` could not be resolved; 12 tests passed and 2 entry/tests failed for environment setup. Not counted as a candidate test failure. |
| First `npm.cmd run build`; root/extension lint | 1 / 1 / 1 | Vite/ESLint executables absent before dependency installation. Not counted as candidate failures. |
| `npm.cmd ci` | 0 | Installed 192 lockfile-pinned packages. npm reported 11 dependency audit findings (1 low, 4 moderate, 6 high); no audit fix or dataset regeneration was performed. |
| `node --test validation/browser-scope.test.mjs validation/guidance.test.cjs` | 0 | 24 passed, 0 failed. Includes 11 focused scope tests, 13 guidance tests, 116 samples through both real engines (232 calls), history/category/extension consumers, JSON, both PDF generators, and diagnostics. |
| `npm.cmd run build` | 0 | Vite 8.0.8; 233 modules transformed. Existing large-chunk warning; largest output 3,761.79 kB (913.24 kB gzip). |
| `npm.cmd run lint` | 1 | Two errors in `src/utils/jsonExporter.js:20`: parameters `stats` and `owaspCategories` are assigned defaults but never used. |
| `node --check vscode-extension/src/extension.js` | 0 | Syntax check passed. |
| `npm.cmd --prefix vscode-extension run lint` | 0 | Extension lint passed. |
| `git diff --check 348a107..e72d34d` | 2 | Reports trailing whitespace/CRLF-style noise in changed portions of `vscode-extension/src/scanner/rules.js`; no runtime failure. |
| In-memory advisory-only scanner probe piped to `node --input-type=module` | 0 | Axios import emitted one `INFORMATIONAL` `findingType: advisory`; stats were 0 total/active vulnerabilities, 1 active advisory, score 100. No probe file was created. |
| `rg -n "DETAILED VULNERABILITY FINDINGS REPORT|if \\(fpFlags.includes\\(fpKey\\)\\) return;|activeIssuesList.push" src/utils/pdfGenerator.js vscode-extension/src/utils/pdfGenerator.js` | 0 | Reproduced that both PDF detail sections label the table as vulnerability findings but append all non-FP findings, including advisories. |

Environment: Node `v24.15.0`, npm `11.12.1`; `ao version` printed `dev`.

## Acceptance matrix

| Phase 01 acceptance criterion | Result | Independent evidence |
| --- | --- | --- |
| Ordinary browser `fetch` and Axios calls do not receive SSRF or vulnerable-component labels merely because their request target is a variable. | **PASS** | Focused tests pass for bare variable `fetch`/Axios. Imported Axios produces only an informational manual component-review advisory; no request-target/SSRF branch remains. |
| Express header and response-side CORS checks are absent from active coverage in both interfaces. | **PASS** | Matching registries exclude A05-002/A05-004/A10-001; server-header probe is empty apart from an import advisory where an explicitly listed package is imported. Retired branch terms survive only in comments/guidance/history support. |
| Browser-relevant checks, including sensitive HTTP endpoints, still run as intended. | **PASS within tested scope** | Sensitive HTTP `fetch("http://api.example.com/login")` retains A02-004; eval retains A03-001; all 116 samples parse without rule errors and both engines agree. This is development regression evidence, not research accuracy evidence. |
| Active IDs and OWASP mappings agree between scanners and reports. | **PASS within tested scope** | Both engines expose the same 24 IDs/seven categories; policies are byte-logically mirrored. JSON/app/PDF category consumers use the policy; historical A10 is conditionally retained. |
| A06 wording does not claim a confirmed vulnerable dependency from an import alone. | **PASS** | Rule and guidance wording requests installed-version/advisory verification; new output is INFORMATIONAL/advisory with null CVSS and no affected-version claim. Guidance parity suite passes 13/13. |
| Advisory-only A06 signals remain visible for review but do not inflate vulnerability totals, deduct score, or enter vulnerability accuracy calculations. | **FAIL (presentation boundary)** | Counts, score, JSON eligibility, diagnostics, history, and category summaries behave correctly. However, both actual PDF generators insert the advisory into a section titled `DETAILED VULNERABILITY FINDINGS REPORT`; this still presents an import-only advisory as a vulnerability finding. No Phase 05 evaluator exists, so evaluator exclusion remains untested. See RR-P2-01. |
| Run existing guidance/build checks and add focused scope regressions without treating them as research results. | **FAIL (development check)** | Focused/guidance suite passes 24/24 and build passes, but the repository's existing root lint command fails on code introduced by the correction. See RR-P2-02. The tests are correctly described as development evidence, not formal accuracy results. |

## Actionable findings

### RR-P2-01 — PDF detail sections classify advisories as vulnerabilities

Locations:

- `src/utils/pdfGenerator.js:224` titles section 5 `DETAILED VULNERABILITY FINDINGS REPORT`; lines 230-249 append every non-false-positive issue, with no `isAdvisory(issue)` separation.
- `vscode-extension/src/utils/pdfGenerator.js:235` uses the same title; lines 241-260 append every non-false-positive issue, again without advisory separation.

Reproduction:

1. Scan `import axios from "axios";`. The real scanner returns one `INFORMATIONAL`, `findingType: advisory` notice, zero vulnerability-pattern findings, and score 100.
2. Generate either PDF. The existing PDF consumer regression proves the advisory is retained; direct source/runtime-path inspection shows it is pushed into `activeIssuesList` and rendered under the vulnerability-only section title.
3. Thus the executive totals say zero vulnerabilities while the detailed **vulnerability** table lists the import advisory. This is a contradictory classification and does not fully apply the required advisory/vulnerability distinction to reports.

Required correction: rename and structure the section as mixed findings with an explicit finding-type/advisory label, or separate advisories from vulnerability findings. Preserve their visibility and guidance while avoiding a confirmed-vulnerability presentation. Add an assertion covering the detail-section title/type, because the current PDF test checks summary/matrix/category tables but misses this case.

### RR-P2-02 — Candidate fails the existing root lint check

Location: `src/utils/jsonExporter.js:20`.

Reproduction: `npm.cmd run lint` exits 1 with `no-unused-vars` for `stats` and `owaspCategories`. The correction changed the formatter to recompute safe statistics/categories from findings at lines 24-25, leaving the two defaulted compatibility parameters unused. The failure is introduced within `348a107..e72d34d` and is not a pre-existing/out-of-phase scanner defect.

Required correction: retain intentional API compatibility without violating lint (for example, adjust the API/call sites or explicitly document/handle ignored legacy arguments), then rerun root lint, focused tests, and build.

## Other observations and scope boundaries

- `git diff --check` reports whitespace in the changed extension rules file. This is review hygiene, not the reason for the functional verdict.
- The Vite large-chunk warning and npm dependency-audit output are pre-existing/project-wide concerns and are not Phase 01 acceptance defects established by this review.
- Retired IDs remain in extension confidence arrays and historical guidance/comments, but active registration cannot emit them. Retaining historical guidance is required; confidence-array cleanup is non-functional and does not reactivate coverage.
- The broad A06 import heuristic remains a disclosed limitation; it does not inspect lockfiles or prove affected versions.
- Existing validation-guard and overlapping-HTML behavior belongs to later phases and was not treated as a Phase 01 regression.

## Untested or not formally verified

- Interactive browser workflows and rendered UI behavior.
- Installed VS Code/Antigravity or packaged VSIX behavior.
- Visual PDF page-layout inspection; PDF logic/table content was exercised, not pages rendered for visual QA.
- Full before/after execution of all 116 samples at both base and candidate. This re-review ran the candidate through both engines and inspected the exact diff; the historical 464-call comparison was not re-claimed as new evidence.
- Any formal AU lab testing, research accuracy/denominator calculation, ISO interpretation, multi-PC performance/memory measurement, dataset regeneration, or Chapter IV/V evidence.
- Phase 05 evaluator exclusion because that evaluator does not yet exist.
- Remote state, CI, or provider status because refs were intentionally not refreshed and no network/provider review was requested.

## Verdict and gates

**Independent re-review verdict: FAIL (scoped to Phase 01 at `e72d34df77a7e42877feb38770100a8b16df7ff0`).**

The core active inventory, retirement behavior, retained browser checks, advisory scoring/counting, versioning, and historical A06/A10 semantics pass within the tested development scope. Phase 01 is not ready for acceptance because both PDF outputs still classify advisory-only imports under a vulnerability-finding section and the candidate fails the existing root lint check. Corrections must be reported and independently re-reviewed before acceptance.

- Manager assessment: **PENDING**
- Human acceptance: **PENDING**
- Merge/integration approval: **PENDING**
- Permission to begin Phase 02: **PENDING / NOT AUTHORIZED**

No production code/tests, datasets, chapters, or historical reports were edited. No formal AU testing, merge, push, PR, or Phase 02 work was performed.

## Reproducible in-memory advisory probe

The exact PowerShell command used for the successful advisory-only probe was:

```powershell
$probeSource = @'
import { scanFile } from './src/utils/scannerEngine.js';
import { knownVulnsRules } from './src/scanner/rules/knownVulns.js';
import { calculateStats } from './src/utils/findingPolicy.js';
const result = await scanFile({ name: 'advisory-only.js', text: async () => 'import axios from "axios";' }, knownVulnsRules);
console.log(JSON.stringify({ issues: result.issues, stats: calculateStats([result]) }, null, 2));
'@
$probeSource | node --input-type=module
```

Exit code was 0. The result contained one `OWASP-A06-001:component-review` issue with `severity: "INFORMATIONAL"`, `findingType: "advisory"`, null CVSS score, and scanner-supplied source line. Calculated statistics were zero total/active vulnerability-pattern findings, one total/active advisory, and security score 100. The probe was executed from the assigned workspace at detached HEAD `e72d34df77a7e42877feb38770100a8b16df7ff0`; it creates no file.

## Manager assessment — separately attributed

Manager assessment supplied by AO orchestrator session `jsentinel-4` after reading this review:

**Not ready for Phase 01 acceptance. Corrections RR-P2-01 and RR-P2-02 are required, followed by a fresh independent re-review of the changed candidate. Human acceptance, integration, and Phase 02 authorization remain PENDING. No fixes are authorized by this assessment.**

This manager assessment concurs with, but is separate from, the independent reviewer verdict above. It does not convert the review into human acceptance or implementation authorization.

## Final workspace integrity evidence

Final state remained detached at `e72d34df77a7e42877feb38770100a8b16df7ff0`.

| Command | Exit | Result |
| --- | ---: | --- |
| `git status --short --branch --untracked-files=all` | 0 | `## HEAD (no branch)`; no tracked or ordinary untracked changes reported because the review artifact and generated dependency/build directories match ignore rules. |
| `git status --short --branch --ignored=matching --untracked-files=all` | 0 | `!! dist/`, `!! documents/research-phases/checks/01-independent-rereview-2026-09-13.md`, and `!! node_modules/`. |
| `git diff --exit-code` | 0 | All tracked files are byte-for-byte unchanged from candidate HEAD in the working tree. |
| `git diff --exit-code -- documents/research-phases/checks/01-changes.md documents/research-phases/checks/01-checklist.md documents/research-phases/checks/01-issues.md` | 0 | Historical Phase 01 check files are unchanged. |
| `git diff --exit-code -- README.md src validation vscode-extension` | 0 | Production, presentation, extension, validation, and tracked README files are unchanged. |

The only authored evidence is this ignored, separate review artifact. `node_modules/` resulted from the lockfile install needed to run checks, and `dist/` resulted from the successful build. Neither is tracked. Historical reports and production/test files remain unchanged.
