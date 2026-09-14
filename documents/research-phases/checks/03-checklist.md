# Phase 03: Verification Checklist

Branch: `ao/jsentinel-22/phase03-findings-scoring`
Date: September 14, 2026
Implementation commit: `caa5e6c22f1fb22683c1932746cb7b6ff772a8dd` (`caa5e6c`)
Comparison base: `4a22c67953f52cb9356f5de5dbd6cacf79329f40` (`4a22c67`)

**Worker Self-Check Result: SATISFIED (Ready for Independent Verification).**
**Independent Verdict: PENDING. Manager Acceptance: PENDING.**

This checklist evaluates candidate `caa5e6c` against the requirements specified in Phase 03 ([03-findings-and-scoring.md](../03-findings-and-scoring.md)).

---

## Check 1: Dynamic Template Assignment

- [x] One dynamic template assignment produces one applicable HTML finding and deduction.

**Self-Check Result: SATISFIED**

**Evidence:**
- Code: `container.innerHTML = \`<div class="card">${username}</div>\`;`
- Before the fix, both `OWASP-A03-004` (template literal) and `OWASP-A03-006` (innerHTML) fired, deducting 20 points (score 80).
- After the fix, `OWASP-A03-004` is prioritized over `OWASP-A03-006`. Exactly one finding is returned with severity HIGH.
- `calculateStats` yields `totalIssues: 1`, `activeIssuesCount: 1`, `highIssues: 1`, and `securityScore: 90` (a single 10-point deduction).
- Verified in `validation/html-overlapping.test.mjs` (Regression A) across both web and extension engines.

---

## Check 2: Function-Result Assignment

- [x] One function-result assignment produces one applicable HTML finding and deduction.

**Self-Check Result: SATISFIED**

**Evidence:**
- Code: `container.innerHTML = renderCard(username);`
- Before the fix, both `OWASP-A03-005` (function return) and `OWASP-A03-006` (innerHTML) fired, deducting 20 points (score 80).
- After the fix, `OWASP-A03-005` is prioritized over `OWASP-A03-006`. Exactly one finding is returned with severity HIGH.
- `calculateStats` yields `totalIssues: 1`, `activeIssuesCount: 1`, `highIssues: 1`, and `securityScore: 90` (a single 10-point deduction).
- Verified in `validation/html-overlapping.test.mjs` (Regression B) across both web and extension engines.

---

## Check 3: Generic Assignment

- [x] A generic assignment still receives its applicable check.

**Self-Check Result: SATISFIED**

**Evidence:**
- Code: `container.innerHTML = rawMarkup;`
- Neither A03-004 nor A03-005 matches non-template, non-call assignments.
- `OWASP-A03-006` fires and survives deduplication as the sole applicable finding.
- `calculateStats` yields `totalIssues: 1`, `activeIssuesCount: 1`, `highIssues: 1`, and `securityScore: 90`.
- Verified in `validation/html-overlapping.test.mjs` (Regression C) across both web and extension engines.

---

## Check 4: Two Separate Unsafe Assignments

- [x] Two separate unsafe assignments remain two findings.

**Self-Check Result: SATISFIED**

**Evidence:**
- Tested distinct assignments on the same line: `a.innerHTML = \`<p>${x}</p>\`; b.innerHTML = render(y);`
- Both assignments share line 1, but start at distinct columns (column 0 and column 27).
- Each assignment expression deduplicates independently against its own location: Assignment 1 produces `OWASP-A03-004`, Assignment 2 produces `OWASP-A03-005`.
- Both findings survive. `calculateStats` yields `totalIssues: 2`, `activeIssuesCount: 2`, and `securityScore: 80` (two 10-point deductions).
- Also verified for two generic assignments on the same line (`a.innerHTML = x; b.innerHTML = y;`), producing two surviving `OWASP-A03-006` findings.
- Verified in `validation/html-overlapping.test.mjs` (Regression D) across both web and extension engines.

---

## Check 5: Unrelated Vulnerability at the Same Location

- [x] An unrelated vulnerability at the same location is retained.

**Self-Check Result: SATISFIED**

**Evidence:**
- Deduplication is strictly scoped to the three overlapping HTML rules (`OWASP-A03-004`, `OWASP-A03-005`, `OWASP-A03-006`).
- When an unrelated vulnerability shares coordinates with an innerHTML assignment (such as `OWASP-A02-001` or `OWASP-A03-001`), the unrelated finding is ignored during HTML deduplication and survives.
- Verified unit-level preservation with mixed issue lists and verified rule execution with `eval(userInput); container.innerHTML = \`<p>${userInput}</p>\`;` in `validation/html-overlapping.test.mjs` (Regression E).

---

## Check 6: Both Scanners Parity

- [x] Both scanners and their report consumers agree on counts and deductions.

**Self-Check Result: SATISFIED**

**Evidence:**
- Tested all 116 existing dataset samples across both engines via `validation/browser-scope.test.mjs`. All 116 samples parse with 0 errors and produce identical normalized finding locations and classifications.
- Tested multiple HTML assignment patterns in `validation/html-overlapping.test.mjs` (Regression F). Normalized findings (`[id, line, column, severity, findingType]`) match between web and extension engines across all scenarios.
- Web cards, extension diagnostics, sidebar, PDF exporter, and JSON exporter consume the deduplicated list directly from scanner output.
- Verified in `validation/html-overlapping.test.mjs` (Regressions F and G).

---

## Check 7: Advisory-Only A06 Excluded from Totals and Score

- [x] Advisory-only A06 signals are shown separately and do not alter vulnerability totals or the project score in new scans.

**Self-Check Result: SATISFIED**

**Evidence:**
- For `import axios from "axios";`, `OWASP-A06-001` is emitted with `findingType: 'advisory'` and `severity: 'INFORMATIONAL'`.
- `calculateStats` records `advisoryCount: 1`, `activeAdvisoryCount: 1`, `totalIssues: 0`, `activeIssuesCount: 0`, and `securityScore: 100`.
- In mixed files containing both an advisory and a template vulnerability, the advisory remains visible while only the vulnerability is counted and deducted (`totalIssues: 1`, `advisoryCount: 1`, `securityScore: 90`).
- Verified in `validation/html-overlapping.test.mjs` (Regressions H and I) across both web and extension engines.

---

## Check 8: Historical Saved Scans Preservation

- [x] Do not silently recalculate historical scans under the new behavior.

**Self-Check Result: SATISFIED**

**Evidence:**
- In `src/App.jsx`, `scanHistory` loads stored scans from `localStorage` directly without re-evaluating rules or recomputing stats.
- Verified in `validation/html-overlapping.test.mjs` (Regression J) that deserialized historical records preserve their recorded finding counts and scores (e.g. `totalIssues: 2`, `securityScore: 80`), while new scans run under corrected deduplication logic (`totalIssues: 1`, `securityScore: 90`).
