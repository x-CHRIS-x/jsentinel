# Phase 03: Changes and Implementation Review Target

Branch: `ao/jsentinel-22/phase03-findings-scoring`
Date: September 14, 2026

## Commit References

- Comparison base: `4a22c67953f52cb9356f5de5dbd6cacf79329f40` (Phase 02 accepted commit).
- Implementation commit: `caa5e6c22f1fb22683c1932746cb7b6ff772a8dd` (`caa5e6c`), "fix(phase03): resolve overlapping HTML findings with prioritized assignment deduplication".
- Candidate self-check status: SATISFIED on worker self-check.
- Independent audit status: PENDING. Independent verification and manager acceptance have not yet been performed.

## Implementation Files Changed

| File | Change | Consequence |
| --- | --- | --- |
| `src/utils/scannerEngine.js` | Added `deduplicateOverlappingHtmlIssues` at the scanner output boundary in `scanFile`. | Web scanner outputs exactly one prioritized finding per HTML assignment expression before consumer processing. |
| `vscode-extension/src/scanner/scannerEngine.js` | Added identical `deduplicateOverlappingHtmlIssues` at the scanner output boundary in `scanCode`. | Extension scanner outputs exactly one prioritized finding per HTML assignment expression, maintaining engine parity. |
| `src/scanner/rules/injection.js` | Updated line and column fallbacks for `OWASP-A03-004` and `OWASP-A03-005` using nullish coalescing for column 0. | Eliminates `'unknown'` string on column 0 in web engine, matching extension coordinate behavior. |
| `src/scanner/rules/xss.js` | Updated line and column fallbacks for `OWASP-A03-006` using nullish coalescing for column 0. | Eliminates `'unknown'` string on column 0 in web engine, matching extension coordinate behavior. |
| `validation/html-overlapping.test.mjs` | Created dedicated regression test suite covering Regressions A through J across both engines. | Verifies single deductions, prioritization order, distinct assignments, unrelated vulnerabilities, parity, advisory handling, and history preservation. |

## Detailed Technical Changes

1. **Prioritized HTML Finding Deduplication at Scanner Output Boundary**:
   - The scanner engines coordinate rule execution by collecting issues emitted by individual visitors.
   - For unsafe assignments to `innerHTML`, multiple rules fire on the same assignment expression: `OWASP-A03-004` (dynamic template literal), `OWASP-A03-005` (function call result), and `OWASP-A03-006` (general innerHTML).
   - In both `scanFile` (`src/utils/scannerEngine.js`) and `scanCode` (`vscode-extension/src/scanner/scannerEngine.js`), `deduplicateOverlappingHtmlIssues` runs immediately after rule execution and coordinate attachment.
   - For findings sharing the same assignment coordinates, the priority order is enforced:
     1. `OWASP-A03-004` (template-specific)
     2. `OWASP-A03-005` (function-result)
     3. `OWASP-A03-006` (general innerHTML)

2. **Preservation of Distinct Assignments and Unrelated Vulnerabilities**:
   - Deduplication is strictly scoped to the three overlapping HTML rules (`OWASP-A03-004`, `OWASP-A03-005`, `OWASP-A03-006`).
   - Assignment expressions are identified by their start coordinates (`line` and `column`).
   - Distinct assignments on the same line (such as `a.innerHTML = x; b.innerHTML = y;`) start at different columns and both survive.
   - Unrelated vulnerabilities at the same line or location (such as `OWASP-A02-001` or `OWASP-A03-001`) are not members of the HTML rule set and are never suppressed.

3. **Survivor Integrity and Scoring**:
   - The surviving finding retains all original properties: `id`, `guidanceId`, `severity`, `line`, `column`, `sourceLine`, `message`, `suggestion`, `cvssBaseScore`, and `cvssVector`.
   - The existing severity penalty weights in `calculateStats` (`CRITICAL: 20`, `HIGH: 10`, `MEDIUM: 5`, `LOW: 1`) are untouched.
   - A single surviving HIGH finding incurs a single 10-point penalty, yielding a score of 90 rather than the previous double deduction of 20 points (score 80).
   - The aggregate score is a JSentinel static heuristic based on pattern deduction weights. It is not detection accuracy and not a FIRST-issued CVSS project score.

4. **Coordinate Parity on Column 0**:
   - In `src/scanner/rules/injection.js` and `src/scanner/rules/xss.js`, coordinate assignments originally used `column: path.node.loc?.start?.column || 'unknown'`.
   - Because 0 is falsy in JavaScript, assignments at column 0 evaluated to `'unknown'` in the web engine, while the extension used `|| 0` evaluating to `0`.
   - The web rules now use `column: path.node.loc?.start?.column ?? 0`, ensuring both engines output numeric 0 for column 0 assignments.

5. **Product Boundary and Historical Data Preservation**:
   - Web cards, extension diagnostics, sidebar views, PDF export, and JSON export consume the scanner engine output directly and receive the deduplicated issues list.
   - False-positive exemptions continue to match on `${fileName}:${issue.id}:${issue.line}:${issue.column}`.
   - Historical saved scan records in `localStorage` are loaded without re-scanning or recalculation, preserving legacy records exactly as stored.

## Verification Commands and Results

1. **Test Suite Execution**:
   - Command: `node --test validation/validation-handling.test.mjs validation/browser-scope.test.mjs validation/guidance.test.cjs validation/html-overlapping.test.mjs`
   - Exit code: 0
   - Result: 40 tests passed, 0 failed, duration 3.8s.
   - Coverage: All 30 baseline tests pass (including 116/116 sample engine parity), plus 10 new regression tests (Regressions A through J).

2. **Linter Execution**:
   - Root command: `npm run lint` (ESLint on web codebase)
   - Exit code: 0 (0 errors, 0 warnings)
   - Extension command: `npm --prefix vscode-extension run lint` (ESLint on extension codebase)
   - Exit code: 0 (0 errors, 0 warnings)

3. **Web Production Build**:
   - Command: `npm run build` (Vite build)
   - Exit code: 0 (built in 2.05s)
