# Phase 03: Issues and Review Disclosures

Branch: `ao/jsentinel-22/phase03-findings-scoring`
Date: September 14, 2026
Base: `4a22c67953f52cb9356f5de5dbd6cacf79329f40` (`4a22c67`)
Candidate: `caa5e6c22f1fb22683c1932746cb7b6ff772a8dd` (`caa5e6c`)

**Status: Worker self-check completed. Independent verification and manager acceptance PENDING.**

---

## Resolved Phase 03 Defects

### P3-V01: Overlapping HTML Findings on Dynamic Template Literal Assignments

- **Previous Behavior**: An unsafe assignment like `elem.innerHTML = \`<p>${user}</p>\`;` triggered both `OWASP-A03-004` (template literal) and `OWASP-A03-006` (innerHTML). Because both rules carry a HIGH severity (10-point penalty), the scanner deducted 20 points from the project score (resulting in score 80) for a single unsafe assignment.
- **Resolution**: Implemented prioritized deduplication at the scanner output boundary in both engines (`src/utils/scannerEngine.js` and `vscode-extension/src/scanner/scannerEngine.js`). When findings share an assignment expression, `OWASP-A03-004` takes precedence over `OWASP-A03-006`, leaving exactly one finding and a single 10-point deduction (score 90).

### P3-V02: Overlapping HTML Findings on Function Return Assignments

- **Previous Behavior**: An assignment like `elem.innerHTML = render(user);` triggered both `OWASP-A03-005` (function call result) and `OWASP-A03-006` (innerHTML), producing two HIGH severity findings and deducting 20 points for one assignment.
- **Resolution**: Under the same deduplication logic, `OWASP-A03-005` takes precedence over `OWASP-A03-006`, resulting in exactly one finding and a single 10-point deduction.

### P3-V03: Web Engine Column 0 Coordinate Discrepancy

- **Previous Behavior**: In `src/scanner/rules/injection.js` and `src/scanner/rules/xss.js`, coordinates were assigned with `path.node.loc?.start?.column || 'unknown'`. In JavaScript, numeric 0 is falsy, causing assignments at column 0 to record `'unknown'` instead of 0. The extension engine used `|| 0`, recording numeric 0.
- **Resolution**: Normalized the column fallback using nullish coalescing (`path.node.loc?.start?.column ?? 0`) across `OWASP-A03-004`, `OWASP-A03-005`, and `OWASP-A03-006`. Both engines now report numeric 0 for column 0 assignments.

---

## Disclosed Review Limitations

The following items are accepted scope boundaries for Phase 03:

1. **Local Syntactic Assignment Matching**:
   - Deduplication groups HTML findings by their AST assignment expression start coordinates (`line` and `column`).
   - Distinct assignments on the same line (such as `a.innerHTML = x; b.innerHTML = y;`) start at different columns and are treated as separate assignments, each receiving its own finding.

2. **No Dataflow Analysis for Markup Sanitization**:
   - The scanner operates via AST pattern matching. If a function call returns pre-sanitized HTML (e.g. `elem.innerHTML = DOMPurify.sanitize(input);`), `OWASP-A03-005` is still emitted unless a dedicated sanitizer bypass rule is introduced in a future phase.
   - Tracing sanitizer dataflow across variables or imports is outside the scope of Phase 03.

3. **Historical Saved Scans Untouched**:
   - Historical scan objects loaded from `localStorage` retain the findings, active counts, and scores they were saved with.
   - The application does not silently rewrite or recalculate historical scan data upon loading. New scans run under the corrected deduplication logic.

4. **Aggregate Score Definition**:
   - The JSentinel project security score is an internal static heuristic calculated as `Math.max(0, 100 - penalty)`, where fixed deduction weights correspond to finding severities (CRITICAL: 20, HIGH: 10, MEDIUM: 5, LOW: 1).
   - This score represents a static defect penalty summary. It is not an empirical detection accuracy percentage and is not a FIRST-issued CVSS project score.

5. **VS Code GUI Testing Scope**:
   - The extension scanner engine and its exported deduplication helper were verified programmatically via Node test suites (`browser-scope.test.mjs`, `html-overlapping.test.mjs`) ensuring exact output parity with the web engine.
   - Interactive VS Code editor decorations and sidebar webview rendering were verified through structural unit tests rather than a live VS Code window.

6. **Boundary Discipline**:
   - No Phase 04 work was started.
   - No edits were made to the 116-file benchmark dataset or dataset evaluator.
