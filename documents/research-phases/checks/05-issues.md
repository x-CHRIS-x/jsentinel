# Phase 05 Issues, Coordinate Analysis, and Inventory Notes

Date: September 15, 2026.
Branch: `ao/jsentinel-26/phase05-evaluator`.
Manager: Astra coordinator (`jsentinel-4`). Independent verifier: Pending Batch C freeze.

---

## 1. Coordinate Analysis and Column 0 Provenance

Prior evidence noted a discrepancy between web and extension scanner coordinates. A technical inspection of the rule visitors and parser configurations clarifies the exact source of this issue:

### Parser Engine Parity
Both the web scanner ([`src/utils/scannerEngine.js`](file:///C:/Users/johnc/.ao/data/worktrees/jsentinel/jsentinel-26/src/utils/scannerEngine.js)) and the extension scanner ([`vscode-extension/src/scanner/scannerEngine.js`](file:///C:/Users/johnc/.ao/data/worktrees/jsentinel/jsentinel-26/vscode-extension/src/scanner/scannerEngine.js)) use Babel AST parsers (`@babel/standalone` and `@babel/parser`). In Babel:
- `loc.start.line` is 1-indexed.
- `loc.start.column` is 0-indexed (the first character of a line is at index 0).

Neither engine implements a custom 1-indexed column conversion.

### The Column 0 Falsy Fallback Bug
The discrepancy arises from the syntax used to extract AST coordinates in rule visitor handlers:

```javascript
// Pattern A: Falsy fallback used in multiple web rule visitors
column: path.node.loc?.start?.column || 'unknown'

// Pattern B: Nullish coalescing used in other visitors and extension
column: path.node.loc?.start?.column ?? 0
```

When a vulnerability starts at the beginning of a line (`column === 0`):
- Under Pattern A, `0 || 'unknown'` evaluates `0` as falsy and returns string `'unknown'`.
- Under Pattern B, `0 ?? 0` returns integer `0`.

This creates an inconsistency for findings at column 0, where one engine or rule records `'unknown'` while another records `0`. The issue is not an engine-wide 1-indexing offset, but a specific JavaScript truthiness bug on column zero.

### Evaluator Handling
The evaluator's `normalizeFinding` function parses coordinate values strictly:
- String digits `'0'` or integers `0` resolve to numeric `0`.
- String `'unknown'` or non-numeric values resolve to `null`.
- Under `matchColumn: true`, both expected and actual coordinates must be finite numbers; missing coordinates cannot produce false matches.
- Under default `matchColumn: false`, line-level matching is enforced while preserving raw column coordinates for audit.

---

## 2. Resolved Review Findings

### Coordinate Matching Bug (Resolved)
- Prior code executed `Math.abs(actLine - expLine) > policy.locationTolerance`. If `actLine` was undefined, `actLine - expLine` evaluated to `NaN`. Because any comparison `NaN > tolerance` is false in JavaScript, missing coordinates erroneously matched targets.
- Resolved by requiring `Number.isInteger(line) && line > 0` on both expected and actual records.

### Same-Line Duplicate Logic (Resolved)
- Prior code flagged extra findings as duplicates based solely on line number. Two distinct vulnerability sinks on the same line with different columns were incorrectly merged.
- Resolved by checking exact coordinates (`line` and `column`). Distinct columns on the same line are preserved as separate unmatched findings.

### Identical Duplicate Inflation (Resolved)
- When multiple targets existed at the same line, index tracking alone allowed two identical duplicate actual findings to satisfy both targets.
- Resolved by tracking matched actual coordinates. An identical duplicate cannot satisfy a second target; the evaluator reports coordinate ambiguity and marks the second target missed.

### Adapter Input Rejection (Resolved)
- Malformed descriptor objects (e.g. `{ name: 'file.js' }`) without `content`, `code`, or `text()` were previously treated as empty source code and scanned as clean files.
- Resolved by validating file inputs and failing closed with explicit errors.

### Honest Metrics and Ground Truth Separation (Resolved)
- The target-match ratio `matchedFindings / totalActualFindings` is now clearly separated from precision. Adjudicated precision is reported as `null` / `'N/A'` pending manual review.
- Blanket `metadataValid: true` was removed. The evaluator distinguishes structural metadata matches from pending semantic description reviews.

---

## 3. Open Policy Questions for Manager and Chris Review

Before formal freezing in Batch C, the following policy questions require human agreement:

1. **Controlled File Location Matching:**
   - Proposal: Enforce exact line matching (`locationTolerance: 0`) across all 108 controlled benchmark files. Controlled samples contain single, isolated flaw pairs where exact line alignment is verifiable.

2. **Scenario Location Policy:**
   - Proposal: Scenarios contain multi-statement application blocks. We propose keeping matching policies independent of local scanner results. Whether exact line matching or a group-agreed window is used must be settled in Pass A documentation before formal measurement.

3. **Column Matching Policy:**
   - Proposal: Retain `matchColumn: false` as the standard evaluation mode until rule visitors are audited for the column 0 truthiness fallback. Column coordinates remain fully visible in exports.

4. **Unmatched Finding Adjudication Protocol:**
   - Proposal: Maintain all unmatched alerts as `PENDING_MANUAL_GROUND_TRUTH_ADJUDICATION`. Provide a manual review sheet for human researchers to adjudicate whether an unmatched finding is a newly identified true flaw or a false positive.
