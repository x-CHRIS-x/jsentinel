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

---

## 4. Benchmark Run Observations (Phase 05 Batch B)

Execution of `validation/evaluator/runner.mjs` across both engines over all 116 files produced the following specific observations:

### Observation 1: The Single False Positive (`C-A1-001.js`)
In the controlled evaluation matrix (N = 108), exactly one clean file produced a vulnerability alert:
- Sample: `C-A1-001.js` (clean partner for `V-A1-001.js`, Broken Access Control).
- Detected alert: `OWASP-A08-001` (A08: Software and Data Integrity Failures, LOW severity) on line 9.
- Code snippet: `const parsed = JSON.parse(userInput);`
- Root cause: The clean sample remediates direct object references by validating user authorization, but utilizes `JSON.parse(userInput)` to unpack data. Rule `OWASP-A08-001` flags unvalidated `JSON.parse` calls. Because `C-A1-001.js` is labeled "clean", this in-scope alert correctly classifies the file as a False Positive in the binary matrix, and the alert is routed to `unmatched` with status `PENDING_MANUAL_ADJUDICATION`.

### Observation 2: The Nine False Negatives (FN = 9)
Nine vulnerable samples produced zero in-scope vulnerability alerts:
1. `V-A10-053.js`: Client fetch to arbitrary URL with ambient credentials enabled. Expected rule is `null` (unsupported weakness).
2. `V-A10-054.js`: Dynamic script element injection. Expected rule is `null` (unsupported weakness).
3. `V-A6-033.js`: Window postMessage with wildcard `*` target origin. Expected rule is `null` (unsupported weakness).
4. `V-A2-018.js`: Missed detection for `OWASP-A02-003` (insecure cipher algorithm).
5. `V-A6-036.js`: Missed detection for `OWASP-A05-003` (verbose error leakage).
6. `V-A6-037.js`: Missed detection for `OWASP-A02-004` (hardcoded key).
7. `V-A7-042.js`: Missed detection for `OWASP-A03-007` (outerHTML XSS).
8. `V-A9-051.js`: Missed detection for `OWASP-A07-001` (hardcoded password).
9. `V-A9-052.js`: Missed detection for `OWASP-A02-007` (storage token).

Three of the nine false negatives stem from documented gaps in scanner rule coverage (`ruleId: null, unsupported: true` in `dataset-manifest.json`). The remaining six are genuine scanner rule misses under AST visitor analysis. The benchmark faithfully reports an 83.33% file-level recall without altering ground-truth labels.

### Observation 3: Adjudication Status of Unmatched Findings
Across all 108 completed controlled scans, there are 52 actual vulnerability alerts:
- 51 findings match expected vulnerability targets one to one.
- 0 duplicate findings were reported.
- Exactly 1 finding is unmatched (`OWASP-A08-001` on `C-A1-001.js`).
Because this finding is unreviewed, adjudicated finding precision is reported as `N/A`. The target-match fraction is 98.08% (51 / 52).

### Observation 4: Node Execution Timing Boundary
The execution durations recorded in `run_metadata.json` (2,680.6ms for Web, 326.0ms for Extension across 116 files) represent local Node.js AST parsing and visitor traversal. They do not measure web browser DOM rendering, UI event handling, or VS Code extension host latency on physical AU laboratory computers. Chapter III and Pass A explicitly define this boundary.

---

## 5. Resolved Review Deficiencies (Phase 05 Batch B/C Corrections)

Following coordinator inspection, five technical review deficiencies were resolved:

### Deficiency 1: Dynamic Ingestion in Package Metadata Generator
- Prior implementation hardcoded observed metrics, attempts, evaluatorCommit, branch, and unmatched finding identities.
- Resolved by rewriting `scripts/generate-candidate-package-metadata.mjs` to ingest `evaluation_report.json` and `run_metadata.json` dynamically from disk, extract live Git and package versions, and enforce exact manifest counts (54V, 54C, 8 scenarios, 116 total).

### Deficiency 2: Adjudication Double-Counting and Scenario Segregation
- Prior template generation included both matched targets and scenario findings. When applied, `applyAdjudication` added `matchedFindings` twice and admitted scenario findings into the controlled precision denominator.
- Resolved by introducing explicit finding scope (`'controlled' | 'scenario'`) and kind (`'unmatched' | 'matched' | 'duplicate'`). Controlled precision inspects only completed controlled unmatched findings, adding reviewed true positives to automated target matches without double-counting. Scenario findings are segregated.

### Deficiency 3: Runner Evidence Protection
- Prior runner defaulted to `runs/phase05-batch-b` without verifying whether the directory already contained files.
- Resolved by adding destination checks that refuse to overwrite populated folders. New runs are versioned (`phase05-batch-b-corr1`), and the runner accepts CLI reproduction flags.

### Deficiency 4: Pass A Lifecycle and Paper Sourcing
- Prior draft claimed Chris authored the AI draft, asserted that protocols were agreed/locked down, omitted the file-size protocol, and misstated the transfer timing as Pass B / Phase 08.
- Resolved by updating `05-pass-a-technical-method-draft.md` to clearly state it is an AI draft for group review, establishing that the agreed method must be transferred to the shared Google Doc during Pass A before Phase 07, defining the file-size measurement protocol, and sourcing survey details directly to `documents/MD/Final-Grp13-IT225-Chapters123-Aug25-2026.md`.


