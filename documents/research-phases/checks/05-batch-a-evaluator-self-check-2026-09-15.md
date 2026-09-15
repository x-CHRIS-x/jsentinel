# Phase 05 Batch A Self-Check: Evaluator Tooling and Known-Case Verification

- **Evaluation Date:** September 15, 2026 (Asia/Manila)
- **Assigned Session:** AO worker session `jsentinel-26`
- **Model / Harness:** Gemini 3.8 Flash High (Antigravity CLI / Agy, no subagents invoked)
- **Base Commit:** `0a76a2f61dea576a0155153a8e0bad6a4d42fdbb` (Phase 04 acceptance baseline)
- **Implementation Commit:** `98a1f82`
- **Candidate Dataset / Manifest:** Commit `9dc269f`, Manifest Version 1.0.0 (54 Vulnerable, 54 Clean, 8 Scenarios)

---

## 1. External Document Provenance and Evidence Hashes

External reference documents not tracked in the accepted git tree were verified and recorded with their cryptographic hashes:

1. **Chapters I to III Update Checklist:**
   - Local Source Path: `C:/Users/johnc/OneDrive/Desktop/school archive/1.1 antigrav/github repo/jsentinel/documents/research-phases/chapters-1-3-update-checklist.md`
   - Algorithm: SHA-256
   - Hash: `2DF5DB5D38AF018A6503E644E87A3B564D1736CFDE8A1B3F1A6CDCFB9E7375B1`
   - Role: Establishes Pass A (technical method settlement before lab testing) and Pass B (reconciliation after testing).

2. **Workflow Guide Snapshot:**
   - Git Tree Location: `git show a9d64fb:documents/research-phases/WORKFLOW.md`
   - Base Reference: Preserves human authority gates, routing rules, and research boundaries.

3. **Phase 04 Manager Acceptance Document:**
   - Git Tracked Path: `documents/research-phases/checks/04-manager-acceptance-2026-09-15.md`
   - Acceptance Commit: `0a76a2f61dea576a0155153a8e0bad6a4d42fdbb`
   - Base Candidate: `9dc269fa92a3e2979e481d4db42f227b67c0db0b`

---

## 2. Implemented Research Evaluator Architecture

The evaluator tooling was implemented in `validation/evaluator/` without modifying scanner rules, dataset samples, or live chapters:

- **Adapters (`adapters.mjs`):** Unified adapters for the actual web engine (`scanFile` with 24 rules across 8 modules), the actual VS Code extension engine (`scanCode` with 24 rules), and recorded supplied outputs. Retains rule ID, category mapping, line/column coordinates, guidance ID, severity, message, parse errors, and completion state. Enforces the strict rule that empty findings on failed scans must never be inferred as clean negatives.
- **One-to-One Matching Engine (`matching.mjs`):** Implements strict one-to-one matching between expected vulnerabilities and actual findings by rule ID and location. Enforces that one actual finding cannot match two expectations. Flags duplicate findings so they cannot inflate detection counts. Marks unmatched alerts as `PENDING_MANUAL_ADJUDICATION`. Applies an explicit unresolved policy for expectations with null rule IDs.
- **Metrics Calculator (`metrics.mjs`):** Computes distinct measurements with zero-denominator safeguards (returning `null` and `'N/A'`). Isolates the file-level confusion matrix to completed eligible controlled scans. Reports expected-rule recall, finding precision, metadata check accuracies, and advisory counts separately.
- **Result Schema and Validator (`schema.mjs`):** Enforces a versioned JSON schema (`1.0.0`) with validation functions to guarantee report consistency.
- **Central Runner and Exporters (`evaluator.mjs`):** Coordinates multi-file suite evaluation, isolates simulated scenarios, and exports versioned JSON alongside three checkable CSV tables (metrics summary, file results, and finding details).

---

## 3. Disclosed Synthetic Test Cases

All 16 specified evaluator test conditions and adapter error checks were implemented in `fixtures/synthetic-cases.mjs` and verified in `evaluator.test.mjs`:

| Case ID | Condition Checked | Evaluator Behavior | Result |
|---|---|---|---|
| `1` | Correct detection | Matches expected rule and location one-to-one; records TP | PASS |
| `2` | Missing finding | Expected vulnerability with zero actual findings; records FN | PASS |
| `3` | Unrelated alert | Finding with wrong rule or location cannot satisfy target; target is FN; alert is unmatched | PASS |
| `4` | Duplicate findings | Two findings for one target; only first matches; duplicate cannot inflate target count | PASS |
| `5` | Multiple findings (one match) | Three findings for one target; exactly one matches; other two are duplicates or unmatched | PASS |
| `6` | One actual for two targets | Single actual finding cannot satisfy two distinct expectations at the same line | PASS |
| `7` | Parse failure | Adapter records failed scan; empty findings not inferred as clean negative; excluded from N | PASS |
| `8` | Partial scan | Rule error during scan records partial status; excluded from matrix N | PASS |
| `9` | Runtime engine failure | Adapter catches unhandled exception; status marked failed; excluded from matrix N | PASS |
| `10` | Clean negative | Clean file with zero alerts correctly classified as TN | PASS |
| `11` | Clean false positive | Clean file with unexpected alert correctly classified as FP | PASS |
| `12` | Advisory-only (A06) | Clean file with A06 advisory remains TN in vulnerability matrix; advisory tracked separately | PASS |
| `13` | Zero denominator | Suite with 0 completed scans returns null and N/A without NaN or crashing | PASS |
| `14` | Metadata error separation | Detection match succeeds on rule and location; category and severity errors flagged separately | PASS |
| `15` | Scenario segregation | Multi-flaw scenarios excluded from controlled V/C confusion matrix and reported separately | PASS |
| `16` | Unsupported null rule | Expected weakness with null ruleId cannot be claimed; explicit unresolved policy applied | PASS |
| `17` | Web adapter error handling | Live execution on valid code detects eval; handles null inputs and thrown errors safely | PASS |
| `18` | Extension error handling | Live execution on valid code detects eval; handles syntax errors and thrown errors safely | PASS |
| `19` | Schema and exports | Full suite validates against schema 1.0.0; JSON and CSV exports produce valid data | PASS |

---

## 4. Test and Build Execution Evidence

The following commands were executed locally and passed with zero errors:

```bash
# 1. Focused Phase 05 Evaluator Tests (19 tests)
node --test validation/evaluator/evaluator.test.mjs
# Result: 19 passed, 0 failed (427ms)

# 2. Existing Phase 01-04 Validation Regressions (35 tests)
node --test validation/browser-scope.test.mjs validation/html-overlapping.test.mjs validation/validation-handling.test.mjs validation/pilot-manifest.test.mjs
# Result: 35 passed, 0 failed (5948ms)

# 3. Guidance Catalog Regressions (13 tests)
npm run test:guidance
# Result: 13 passed, 0 failed (500ms)

# 4. ESLint Check
npm run lint
# Result: Exited with code 0, clean formatting

# 5. Production Build
npm run build
# Result: Built client environment in 2.18s
```

---

## 5. Disclosed Limitations and Explicit Omissions (NOT RUN)

In accordance with research integrity guidelines, the following tasks were deliberately omitted from Batch A:

1. **Full 116-File Dataset Evaluation:** NOT RUN. Running the full benchmark across all 116 files belongs to Batch B.
2. **Test Package Freeze:** NOT RUN. Freezing package artifacts, SHA-256 digests, and manifest freeze files belongs to Batch C.
3. **Live Chapters I to III Modifications:** NOT RUN. No chapter files or Google Docs were modified.
4. **Survey and Method Promises:** NOT RUN. Methodological commitments and survey protocols were preserved untouched.
5. **Phase 06, 07, and 08 Activities:** NOT RUN. Downstream phases remain unstarted.
6. **Remote Git Actions:** NOT RUN. No `git push`, remote branch creation, pull request, or merge to main was performed.
7. **Group Authority Claims:** No claim of final team or professor approval is made. This report represents autonomous worker self-check evidence for manager review.

---

## 6. Proposed Policies and Questions for Manager / Chris Review

The evaluator exposes configurable policies documented pending human freeze:

1. **Location Matching Tolerance:** Default is exact line matching (`locationTolerance: 0`). A configurable window (`±N` lines) is supported. We propose retaining exact line matching for the controlled 108 files, and considering `±1` line tolerance for multi-statement scenario blocks if agreed.
2. **Column Matching Policy:** Default is `matchColumn: false`. Because the web parser produces 1-indexed columns while the VS Code extension engine carries the documented Phase 03 column offset discrepancy, line-only matching is recommended until column coordinates are normalized across engines.
3. **Adjudication Policy for Unmatched Findings:** Unmatched findings currently receive status `PENDING_MANUAL_ADJUDICATION`. We propose retaining this explicit status so that provisional finding precision does not prematurely treat unmatched alerts as false positives or confirmed weaknesses without human review.
