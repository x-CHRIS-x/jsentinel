# Phase 05 Changes: Research Evaluator Implementation and Batch A Corrections

Branch: `ao/jsentinel-26/phase05-evaluator`. Date: September 15, 2026.
Session: AO worker `jsentinel-26`. Model route: Agy with Gemini 3.8 Flash (High).
Manager: Astra coordinator (`jsentinel-4`). Independent verifier: Pending Batch C freeze.

---

## 1. Commit and Branch Reference

- Comparison Base: `0a76a2f61dea576a0155153a8e0bad6a4d42fdbb` (docs(phase04): record Astra manager acceptance assessment).
- Accepted Phase 04 Chain: `fd17002`, `c650be9`, `38c1562`, `e21f77f`, `845bfea`, `9a7d50c`, `c697802`, `9dc269f`, `fd2d64d`, `f2cae08`, `7463da7`, `0a76a2f`.
- Initial Phase 05 Batch A Commits:
  - `98a1f82`: `feat(phase05): implement research evaluator, scanner adapters, and known-case tests`
  - `e38610a`: `docs(phase05): record Batch A evaluator self-check and known-case evidence`
- Corrected Implementation Commit:
  - `459c82a`: `fix(phase05): correct evaluator adapters, matching coordinates, and completion tracking`
- Scope: Phase 05 Batch A bounded evaluator research tooling, actual-scanner adapters, result schema, and known-case tests. Corrects the 7 defect areas identified in manager review without altering dataset files, scanner detection rules, or paper text.

---

## 2. Bounded Corrections Addressing Manager Review

Following Astra coordinator review of commits `98a1f82` and `e38610a`, seven specific defect categories were resolved across the evaluator modules:

### Defect 1: Fail-Closed Adapter Normalization and Input Validation
- **Problem:** `normalizeScanResult` defaulted empty objects `{}` or missing `issues` arrays to completed success. It ignored explicit flags like `status: 'partial'`, `status: 'failed'`, `completed: false`, and `ruleErrors`. Input objects lacking valid file content became empty string successful scans.
- **Correction:** Implemented strict input validation in `scanWithWebAdapter` and `scanWithExtensionAdapter`. Non-string inputs must be descriptors containing executable `text()`, `content` string, or `code` string; otherwise, they fail closed immediately. `normalizeScanResult` now validates that `issues` is a true array, respects explicit status and completion properties, preserves `ruleErrors` and `parseError`, and marks contradictory results as partial or failed.

### Defect 2: Finite Coordinate Requirements and Policy Validation
- **Problem:** Location matching executed `Math.abs(undefined - expLine) > tolerance`. Because `NaN > tolerance` is false in JavaScript, findings with missing or non-numeric line numbers were admitted as valid matches. In addition, `DEFAULT_MATCHING_POLICY` contained unsupported no-op knobs (`strict`, `strict_fp`).
- **Correction:** Implemented strict finite coordinate checks in `matching.mjs`. Both expected and actual lines must be positive integers (`Number.isInteger(line) && line > 0`). When `matchColumn: true` is configured, both sides must possess finite numeric column coordinates. Removed dead policy knobs and added `validateMatchingPolicy` to enforce non-negative integer tolerances, boolean flags, and string prefix arrays.

### Defect 3: Same-Line Coordinate Preservation and Duplicate Ambiguity
- **Problem:** Duplicate classification compared only `ruleId` and `line`, treating distinct findings at different columns on the same line as duplicates. Under a line-only policy, index usage alone allowed identical duplicate findings to satisfy multiple distinct expectations at that line.
- **Correction:** In `matching.mjs`, an extra finding is classified as a duplicate if and only if it shares identical rule and coordinates (`line` and `column`) with an already-matched finding. Distinct columns on the same line remain separate unmatched findings. Identical duplicate actuals cannot satisfy subsequent distinct expectations: the evaluator flags them with coordinate ambiguity and records them as missed.

### Defect 4: Retention of Complete Raw Outputs and Scenario Unsupported Weaknesses
- **Problem:** `evaluateSuite` gathered raw engine results during evaluation but omitted them from the exported report. Furthermore, `unsupportedWeaknesses` from scenario manifest entries were dropped from `scenarioObservations`.
- **Correction:** Added `rawScanResults` to the evaluation result object and the versioned schema (`schema.mjs`). `evaluateSuite` now copies manifest `unsupportedWeaknesses` directly into each scenario observation record.

### Defect 5: Unattempted Scans, Completion Breakdown, and Controlled Eligibility
- **Problem:** Missing scan entries fabricated `attempted: true`. Completion totals omitted scenarios, and non-controlled or invalid labels were not categorized explicitly.
- **Correction:** In `evaluator.mjs`, missing scan results are recorded as `status: 'unattempted'` with `attempted: false`. `metrics.mjs` distinguishes `overallCompletion` (attempted, unattempted, completed, partial, failed), `scenarioCompletion`, and `controlledEligibility` (eligible vs excluded with explicit reasons: `EXCLUDED_UNATTEMPTED`, `EXCLUDED_INCOMPLETE_PARTIAL`, `EXCLUDED_INCOMPLETE_FAILED`, `EXCLUDED_INVALID_LABEL`, `EXCLUDED_SCENARIO`).

### Defect 6: Target-Match Fraction vs Adjudicated Finding Precision
- **Problem:** The ratio `matchedFindings / totalActualFindings` was labeled provisional precision, and `metadataValid: true` implied that manual semantic description checks had passed.
- **Correction:** Relabeled the ratio to `targetMatchFraction` with explicit formula documentation. Final adjudicated precision is kept strictly as `null` / `'N/A'` pending manual review. Replaced blanket `metadataValid: true` with `structuralMetadataMatch` and explicit pending statuses (`semanticDescriptionStatus: 'PENDING_MANUAL_SEMANTIC_REVIEW'`, `adjudicatedMetadataStatus: 'PENDING_MANUAL_REVIEW'`).

### Defect 7: Accurate Column Indexing Evidence and Phase Guide Checkmark Reconciliation
- **Problem:** Prior self-check evidence claimed web columns were 1-indexed. In reality, both web and extension engines use Babel's 0-indexed column parser (`path.node.loc.start.column`). The known Phase 03 discrepancy is that certain rule visitors used `col || 'unknown'`, which treated column 0 as falsy and fell back to string `'unknown'`. Also, premature checkmarks were placed in `05-evaluator-and-freeze.md`.
- **Correction:** Documented the exact column 0 fallback mechanism with code evidence. Reverted premature checkmarks in `05-evaluator-and-freeze.md` to pending manager review. Preserved prior reports intact and created separate correction records.

---

## 3. Inventory of Evaluator Modules

```text
validation/evaluator/
├── index.mjs               # Public exports including JSentinelEvaluator and validator
├── schema.mjs              # Schema 1.0.0 definition and validation
├── adapters.mjs            # Web, extension, and supplied engine adapters
├── matching.mjs            # One-to-one rule and coordinate matching
├── metrics.mjs             # Completion, confusion matrix, rates, and precision
├── evaluator.mjs          # Central runner and CSV/JSON export pipeline
├── fixtures/
│   └── synthetic-cases.mjs # 20 disclosed synthetic test cases
└── evaluator.test.mjs      # 27 targeted test cases
```
