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
├── adjudication.mjs        # Schema-validated human ground-truth adjudication module
├── runner.mjs              # Reproducible benchmark runner across all 116 manifest files
├── fixtures/
│   └── synthetic-cases.mjs # 20 disclosed synthetic test cases
└── evaluator.test.mjs      # 33 targeted unit and integration test cases
```

---

## 4. Batch B: Local Benchmark Execution and Adapter Edge-Case Hardening

Following manager authorization in commit `4bde58f`, Batch B implemented the benchmark runner, human adjudication module, and final adapter edge cases.

### Adapter Edge-Case Fixes
1. **Valid Empty-String Source:** Empty string `''` source files now scan normally as clean completed files. The adapter null-check was updated from `if (!fileInput)` to `if (fileInput === null || fileInput === undefined)`, allowing empty JavaScript code to parse cleanly into an empty AST Program.
2. **Malformed Descriptor Rejection:** Input objects missing valid file content (such as `{ name: 'foo.js' }`) fail closed immediately with a documented error.
3. **Fail-Closed Status Normalization:** If a scan result contains an unknown status, it fails closed to `'failed'`. If a raw result specifies `completed: false` or `status: 'partial'`, it is preserved as `'partial'`, while unhandled engine errors or parse errors take precedence as `'failed'`.

### Human Adjudication Engine (`validation/evaluator/adjudication.mjs`)
Implemented schema 1.0.0 validation for human review of unmatched findings. The module enforces:
- Explicit review fields: `disposition` (`TRUE_POSITIVE`, `FALSE_POSITIVE`, `PENDING`), `rationale`, and `reviewer`.
- Semantic description check: `matchesExpectedWeakness` boolean and `notes`.
- Duplicate precision policy: `duplicatePrecisionEligibility` (`EXCLUDE_FROM_PRECISION` vs `COUNT_AS_FP`).
- Strict validation: Rejects unknown sample keys, duplicate keys, and invalid disposition values.

### Local Benchmark Execution Over Accepted 116 Files
The benchmark runner (`validation/evaluator/runner.mjs`) executed both the Web and Extension engines across all 116 manifest files. This produced 232 total scan attempts (116 Web, 116 Extension; 108 controlled files and 8 scenarios each).

Run outputs are isolated in versioned directories:
- `validation/evaluator/runs/phase05-batch-b/web/`
- `validation/evaluator/runs/phase05-batch-b/extension/`

Each directory retains `evaluation_report.json`, `metrics_summary.csv`, `file_results.csv`, `findings_details.csv`, and `run_metadata.json`.

Key Benchmark Findings:
- Total attempts: 116 files per engine (232 total).
- Completion: 116 completed, 0 partial, 0 failed, 0 unattempted.
- Controlled Confusion Matrix (N = 108):
  - True Positives (TP): 45
  - True Negatives (TN): 53
  - False Positives (FP): 1 (`C-A1-001.js` triggers `OWASP-A08-001` on line 9 `JSON.parse(userInput)`)
  - False Negatives (FN): 9 (3 unsupported weaknesses: `V-A10-053`, `V-A10-054`, `V-A6-033`; 6 rule misses: `V-A2-018`, `V-A6-036`, `V-A6-037`, `V-A7-042`, `V-A9-051`, `V-A9-052`)
  - Accuracy: 90.74% (98 / 108)
  - Precision: 97.83% (45 / 46)
  - Recall: 83.33% (45 / 54)
  - Specificity: 98.15% (53 / 54)
  - False Positive Rate: 1.85% (1 / 54)
  - False Negative Rate: 16.67% (9 / 54)
- Expected-Rule Recall: 85.00% (51 matched out of 60 expected vulnerabilities across completed scans).
- Finding Precision: Total in-scope alerts: 52; matched targets: 51; duplicates: 0; unmatched: 1. Target-match fraction is 98.08% (51 / 52). Adjudicated precision is reported as `N/A` pending human review.

---

## 5. Batch C: Candidate Package Metadata and Pass A Method Draft

### Candidate Package Metadata
Generated `documents/research-phases/checks/05-candidate-package-metadata.json` capturing SHA-256 hashes across:
- All 116 dataset sample files in `test-samples/samples/`
- Dataset manifest `test-samples/dataset-manifest.json` (version 1.0.0, base commit `0a76a2f`)
- Scanner source files across web and extension engines (17 files)
- Active rule registry inventory (24 rules: 23 vulnerability rules and 1 advisory rule)
- Evaluator modules (9 files)

The package is explicitly labeled `PROPOSED / UNFROZEN` with group freeze status `PENDING_GROUP_ADOPTION`.

### Pass A Technical Method Checkpoint Draft
Drafted `documents/research-phases/checks/05-pass-a-technical-method-draft.md` covering all Pass A items:
1. 116-file Table 1 distribution (54V, 54C, 8 scenarios).
2. Ground-truth provenance (AI completed, human review pending).
3. One-file test unit definition.
4. Separation of file matrix, expected-rule recall, finding precision, and scenario observations.
5. Proposed AU laboratory testing protocol with timing boundary labeled "Node development environment only".
6. Survey methodology preserving 40 user and 10 technical respondents, 10 items, 5 criteria, and explicit denominator rules.
7. Google Doc transfer gate preserving live Chapter I through III documents until group review and adoption.

