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

---

## 6. Batch B/C Corrections Addressing Manager Review

Following coordinator review of commits `5239da9` and `ab37e50`, six specific defect areas were addressed across the evaluator modules, runner, candidate package metadata generator, and Pass A draft:

### Defect 1: Dynamic Package Metadata Generation and Manifest Verification
- **Problem:** `scripts/generate-candidate-package-metadata.mjs` hardcoded observed metrics, attempts, evaluatorCommit, branch, and unmatched findings. Scenario files evaluated to 0 because workloadType was checked against `scenario` instead of `simulated-browser-workload` or `label === 'scenario'`.
- **Correction:** Rewrote the script to ingest actual versioned per-engine reports (`evaluation_report.json`) and run metadata (`run_metadata.json`) dynamically. Dynamically queries Git full and short commit hashes, working tree cleanliness, branch, package version, and tool dependencies. Enforces manifest consistency: derives 54 vulnerable, 54 clean, 8 scenarios (116 total), throwing an error upon any discrepancy. Extracts unmatched findings list directly from the reports with zero hardcoding.

### Defect 2: Adjudication Scoping and Double-Counting Prevention
- **Problem:** `adjudication.mjs` template included matched and scenario findings without proper scoping. `applyAdjudication` counted all entries with `TRUE_POSITIVE`/`FALSE_POSITIVE` and then added `matchedFindings` again, double-counting matched targets and allowing scenario findings to contaminate controlled precision.
- **Correction:** Implemented explicit finding scope (`'controlled' | 'scenario'`) and kind (`'unmatched' | 'matched' | 'duplicate'`). Canonical keys now incorporate engine, sampleId, ruleId, location, and kind. The validation engine checks input documents against actual evaluation results, rejecting unknown, duplicate, or cross-run keys. Controlled precision inspects only completed controlled unmatched findings, adding reviewed TP strictly to automated matched targets without double counting. Completed dispositions require non-empty `reviewer`, `rationale`, and valid `reviewDate`. Semantic review denominator is strictly matched targets in completed controlled scans.

### Defect 3: Runner Immutability and Evidence Destination Protection
- **Problem:** `runner.mjs` defaulted to a fixed output folder (`runs/phase05-batch-b`) and could overwrite existing evidence.
- **Correction:** Added destination protection that checks if the output folder exists and contains files; if so, it throws an error and refuses to overwrite. Exposed CLI arguments (`--output-dir`, `--run-id`, `--manifest`, `--samples-dir`). Created new versioned run directory `validation/evaluator/runs/phase05-batch-b-corr1`, preserving the original `phase05-batch-b` evidence intact. Recorded dependency versions from `package.json`, Git provenance, and raw errors.

### Defect 4: Pass A Technical Method Checkpoint Revision
- **Problem:** Prior draft claimed Chris as author of the AI draft, described arrangements as agreed or locked down, omitted the file-size measurement protocol, claimed uninstrumented separate parse/rule timings, misstated N as fixed 108, and placed shared Google Doc transfer in Pass B / Phase 08.
- **Correction:** Revised `05-pass-a-technical-method-draft.md`:
  - Header explicitly identifies it as an AI draft prepared in session `jsentinel-26` for student group review.
  - Clarified lifecycle: the agreed Chapter III technical method must be transferred into the shared Google Doc during Pass A, before Phase 07 laboratory testing begins.
  - Marked shared Google Doc link as pending group review and adoption.
  - Specified N as completed eligible controlled scans (N <= 108).
  - Clarified that detection matches are decided strictly by `ruleId` and location coordinates; category and severity metadata do not decide matches.
  - Marked warm-up (10 samples), 3 repetitions, SSD execution, cache clearing, and memory monitoring as proposed research protocols pending group and PC adoption.
  - Feasible timing boundary defined as total elapsed file scan duration without claiming separate parse vs rule timings.
  - Added explicit file-size measurement protocol (raw byte size on disk, line counts, character length).

### Defect 5: Sourcing Survey Methodology and Active Rule Limitations
- **Problem:** Survey details added beyond the checklist were unsourced.
- **Correction:** Sourced survey details directly to `documents/MD/Final-Grp13-IT225-Chapters123-Aug25-2026.md` (Table 6 ISO evaluation form, Table 7 4-point Likert Scale, and respondent composition: 40 users, 10 technical experts). Preserved active 24-rule counts (23 vulnerability + 1 advisory), noted the 3 unsupported weaknesses (`V-A10-053`, `V-A10-054`, `V-A6-033`), and documented the column 0 truthiness limitation (`col || 'unknown'`).

### Defect 6: Expanded Evaluator Test Suite
- **Correction:** Expanded `evaluator.test.mjs` from 33 to 40 targeted tests covering template roundtrip, duplicate/unknown key rejection, incomplete disposition rejection, scenario segregation, semantic review scoping, runner immutability, and dynamic package metadata ingestion.

---

## 7. Manager Review Corrections (Commits 0631380 and 9804964 Follow-Up)

Following coordinator review of commits `0631380` and `9804964`, four remaining bounded blockers were resolved:

### Defect 1: Dynamic Rule Inventory Extraction from Scanner Registries
- **Problem:** The package metadata generator previously hardcoded a 24-rule array containing incorrect descriptions (for example, describing `OWASP-A01-001` as storage access rather than open redirect, `OWASP-A02-002` as SHA-1 rather than cookie manipulation, and `OWASP-A03-004` as Function constructor rather than template literal HTML injection).
- **Correction:** Replaced the hardcoded inventory with `loadActualRuleInventories()`. The function dynamically loads the extension registry from `vscode-extension/src/scanner/rules.js` and all 8 web rule modules from `src/scanner/rules/`. It verifies 1-to-1 rule ID agreement, matching severity levels, and identical rule types between both engines. Descriptions and categories are extracted directly from accepted scanner rule objects (`webRule.message`, `webRule.owasp`). Counts are derived dynamically (24 total: 23 vulnerability, 1 advisory, 7 categories). Added test 41 comparing the derived inventory against the active registries.

### Defect 2: IngestRunReports Provenance Binding and Distinct Base Commits
- **Problem:** `ingestRunReports` only parsed JSON files without validating scanner engine binding, dataset integrity, or commit consistency. Additionally, the dataset manifest base commit (`ca15477`) was mislabeled as the accepted evidence base commit.
- **Correction:** Enhanced `ingestRunReports` with strict provenance checks:
  1. Rejects cross-engine contamination (verifies `engine === 'web'` in web runs and `engine === 'extension'` in extension runs).
  2. Verifies evaluator commit consistency across both scanner engines.
  3. Binds run metadata against the dataset manifest (`datasetBaseCommit` and `datasetManifestVersion`).
  4. Verifies sample file SHA-256 hashes against disk files.
  5. Validates completion and confusion matrix counts (116 attempted, 116 completed, 108 evaluated).
  6. In package metadata, cleanly separates three distinct commit references: `datasetBaseCommit` (`ca15477`), `acceptedPhase04EvidenceCommit` (`0a76a2f`), and `evaluatorSourceCommit` (live Git HEAD).
  7. Reproduction command updated to target a new output directory (`phase05-benchmark-repro`), respecting runner immutability.
  8. Preserved the previous metadata artifact at `05-candidate-package-metadata-2026-09-15-corr1.json` before writing version 1.1.0 to `05-candidate-package-metadata.json`.

### Defect 3: Adjudication Multiplicity, Binding, and Tampering Rejection
- **Problem:** Adjudication keys collapsed repeated identical unmatched findings at the same line and column, reducing the evaluation denominator. Furthermore, adjudication documents contained no run ID or result digest binding, allowing cross-run tampering. Completed semantic reviews did not enforce genuine human review.
- **Correction:** 
  1. Multiplicity: `makeFindingKey` and `extractEvaluationFindingsMap` incorporate an `occurrenceIndex`. Two identical alerts in the same file at the same coordinates receive distinct keys (index 0 and index 1). Both are preserved in templates and counted in precision denominators without loss.
  2. Cross-Run Digest Binding: Exported `computeEvaluationDigest(evaluationResult)` calculating a deterministic SHA-256 digest of findings and metadata. Adjudication documents require `scannerEngine`, `evaluationRunId`, and `evaluationResultDigest`. Mismatches trigger cross-run rejection.
  3. Canonical Field Tampering: Validator compares entries against ground truth. Modifying `scope`, `kind`, `sampleId`, `fileName`, `ruleId`, or location coordinates fails validation.
  4. Human Reviewer Requirement: Completed dispositions and completed semantic reviews require a non-empty human reviewer name, valid ISO review date, and non-empty rationale. `AUTOMATED_EVALUATOR` is rejected for completed reviews.
  5. Duplicate Policy Validation: Validates the `duplicateEligibility` policy enum (`EXCLUDE_FROM_PRECISION` vs `COUNT_AS_FP`), rejecting invalid options.

### Defect 4: Phase 05 Checklist Creation
- **Correction:** Created `documents/research-phases/checks/05-checklist.md` itemizing all 21 acceptance criteria, execution records, exit codes, and explicit research limits (Node development timing boundaries, AST limits, and pending group adoption gates). Expanded unit tests from 40 to 46 passing tests.

---

## 8. Coordinator Residual Review Corrections (Commit b8a9fef Follow-Up)

Following coordinator inspection of commit `b8a9fef`, three concrete residual blockers were resolved across the evaluator modules and metadata scripts:

### Blocker 1: Complete 116 Sample Provenance Across Both Engines
- **Problem:** `ingestRunReports` previously inspected only `(webMeta.files || []).slice(0, 5)`, leaving 111 files unverified. It also ignored extension engine sample digests and lacked full manifest digest binding.
- **Correction:** Replaced the 5-sample slice with complete verification of all 116 sample IDs and digests across both engines against the manifest and disk files. Checks for missing or duplicate files, cross-engine digest agreement, and manifest SHA-256 digest binding. Added unit test 47 (detecting hash mismatches beyond index 5 and extension-only mismatches) and test 52 (detecting duplicates and missing samples).

### Blocker 2: Persisted Unique RunId and Adjudication Cross-Run Binding
- **Problem:** The benchmark runner previously created `runId` only for `run_metadata.json` after running `evaluateSuite`, leaving `evaluation_report.json` with null `runId`. In addition, adjudication validation permitted synthesized fallback run IDs and skipped run ID matching when `evaluationResult.metadata.runId` was absent.
- **Correction:** The runner now generates a unique `runId` upfront, passes it to the evaluator constructor and `evaluateSuite`, and persists matching `runId`s in both `evaluation_report.json` and `run_metadata.json`. `adjudication.mjs` strictly requires non-empty `metadata.runId`, rejecting legacy unbound evaluation results. `computeEvaluationDigest()` now incorporates `runId`, engine, versions, matching policy, and all finding attributes (rule, location, severity, description, category). Added unit test 48 (legacy unbound rejection) and test 49 (rejecting identical findings from distinct runs via public API).

### Blocker 3: Dynamic Arithmetic Validation Without Hardcoded Completed/Evaluated Counts
- **Problem:** `validateEngineCounts` hardcoded `completed: 116, N: 108`, which would crash on legitimate partial or failed benchmark runs rather than recording honest outcomes with accurate exclusions.
- **Correction:** Rewrote `validateEngineCounts` to validate arithmetic invariants dynamically against raw outcomes and manifest totals. It verifies that `totalSamples === attempted + unattempted`, `attempted === completed + partial + failed`, `controlledTotal === eligible + excluded`, `matrix.N === eligible`, and `matrix.N === TP + TN + FP + FN`. Honest partial and failed outcomes are accepted with accurate exclusions, while contradictory counts are strictly rejected. Added unit test 50 (valid partial/failed fixture acceptance) and test 51 (contradictory count rejection).

### Test Suite Expansion and Isolated Corr2 Evidence
- Expanded unit test coverage in `validation/evaluator/evaluator.test.mjs` from 46 to 52 passing tests.
- Replaced "frozen 108" claim wording in checklist item 3 with "accepted dataset (108 controlled + 8 scenarios) / proposed package".
- Executed fresh versioned benchmark run in `validation/evaluator/runs/phase05-batch-b-corr2`, preserving `phase05-batch-b` and `phase05-batch-b-corr1` intact. Regenerated candidate package metadata with version 1.1.0 at `05-candidate-package-metadata.json`.



