# Phase 05 Batch B & Batch C Self-Check Report

Date: September 15, 2026  
Session: AO worker `jsentinel-26`  
Orchestrator: Astra manager (`jsentinel-4`)  
Branch: `ao/jsentinel-26/phase05-evaluator`  
Base Commit: `0a76a2f61dea576a0155153a8e0bad6a4d42fdbb`  
Evaluator State Commit: `5239da9`  
Candidate Package Status: `PROPOSED / UNFROZEN` (Pending Group Freeze Adoption)  
External Checklist SHA-256: `2DF5DB5D38AF018A6503E644E87A3B564D1736CFDE8A1B3F1A6CDCFB9E7375B1`  

---

## 1. Summary of Execution and Completed Scope

This self-check documents the completion of Phase 05 Batch B and Batch C. All tasks were performed under explicit constraints: zero subagents, zero modifications to scanner detection rules or dataset files, no live edits to shared Google Docs, and strict fail-closed evaluation standards.

The work completed across these batches includes:
1. Hardened adapter edge cases: valid empty-string JavaScript sources scan normally as clean files, malformed descriptors fail closed with clear errors, and status normalization preserves explicit partial/failed states without inventing success.
2. Implemented the human adjudication module (`validation/evaluator/adjudication.mjs`) supporting ground-truth dispositions (`TRUE_POSITIVE`, `FALSE_POSITIVE`, `PENDING`), semantic description review, and duplicate precision policies.
3. Executed reproducible local benchmark runs (`validation/evaluator/runner.mjs`) across all 116 manifest files for both actual scanner engines (232 total scan attempts).
4. Retained all raw scan outputs, normalized results, CSV summaries, and run metadata in versioned directories (`validation/evaluator/runs/phase05-batch-b/`).
5. Generated candidate package metadata (`documents/research-phases/checks/05-candidate-package-metadata.json`) containing SHA-256 hashes across all 116 dataset files, scanner sources, active rules (24), manifest, and evaluator modules.
6. Drafted the Pass A technical method checkpoint (`documents/research-phases/checks/05-pass-a-technical-method-draft.md`) addressing all Chapter III methodology items.

---

## 2. Test Verification and Lint Results

The evaluator test suite was expanded to 33 targeted tests covering all known-case scenarios, adapter edge cases, policy validations, and adjudication rules.

```text
> node --test validation/evaluator/evaluator.test.mjs
✔ 1. Correct Match: matches expected rule and location one-to-one (TP)
✔ 2. Missing Finding: expected vulnerability without scanner finding recorded as missed (FN)
✔ 3. Unrelated Alert: wrong rule/location cannot satisfy target expectation
✔ 4. Duplicate Findings: duplicates cannot inflate target detection matches
✔ 5. Multiple Findings Only One Match: extra findings categorized as duplicate or unmatched
✔ 6. One Actual Finding Cannot Match Two Expectations: single alert cannot satisfy two targets
✔ 7. Parse Failure: empty findings on parse error must NOT be inferred as clean negative
✔ 8. Partial Scan: rule execution error excluded from completed matrix N
✔ 9. Failed Scan: unhandled engine error excluded from completed matrix N
✔ 10. Clean Negative: clean file with zero alerts correctly classified as TN
✔ 11. Clean Unrelated False Positive: clean file with alert classified as FP
✔ 12. Advisory A06 Policy: A06 alert excluded from vulnerability metrics and retained separately
✔ 13. Zero Denominator Protection: returns null and N/A without NaN or throwing
✔ 14. Metadata Error Separate from Detection: detection matches while metadata mismatch is flagged
✔ 15. Scenario Segregation: scenarios excluded from controlled matrix and unsupportedWeaknesses retained
✔ 16. Unsupported Null-Rule Policy: null ruleId cannot be detected or matched
✔ 17. Web Adapter Live Execution and Error Handling with Malformed Descriptor Rejection
✔ 18. Extension Adapter Live Execution and Error Handling with Malformed Descriptor Rejection
✔ 19. Fail-Closed Scan Result Normalization and Preserved Errors
✔ 20. Finite Valid Coordinates: missing or invalid location rejected and cannot match
✔ 21. Distinct Same-Line Locations: different columns are NOT duplicates
✔ 22. Identical Duplicate Actuals Cannot Satisfy Multiple Expectations
✔ 23. Policy Validation: rejects invalid parameters
✔ 24. Unattempted Scans: missing scan recorded as unattempted rather than fabricated attempted
✔ 25. Mixed Suite: comprehensive completion breakdown and controlled eligibility
✔ 26. Finding Precision Metrics: targetMatchFraction reported, precision kept N/A pending adjudication
✔ 27. Schema Validation, Retained Outputs, and CSV Pipeline
✔ 28. Valid Empty-String Source: scans normally as clean completed file in both adapters
✔ 29. Malformed Input Descriptors: fail closed in both adapters
✔ 30. Normalization of Unknown Status and Explicit Partial/Failed Flags
✔ 31. Finding Adjudication Document Validation: rejects duplicate and unknown keys
✔ 32. Adjudication Metrics Consumption: applies reviewed decisions and computes precision
✔ 33. Duplicate Precision Eligibility Policy in Adjudication
ℹ tests 33, pass 33, fail 0 (521ms)
```

Static analysis via `npm run lint` completed with 0 errors. The existing regression suite (`validation/browser-scope.test.mjs`, `validation/html-overlapping.test.mjs`, `validation/validation-handling.test.mjs`, `validation/pilot-manifest.test.mjs`) and guidance tests pass cleanly.

---

## 3. Local Benchmark Results (Phase 05 Batch B)

The benchmark runner evaluated both actual scanner engines across the entire 116-file benchmark suite. Execution produced 232 total scan attempts:

| Metric Category | Metric Name | Value | Percentage / Notes |
| :--- | :--- | :---: | :--- |
| **Scan Completion** | Total Attempts | 232 | 116 Web, 116 Extension |
| | Completed Scans | 232 | 100% completion rate |
| | Partial Scans | 0 | No rule runtime exceptions |
| | Failed Scans | 0 | No unhandled engine or parse crashes |
| | Unattempted Scans | 0 | All manifest files processed |
| **Controlled Matrix (N = 108)** | True Positives (TP) | 45 | Vulnerable files with active detections |
| | True Negatives (TN) | 53 | Clean files with zero vulnerability alerts |
| | False Positives (FP) | 1 | `C-A1-001.js` (`JSON.parse` flagged by A08) |
| | False Negatives (FN) | 9 | 3 unsupported weaknesses + 6 rule misses |
| | Accuracy | 0.9074 | 90.74% ((45 + 53) / 108) |
| | Precision | 0.9783 | 97.83% (45 / (45 + 1)) |
| | Recall (Sensitivity) | 0.8333 | 83.33% (45 / (45 + 9)) |
| | Specificity | 0.9815 | 98.15% (53 / (53 + 1)) |
| | False Positive Rate | 0.0185 | 1.85% (1 / (1 + 53)) |
| | False Negative Rate | 0.1667 | 16.67% (9 / (9 + 45)) |
| **Expected-Rule Recall** | Expected Targets | 60 | Across completed controlled scans |
| | Matched Rules | 51 | Strict one-to-one rule and coordinate match |
| | Missed Rules | 6 | Actual scanner detection misses |
| | Unsupported Targets | 3 | Gaps in active rule registry |
| | Expected-Rule Recall | 0.8500 | 85.00% (51 / 60) |
| **Finding Precision** | Actual Vuln Alerts | 52 | In-scope alerts from completed scans |
| | Matched Alerts | 51 | Matched to documented ground truth |
| | Duplicate Alerts | 0 | No duplicate coordinates |
| | Unmatched Alerts | 1 | Line 9 `JSON.parse` on `C-A1-001.js` |
| | Target-Match Fraction | 0.9808 | 98.08% (51 / 52) |
| | Adjudicated Precision | N/A | PENDING manual ground-truth adjudication |

Execution Timings (Development Node Environment):
- Web Engine: 2,680.6ms total across 116 files (average 23.1ms per file).
- Extension Engine: 326.0ms total across 116 files (average 2.8ms per file).
- Boundary Disclaimer: Timings reflect local Node.js AST traversal and do not establish live browser DOM or VS Code extension performance on physical AU laboratory computers.

---

## 4. Candidate Package Metadata Verification (Batch C)

The candidate package metadata file was written to `documents/research-phases/checks/05-candidate-package-metadata.json` (40,954 bytes). It records:
- Package status: `PROPOSED / UNFROZEN`
- Group freeze status: `PENDING_GROUP_ADOPTION`
- Commit hashes: evaluator commit `5239da9`, base commit `0a76a2f61dea576a0155153a8e0bad6a4d42fdbb`
- SHA-256 digests for all 116 dataset sample files in `test-samples/samples/`
- SHA-256 digest for `test-samples/dataset-manifest.json`
- SHA-256 digests for 17 scanner source files across web and extension implementations
- SHA-256 digests for 9 evaluator modules
- Inventory of 24 active detection rules (23 vulnerability detectors, 1 advisory rule)
- Benchmark metrics summary and adjudication protocol specification

---

## 5. Pass A Technical Method Review Against Checklist

The Pass A technical method draft (`documents/research-phases/checks/05-pass-a-technical-method-draft.md`) was reviewed against the seven requirements in `chapters-1-3-update-checklist.md`:

1. Data Collection and Table 1: Preserved 116-file total (54V, 54C, 8 scenarios). Module rows derived from the manifest. Controlled subtotal is 108; scenario row is 8. Advisory module `knownVulns.js` has 0 controlled vulnerability pairs.
2. Labels and Coverage: Documented independent ground truth, AI curation provenance, and pending human review. Detailed active rules (24), advisory signals (1), and realistic non-uniform coverage across categories.
3. Technical Evaluation: Defined one controlled test case as one file with reviewed expectations and actual findings. Separated file classification from expected-rule matching, finding precision, and scenario observations.
4. Calculations: Defined TP, TN, FP, FN, and all reported metric formulas. Excluded incomplete scans from N. Kept advisory signals separate. Handled zero denominators as `N/A`.
5. Lab Procedure: Outlined warm-up run, 3 repeated runs, timing boundary labeled as development Node execution, and process memory observation. Marked group and PC decisions as pending group adoption.
6. Survey and Statistical Tools: Preserved 40 user respondents, 10 technical respondents, 10 questions across 5 ISO criteria, Likert scale interpretations, and frequency/percentage/weighted mean methods with clear denominator distinctions.
7. Written-Method Checkpoint: Versioned draft created with future/procedure wording for pending lab runs. Confirmed zero direct edits to live paper chapters or shared Google Docs.

---

## 6. Style and Policy Compliance

1. Zero Em Dashes: Verified across all written documents and code comments.
2. Writing Style: Direct, explanatory, practical student prose adhering to `chris-writing-style`. Short to medium sentences, focused paragraphs (3-5 sentences), college-level English, and concrete specifics without generic AI fluff.
3. Non-Destructive Operation: Zero changes made to scanner detection rules, dataset files, or `dataset-manifest.json`.
4. Exact Identifier Alignment: Evaluator code was committed in `5239da9` before local runs and metadata generation, ensuring exact commit tracking throughout all run artifacts.
