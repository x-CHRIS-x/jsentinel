# Phase 05 Batch B & Batch C Corrections Self-Check Report

Date: September 15, 2026  
Session: AO worker `jsentinel-26`  
Orchestrator: Astra manager (`jsentinel-4`)  
Branch: `ao/jsentinel-26/phase05-evaluator`  
Base Commit: `0a76a2f61dea576a0155153a8e0bad6a4d42fdbb`  
Source Correction Commit: `06313806fbda5a3410b69f256e81324584b82ae5`  
Candidate Package Status: `PROPOSED / UNFROZEN` (Pending Group Freeze Adoption)  
External Checklist SHA-256: `2DF5DB5D38AF018A6503E644E87A3B564D1736CFDE8A1B3F1A6CDCFB9E7375B1`  
Historical Commits Preserved: `5239da9` (Batch B implementation), `ab37e50` (Batch B/C initial evidence)  
Historical Run Preserved: `validation/evaluator/runs/phase05-batch-b/`  
New Versioned Run: `validation/evaluator/runs/phase05-batch-b-corr1/`  

---

## 1. Summary of Execution and Completed Corrections

This report documents the resolution of all six review items raised by the coordinator following inspection of commits `5239da9` and `ab37e50`. All corrections were implemented in the active session under bounded evaluator scope, preserving historical commits, raw runs, and self-checks.

Key corrections implemented:
1. **Dynamic Metadata Generation (`scripts/generate-candidate-package-metadata.mjs`):** Eliminated all hardcoded metrics and literal result substitutes. The script ingests `evaluation_report.json` and `run_metadata.json` dynamically from disk, queries full 40-character Git commit hashes, branch, and working tree cleanliness, derives 54 vulnerable, 54 clean, 8 scenarios (116 total), and throws an error upon any discrepancy.
2. **Adjudication Scoping and Validation (`validation/evaluator/adjudication.mjs`):** Introduced explicit finding scope (`controlled` vs `scenario`) and kind (`unmatched`, `matched`, `duplicate`). Fixed double-counting defect: controlled precision counts only completed controlled unmatched dispositions in addition to automated baseline matches. Scenarios and partial scans cannot contaminate controlled precision. Dispositions require reviewer, rationale, and reviewDate.
3. **Runner Evidence Protection (`validation/evaluator/runner.mjs`):** Added output directory protection that throws and refuses to overwrite populated directories. Exposed CLI reproduction arguments (`--output-dir`, `--run-id`, `--manifest`, `--samples-dir`). Executed new benchmark run into versioned directory `validation/evaluator/runs/phase05-batch-b-corr1/`, preserving the original `phase05-batch-b/` run untouched.
4. **Pass A Technical Method Revision (`05-pass-a-technical-method-draft.md`):** Removed author claims for the AI draft, stated that agreed method transfer to the shared Google Doc occurs during Pass A before Phase 07, defined N <= 108, clarified that detection matching is decided strictly by rule and coordinates (not category metadata), marked laboratory protocols as proposals pending group adoption, defined feasible total scan duration timing without claiming uninstrumented separate parse timings, and added an explicit file-size measurement protocol.
5. **Survey Instrument Sourcing:** Sourced all survey items, criteria, Likert scale bands, and respondent numbers directly to `documents/MD/Final-Grp13-IT225-Chapters123-Aug25-2026.md` (Table 6 and Table 7).
6. **Test Suite Expansion:** Expanded `validation/evaluator/evaluator.test.mjs` from 33 to 40 tests, verifying adjudication scoping, roundtrip, duplicate/unknown key rejection, runner immutability, and dynamic metadata ingestion.

---

## 2. Test Verification and Lint Results

All unit, integration, regression, and guidance tests pass cleanly:

```text
> node --test validation/evaluator/evaluator.test.mjs
✔ 1-30. Core Evaluator, Adapter Edge-Cases, and Matching Rules (pass)
✔ 31. Finding Adjudication Document Validation: rejects duplicate, unknown, and incomplete entries
✔ 32. Adjudication Template Roundtrip and Scoping
✔ 33. Controlled Precision Adjudication: counts only completed controlled unmatched, never double-counts
✔ 34. Scenario Segregation and Incomplete Scans in Adjudication
✔ 35. Semantic Review Scoping: denominator is strictly matched targets
✔ 36. Duplicate Precision Eligibility Policy in Adjudication
✔ 37. Runner Protection and CLI Argument Parsing
✔ 38. Dynamic Package Metadata Generation and Manifest Distribution Enforcement
✔ 39. Runner Immutability: refuses existing populated output directory
✔ 40. Metadata Ingestion: changed synthetic inputs dynamically change reported outputs with no preset outcome
ℹ tests 40, pass 40, fail 0 (690ms)
```

Combined regression suites (`validation/browser-scope.test.mjs`, `validation/html-overlapping.test.mjs`, `validation/validation-handling.test.mjs`, `validation/pilot-manifest.test.mjs`) pass with 35 passing tests. Guidance test suite (`npm run test:guidance`) passes with 13 passing tests. ESLint passes with 0 errors.

---

## 3. Versioned Benchmark Run (`phase05-batch-b-corr1`)

Following commit of source code in `0631380`, the benchmark runner executed across all 116 manifest files for both engines into `validation/evaluator/runs/phase05-batch-b-corr1/`:
- Web Engine: 116 attempts (108 controlled, 8 scenarios) completed in 2,688.4ms.
- Extension Engine: 116 attempts (108 controlled, 8 scenarios) completed in 317.4ms.
- Total Scan Attempts: 232 attempts, 100% completion rate (0 partial, 0 failed, 0 unattempted).
- Controlled Matrix (N = 108):
  - TP = 45, TN = 53, FP = 1 (`C-A1-001.js`), FN = 9 (3 unsupported weaknesses, 6 rule misses)
  - Accuracy = 90.74%, Specificity = 98.15%, Recall = 83.33%, Precision = 97.83%, FPR = 1.85%, FNR = 16.67%
- Expected-Rule Recall = 85.00% (51 matched out of 60 targets across completed scans).
- Finding Precision: 52 actual alerts, 51 matched targets, 0 duplicates, 1 unmatched (`C-A1-001.js` line 9). Target-match fraction is 98.08% (51 / 52). Adjudicated precision remains `N/A` pending manual human review.

---

## 4. Candidate Package Metadata Verification

`documents/research-phases/checks/05-candidate-package-metadata.json` was generated dynamically from `phase05-batch-b-corr1`:
- Explicitly labeled `PROPOSED / UNFROZEN` with group freeze status `PENDING_GROUP_ADOPTION`.
- Full commit hash: `06313806fbda5a3410b69f256e81324584b82ae5`.
- Manifest distribution derived dynamically: 116 total files (108 controlled: 54 vulnerable, 54 clean; 8 scenarios).
- SHA-256 digests recorded across all 116 dataset sample files, 17 scanner source files, 24 active detection rules, manifest, and 9 evaluator modules.
- Reproduction commands and metric formulas included.

---

## 5. Human Decision Points for Manager and Student Group

1. **Unmatched Finding Ground-Truth Disposition:** Human review of the single completed controlled unmatched finding (`OWASP-A08-001` on line 9 of `C-A1-001.js`) using `validation/evaluator/adjudication.mjs` to establish whether it is a newly identified vulnerability or a false positive.
2. **Formal Package Freeze Adoption:** Student group review and formal freeze adoption of the proposed candidate package metadata.
3. **Chapter III Method Transfer:** Transfer of the agreed Pass A technical method from `05-pass-a-technical-method-draft.md` into the shared Google Doc prior to conducting formal Phase 07 laboratory runs.
