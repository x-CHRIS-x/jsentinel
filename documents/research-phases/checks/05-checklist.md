# Phase 05 Checklist: Evaluator, Adjudication, and Candidate Package

Date: September 15, 2026.  
Branch: `ao/jsentinel-26/phase05-evaluator`.  
Base Commit: `0a76a2f61dea576a0155153a8e0bad6a4d42fdbb` (accepted Phase 04 evidence base).  
Harness: AO worker `jsentinel-26`, Agy with Gemini 3.8 Flash (High). Single session execution, no subagents.  
Manager: Astra coordinator (`jsentinel-4`). Verifier: Opus HOLD.  

---

## 1. Acceptance Criteria Status

| Requirement / Fix Area | Status | Evidence and Verification |
| --- | --- | --- |
| 1. Dedicated evaluator branch from accepted base | **PASS** | Established clean branch `ao/jsentinel-26/phase05-evaluator` from accepted Phase 04 evidence base commit `0a76a2f61dea576a0155153a8e0bad6a4d42fdbb`. |
| 2. Separate evaluator tooling from scanner core | **PASS** | Evaluator modules located exclusively in `validation/evaluator/`. No scanner engines, Babel parser visitors, or dataset samples modified. |
| 3. Fail-closed scan result normalization | **PASS** | `normalizeScanResult` rejects malformed input descriptors, preserves explicit `status: partial` / `completed: false`, and never infers empty error findings as clean passes. Verified in tests 7, 8, 9, 19, 29, and 30. |
| 4. Finite valid coordinates and duplicate prevention | **PASS** | `matchSampleFindings` requires finite positive numbers for line coordinates; rejects NaN or undefined line matching. Distinct same-line columns are preserved as separate findings. Duplicate actual findings cannot satisfy multiple targets. Verified in tests 4, 5, 6, 20, 21, and 22. |
| 5. Separate advisory A06 policy tracking | **PASS** | Advisory check `OWASP-A06-001` tracked separately and excluded from vulnerability confusion matrix and recall/precision denominators. Verified in test 12. |
| 6. Controlled and scenario segregation | **PASS** | Controlled confusion matrix strictly constrained to completed controlled scans (N <= 108). All 8 simulated browser scenarios excluded from controlled metrics and reported separately with unsupported weaknesses retained. Verified in tests 15, 25, and 34. |
| 7. Reproducible local benchmark runner | **PASS** | `validation/evaluator/runner.mjs` executes both actual scanners against all 116 manifest files (232 scan attempts per run). Retains full raw scan outputs, normalized results, run metadata, and CSV exports. Tested in tests 17, 18, and 39. |
| 8. Runner immutability and destination protection | **PASS** | Runner checks destination folder and refuses to overwrite existing populated evidence directories. Historical run `validation/evaluator/runs/phase05-batch-b/` preserved intact. New run isolated in versioned folder `validation/evaluator/runs/phase05-batch-b-corr1/`. Verified in test 39. |
| 9. Dynamic rule inventory derived from actual registries | **PASS** | Removed hardcoded 24-rule array with mismatched descriptions. `loadActualRuleInventories()` dynamically inspects `vscode-extension/src/scanner/rules.js` and all 8 web rule modules in `src/scanner/rules/`. Enforces 1-to-1 ID, severity, and type agreement. Real descriptions loaded from `webRule.message`. Verified in test 41. |
| 10. Dynamic package metadata generation and provenance | **PASS** | `scripts/generate-candidate-package-metadata.mjs` ingests live run reports, metadata, Git commit hashes, dirty status, tool versions, and manifest digests with zero preset outcomes. Validates 54V/54C/8 scenario manifest split. Verified in tests 38, 40, and CLI execution. |
| 11. Separation of distinct base commits | **PASS** | Metadata cleanly separates dataset base commit (`ca154776e3896fe4cc6db883b46d9caaf0d23089`), accepted Phase 04 evidence base commit (`0a76a2f61dea576a0155153a8e0bad6a4d42fdbb`), and evaluator source commit (HEAD). Mislabeled field corrected. |
| 12. Adjudication occurrence multiplicity | **PASS** | `makeFindingKey` and `extractEvaluationFindingsMap` incorporate occurrence indices. Repeated identical alerts at the same coordinates retain distinct keys (`occurrenceIndex: 0`, `occurrenceIndex: 1`), preventing denominator collapse. Verified in test 44. |
| 13. Adjudication document binding and cross-run rejection | **PASS** | Adjudication documents require `scannerEngine`, `evaluationRunId`, and `evaluationResultDigest`. Documents generated for a different run or result digest are strictly rejected. Verified in test 42. |
| 14. Canonical field tampering rejection | **PASS** | Adjudication validator verifies finding entries against ground truth. Modifying `scope`, `kind`, `sampleId`, `fileName`, `ruleId`, or `location` coordinates triggers immediate validation failure. Verified in test 43. |
| 15. Genuine human reviewer requirement | **PASS** | Completed human dispositions and completed semantic reviews require a non-empty human reviewer name, valid ISO review date, and non-empty rationale. `AUTOMATED_EVALUATOR` is strictly rejected for completed reviews. Verified in tests 31 and 45. |
| 16. Duplicate policy enum validation | **PASS** | Supported duplicate policies restricted to `EXCLUDE_FROM_PRECISION` and `COUNT_AS_FP`. Invalid policies rejected. Verified in tests 36 and 46. |
| 17. Versioned package metadata preservation | **PASS** | Prior package metadata artifact preserved at `documents/research-phases/checks/05-candidate-package-metadata-2026-09-15-corr1.json`. New metadata generated with schema version 1.1.0 at `05-candidate-package-metadata.json`. |
| 18. Pass A technical method checkpoint draft | **PASS** | Drafted in `05-pass-a-technical-method-draft.md`. Removed AI author claims. Clarified lifecycle to transfer agreed method into shared Google Doc before Phase 07. Sourced survey to August 25 paper snapshot (Table 6 ISO form, Table 7 4-point Likert Scale). Defined total scan duration timing. |
| 19. Full evaluator unit test suite | **PASS** | 46 tests pass in 652 ms (`node --test validation/evaluator/evaluator.test.mjs`). |
| 20. Full project regression test suite | **PASS** | 48 tests pass across browser scope, overlapping HTML, validation handling, pilot manifest, and guidance tests. |
| 21. Clean linter and web build | **PASS** | `npm run lint` passes with 0 errors and 0 warnings. `npm run build` succeeds cleanly. |

---

## 2. Execution Record and Exit Codes

| Command Line | Purpose | Exit Code | Observed Result |
| --- | --- | ---: | --- |
| `node --test validation/evaluator/evaluator.test.mjs` | Run 46 evaluator unit and integration tests | 0 | 46 passed, 0 failed (duration ~652 ms). |
| `node --test validation/browser-scope.test.mjs validation/html-overlapping.test.mjs validation/validation-handling.test.mjs validation/pilot-manifest.test.mjs validation/guidance.test.cjs` | Run all 48 project regression tests | 0 | 48 passed, 0 failed (duration ~8.2 s). |
| `node scripts/generate-candidate-package-metadata.mjs` | Generate version 1.1.0 candidate package metadata | 0 | Successfully generated metadata file with backup preservation. |
| `npm run lint` | Run ESLint across web project | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm run build` | Build Vite web production bundle | 0 | Clean pass; 233 modules transformed in 1.76 s. |
| `git status` | Verify working tree status | 0 | Clean or tracked changes accounted for before commit. |

---

## 3. Disclosed Limits and Boundaries (NOT RUN / NOT PROVEN)

Validation tests and unit test suites do not prove all aspects of a system. In accordance with research integrity standards, the following limits are explicitly recorded:

1. **Node development timing only:** Execution durations measured using `performance.now()` in Node.js reflect local development workstation AST traversal. They do NOT establish live browser DOM rendering speeds or VS Code extension responsiveness on physical AU computer laboratory machines.
2. **AST traversal vs runtime behavior:** Static analysis scanner rules inspect Babel AST nodes. They do NOT execute code in live JavaScript browser runtime environments or simulate dynamic prototype modification during page execution.
3. **Controlled benchmark boundary (N <= 108):** High precision and recall metrics reflect the curated, frozen 108-file controlled benchmark dataset. These metrics cannot be generalized to arbitrary, uncurated web applications or third-party npm packages.
4. **Human ground-truth adjudication pending:** The adjudication engine and template are implemented and verified. Manual ground-truth review of the single unmatched finding on `C-A1-001.js` line 9 (`OWASP-A08-001`) remains pending human capstone group review.
5. **Candidate package metadata unfrozen:** Package metadata file `05-candidate-package-metadata.json` is explicitly labeled `PROPOSED / UNFROZEN`. Formal freeze adoption awaits human groupmate and adviser review.
6. **Chapter III Google Doc migration pending:** The technical methodology is drafted in `05-pass-a-technical-method-draft.md`. Transfer into the shared capstone Google Doc remains pending group agreement before Phase 07.
7. **Push to remote and branch merge: NOT RUN.** All branch activity remains local on `ao/jsentinel-26/phase05-evaluator` pending coordinator acceptance.
8. **Opus review request: NOT RUN.** Awaiting coordinator authorization before requesting Opus verification.
