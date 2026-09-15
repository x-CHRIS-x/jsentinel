# Phase 05 Human and Group Freeze Authorization Record: 2026-09-15

- **Record Date:** September 15, 2026 (Asia/Manila)
- **Authority:** Human Capstone Group Lead and Members
- **Package Version:** JSentinel Evaluation Package v1.1.0
- **Status:** **FROZEN: PHASE 07 ELIGIBLE**
- **Prior Provenance Commit:** `c6947dcf314f4b1c51ebaa2cc6494f977dc52668`
- **Current Dataset Manifest:** `test-samples/dataset-manifest.json` (SHA-256: `85a2b536fe00571e2442542d99f7eae200b1593b8ee9995e7ce4c0755ccd0770`, size: 372,247 bytes)

---

## 1. Formal Group Approvals Summary

The human capstone group reviewed and formally approved the remaining Phase 05 technical decisions on September 15, 2026:

1. **C-A1-001 Adjudication:**
   Approved as a legitimate False Positive for scanner rule `OWASP-A08-001`. The sample remains classified as clean (`securityGroundTruth.isVulnerable: false`, `expectedScannerFindings: []`). The updated manifest rationale accurately reflects input parsing via `JSON.parse()` without claiming explicit schema validation.

2. **Semantic-Description Review:**
   Approved without reservations. All 51 matched vulnerability expectations across completed controlled scans satisfy human semantic validity:
   - 51 targets reviewed
   - 51 PASS
   - 0 FAIL
   - 0 AMBIGUOUS

3. **Pass A Technical Method:**
   Approved and adopted as the formal evaluation methodology for Chapter III. It defines counting rules, denominators, formulas, advisory segregation, and incomplete scan handling.

4. **Formal Timing Boundary:**
   Approved. Scan duration timing starts upon scan invocation once the target file content is ready in memory. Timing stops when the completed scan and report result become available. Manual file selection, dialog navigation, and upload times are strictly excluded from timing calculations.

5. **Dataset and Scenario Policy:**
   Approved. The formal controlled dataset consists of 108 files (54 vulnerable files and 54 clean or corrected files). The 8 scenario files represent composite multi-vulnerability browser workloads and must remain segregated from the 108-file controlled confusion matrix.

6. **Target Interfaces:**
   Approved. Formal Phase 07 testing will measure two distinct user-facing interfaces:
   - Web browser application
   - VS Code extension

7. **Repetition Protocol:**
   Approved. For each tested interface, testing proceeds with:
   - One unmeasured warm-up run using the defined 10-file warm-up set.
   - Three measured full runs covering all 116 files (108 controlled and 8 scenarios).
   - Strict preservation of all measured runs without cherry-picking.
   - Reporting of mean durations and ranges where applicable.

8. **AU PC Count Policy:**
   Approved. No arbitrary fixed number of AU PCs is required. Testing will use physical AU laboratory PCs actually available to the group during the scheduled testing session. At least one complete identifiable formal AU PC run is required. Every participating PC must have its hardware, operating system, and software environment recorded under the frozen protocol. No synthetic or fabricated multi-PC runs are permitted.

9. **Phase 07 Laboratory Protocol:**
   Approved. The laboratory execution protocol requires:
   - Recording participating AU PC specifications and baseline conditions.
   - Executing a preliminary setup and compatibility pilot before formal measurement.
   - Testing web and VS Code extension interfaces independently.
   - Using the frozen evaluation package and immutable dataset.
   - Enforcing the frozen timing boundary and repetition schedule.
   - Preserving raw scanner outputs, normalized evaluator reports, timing measurements, screenshots, error logs, and commit/digest identifiers.
   - Strictly respecting school security restrictions without attempting bypasses.

10. **Formal Result Boundary:**
    Confirmed. All existing Phase 05 benchmark values (TP = 45, TN = 53, FP = 1, FN = 9, 90.74% accuracy, 85.00% expected-rule recall) represent local development and pre-freeze observations only. They are not formal Phase 07 AU laboratory results.

11. **Manifest and Provenance Binding:**
    Approved. The frozen package binds to current manifest SHA-256 `85a2b536fe00571e2442542d99f7eae200b1593b8ee9995e7ce4c0755ccd0770`. Historical Phase 05 corr2 development runs retain their recorded execution-time manifest SHA-256 `ac9f72499b242d8d580cf617e841766d40d12d7935d65e3381d3d58841ea9199`.

12. **Package Freeze:**
    Approved. Phase 05 Evaluation Package v1.1.0 is formally frozen.

---

## 2. Frozen Evaluation Package v1.1.0 Specifications

| Specification Area | Frozen Value / Identifier |
| :--- | :--- |
| **Package Name** | `jsentinel` |
| **Package Version** | `v1.1.0` (Frozen) |
| **Scanner Engines** | Web scanner engine (`src/utils/scannerEngine.js`) and VS Code extension engine (`vscode-extension/src/scanner/scannerEngine.js`) |
| **Active Rules** | 24 rules across 7 OWASP Top 10 categories, synchronized 1-to-1 between engines |
| **Advisory Rule** | `OWASP-A06-001` (Unscored informational advisory; excluded from vulnerability confusion matrix) |
| **Dataset Version** | `1.0.0` (116 files: 108 controlled, 8 composite scenarios) |
| **Current Manifest SHA-256** | `85a2b536fe00571e2442542d99f7eae200b1593b8ee9995e7ce4c0755ccd0770` |
| **Current Manifest Size** | 372,247 bytes |
| **Evaluator Version** | `1.1.0` (`validation/evaluator/`) |
| **Adjudication Disposition** | C-A1-001 line 9 `OWASP-A08-001` classified as FALSE POSITIVE |
| **Benchmark Status** | Baseline development benchmark recorded (Batch B corr2); Phase 07 laboratory testing unstarted |

---

## 3. Disclosed Operational Limits for Phase 07 AU Testing

The following limitations must be observed during laboratory execution:
1. **Physical Laboratory Network Restrictions:** The web application and VS Code extension are designed for local, offline execution. School firewalls or restricted student accounts must not be bypassed.
2. **Timing Variability on Campus PCs:** Shared laboratory machines may experience variable CPU or background loads. The repetition protocol (1 warm-up plus 3 measured runs) and environment specification logging are required to capture variance accurately.
3. **Manual Upload Exclusion:** File selection dialog latency depends on student manual speed. Timing must strictly record automated scan invocation through completion, excluding file selection.
4. **Single-File vs Composite Scenarios:** The 108 controlled samples measure targeted detection on isolated patterns. The 8 composite scenarios measure parser robustness on multi-vulnerability files and must not be aggregated into the controlled confusion matrix.
