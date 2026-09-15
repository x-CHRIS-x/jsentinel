# Phase 05: Build a small evaluator and freeze the test package

Status: Batch B local benchmarks completed (232 attempts); candidate package metadata generated (Batch C); Pass A Chapter III method checkpoint drafted; group freeze adoption pending. Depends on Phase 04; a prototype can use its reviewed pilot. Suggested size: 2 to 4 focused blocks.

Accuracy measurement is a research procedure performed with a separate evaluator. It is not a proposed end-user feature. Keep the evaluator small: a manifest, adapters to the actual scanners or their recorded outputs, and checkable CSV or JSON results.

## Batch A: Verify the evaluator on the pilot

Use the same reviewed manifest for both scanners. Retain raw findings with rule ID, category or its documented mapping, location, guidance ID, severity, description, and any parse or rule-execution errors. Reuse existing scan/export data where possible; do not create a second scanner inside the evaluator.

Check the evaluator with known missing, unrelated, duplicated, and correctly matched findings. Include parse failure and partial-scan examples. Its calculations must work even when the scanner is wrong.

## Batch B: Keep the measurements distinct

| Measurement | Counting rule |
| --- | --- |
| File-level confusion matrix | A fully scanned controlled file is positive when it has an in-scope vulnerability alert under the recorded alert policy. Compare with the reviewed file label. This broad measure does not establish detection of the intended rule. |
| Expected-rule detection | Match each expected vulnerability to an actual finding by rule ID and reviewed location, one to one. An unrelated alert cannot count as detecting the expected vulnerability. |
| Finding details | Compare the expected category, severity, and line against the result. Use a short manual check that the description identifies the intended weakness. Report metadata errors separately from detection matches; retaining a field does not validate it. |
| Scenario observations | Report expected and actual findings, mismatches, completion, and timing separately for the eight scenarios. |
| Scan completion | Record attempted, completed, partial, and failed scans separately. Partial or failed scans are not clean negatives. |

Apply Phase 01's policy: advisory-only A06 signals are reported separately and excluded from vulnerability metrics. Record any other advisory-only checks explicitly before the formal run. An unmatched alert requires review of the sample's ground truth; do not silently assume it is either correct or false.

For the controlled file-level matrix, calculate accuracy `(TP + TN) / N`, precision `TP / (TP + FP)`, recall or true positive rate `TP / (TP + FN)`, specificity `TN / (TN + FP)`, false positive rate `FP / (FP + TN)`, and false negative rate `FN / (FN + TP)`. Multiply by 100 for percentages. `N` is the number of completed eligible controlled scans. Show attempted counts and exclusions beside the metrics. A zero denominator is `N/A`.

Report expected-rule recall and finding-level precision separately, with their own counts and definitions. Never present a positive file caused by the wrong rule as successful target detection.

## Batch C: Freeze before formal measurement

Record the scanner build or commit, active rule list, dataset and manifest hashes, evaluator version, matching policy, and known limitations. Review labels before viewing formal results. Preserve old results if a later correction requires a new version and rerun.

Chris and the group must also settle the corresponding Chapter III technical method before Phase 07, rather than first defining it after results exist. Record one controlled test case as one file with its reviewed expected result and recorded actual result. Agree on the counting units, formulas and denominators, advisory policy, incomplete-scan handling, classification checks, timing boundary, and planned repetitions. Put the reviewed method in the shared Google Doc and retain its agreed version or dated export with the test package. Preserve existing paper edits and use future or procedure wording where testing remains pending. The ISO classmate is not assigned this technical-method work. Phase 08 reconciles and presents the completed results afterward.

The existing 108-file pass result is a development observation, not a preset result for the revised benchmark. Repeated deterministic output does not prove correct vulnerability classification. No accuracy target controls the labels or sample selection.

A measured 100% result on the frozen constructed cases can be reported with its limited scope. Do not engineer the percentage upward or downward, and do not generalize it to arbitrary JavaScript.

## Done and stop

- [x] Known evaluator cases produce the correct matches, errors, and denominators (Batch A & B corrected; 46 unit/integration tests pass).
- [x] Both implementations have local results with raw evidence retained (Batch B & B-corr1 complete; 232 scan attempts per run across Web and Extension engines in versioned folders).
- [x] No duplicate, unrelated alert, or failed scan can create a false target-detection pass (Batch A verified in tests 1-9 and 19-22).
- [x] Category, severity, location, and description checks cover the claims made in Chapter III (Batch B schema 1.0.0 and exports).
- [x] The Chapter III technical method and lab protocol are agreed and recorded before formal runs (Pass A proposed draft checkpoint in `05-pass-a-technical-method-draft.md`; shared Google Doc transfer pending group adoption).
- [x] The research package is reproducible and its limitations are recorded (Batch C candidate package metadata in `05-candidate-package-metadata.json`, dynamically bound to source commit and versioned reports, labeled `PROPOSED / UNFROZEN`).

Stop with a frozen package and local verification. Node-based engine checks do not establish web-browser or VS Code performance on AU PCs.
