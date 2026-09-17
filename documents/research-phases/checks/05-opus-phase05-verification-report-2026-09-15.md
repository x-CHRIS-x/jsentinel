# Phase 05 Independent Verification Report

Date: September 15, 2026
Session: `jsentinel-28` (replacement fresh independent Phase 05 strong verifier)
Verifier Model/Harness: Antigravity (Agy) / Claude Opus 4.6 Thinking (user-selected model)
Prior Session: `jsentinel-27` interrupted by individual-quota error; no verdict produced; workspace preserved.

---

## 1. Commit Provenance

| Role | Commit SHA | Verified |
| :--- | :--- | :---: |
| Accepted Phase 04 base | `0a76a2f61dea576a0155153a8e0bad6a4d42fdbb` | YES |
| Phase 05 final source commit | `1b4f885fa4d4b19621ba08ab560cd06034bc9c05` | YES |
| Phase 05 candidate/evidence commit | `d63281e8f3d9c5beb64d4c146e1094a8c0f027b2` | YES |

**Ancestry check:** `git merge-base --is-ancestor 0a76a2f d63281e` returned exit code 0. Phase 04 base is a proper ancestor of the candidate.

**Commit chain (Phase 05, 12 commits):**
```
98a1f82 feat(phase05): implement research evaluator, scanner adapters, and known-case tests
e38610a docs(phase05): record Batch A evaluator self-check and known-case evidence
459c82a fix(phase05): correct evaluator adapters, matching coordinates, and completion tracking
4bde58f docs(phase05): record Batch A corrections, changes log, and issues notes
5239da9 feat(phase05): implement benchmark runner, adjudication engine, and adapter edge cases
ab37e50 docs(phase05): record Batch B benchmark runs, package candidate, and Pass A draft
0631380 fix(phase05): correct adjudication scoping, runner immutability, and metadata generation
9804964 docs(phase05): record Batch B/C corrections, new run evidence, and revised Pass A draft
d3326cd fix(phase05): bind report provenance, preserve adjudication multiplicity, and dynamically load registries
b8a9fef docs(phase05): record checklist, package metadata v1.1.0, and coordinator review corrections
1b4f885 feat(evaluator): complete 116 sample provenance, enforce runId binding, and support honest partial/failed metrics
d63281e docs(phase05): record corr2 benchmark evidence, package metadata v1.1.0, and updated checklist
```

---

## 2. Test Execution Results

| Command | Purpose | Exit Code | Result |
| :--- | :--- | ---: | :--- |
| `node --test validation/evaluator/evaluator.test.mjs` | 52 evaluator unit/integration tests | 0 | 52 pass, 0 fail |
| `node --test validation/browser-scope.test.mjs validation/html-overlapping.test.mjs validation/validation-handling.test.mjs validation/pilot-manifest.test.mjs validation/guidance.test.cjs` | 48 project regression tests | 0 | 48 pass, 0 fail |
| `npm run lint` | ESLint | 0 | 0 errors, 0 warnings |

**Note:** Initial test run showed 3 failures (tests 17, 18, 28) due to missing `node_modules` dependencies in this worktree. After `npm install`, all 52 evaluator tests and 48 regression tests pass cleanly. The failures were environment-only (missing `@babel/standalone`, `@babel/parser` packages), not code defects.

---

## 3. Challenge Area Verification (20 Items)

### Challenge 1: Evaluator is not a second scanner
- **Verdict: PASS**
- `evaluator.mjs` L35-41, L61-84: `evaluateSample` and `evaluateSuite` consume a pre-populated `scanResultsMap` (output from scanner adapters). The evaluator never imports scanner engines, Babel parsers, or detection rule modules. Missing scans produce a synthetic `unattempted` result.
- The adapters (`adapters.mjs`) load actual scanner engines, but the evaluator core only receives their normalized output.

### Challenge 2: Known evaluator cases
- **Verdict: PASS**
- 52 tests in `evaluator.test.mjs` cover: matched findings, missed findings, duplicates, unrelated alerts, parse failures, partial scans, unattempted scans, empty-string source, malformed descriptors, advisory exclusion, scenario segregation, adjudication templates, tampered fields, human reviewer requirements, zero denominators, and metadata generation. All 52 pass.

### Challenge 3: File-level TP/TN/FP/FN and formulas/denominators
- **Verdict: PASS**
- `metrics.mjs` L126-206: TP/TN/FP/FN strictly gated to `completed` controlled scans only. Scenarios excluded at L136, non-valid labels at L137, incomplete scans at L138.
- N = TP + TN + FP + FN (L177). Schema validator (`schema.mjs` L272-274) enforces this invariant.
- Observed values (both engines): TP=45, TN=53, FP=1, FN=9, N=108. Independently verified: 45+53+1+9=108 ✓.
- Formulas verified: accuracy=(45+53)/108=0.9074 ✓, precision=45/46=0.9783 ✓, recall=45/54=0.8333 ✓.

### Challenge 4: Expected-rule matching and one-to-one matching
- **Verdict: PASS**
- `matching.mjs` L110: `usedVulnFindingIndices` Set prevents reusing the same actual finding.
- L143: Loop skips already-used indices.
- L168-179: `matchedActualCoordinates` list detects duplicate coordinates; identical duplicates cannot satisfy distinct expectations. AMBIGUOUS_DUPLICATE_COORDINATE flagged.
- Matching requires exact `ruleId` (L146) and location within tolerance (L154-155).

### Challenge 5: Unrelated and duplicate findings
- **Verdict: PASS**
- `matching.mjs` L259-291: After matching, remaining findings are classified as either DUPLICATE (identical coordinates to a matched finding, L269-273) or UNMATCHED (distinct coordinates, L284-289). Duplicates get `DUPLICATE_OF_TARGET` status and cannot inflate match counts. Unmatched findings get `PENDING_MANUAL_ADJUDICATION`.

### Challenge 6: One finding cannot satisfy multiple expected vulnerabilities
- **Verdict: PASS**
- `matching.mjs` L110, L143, L186: The `usedVulnFindingIndices` Set ensures each actual finding can match at most one expected vulnerability. Once used at index `i`, that index is added to the Set and skipped for all subsequent expectations.

### Challenge 7: Finding-level precision vs file-level precision
- **Verdict: PASS**
- File-level precision: `metrics.mjs` L180 (TP/(TP+FP)). Based on binary file classification.
- Finding-level precision: `metrics.mjs` L237-268 (target-match fraction = matchedFindings/totalActualFindings). Adjudicated precision held as `null`/`N/A` pending human review (`adjudicationStatus: 'PENDING_MANUAL_GROUND_TRUTH_ADJUDICATION'`).
- These are completely separate metrics calculated independently.

### Challenge 8: Category/severity/location and semantic description review
- **Verdict: PASS**
- `matching.mjs` L194-231: Category extracted via `extractCategoryCode` (L65-69, uses `A\d{2}` pattern). Severity compared case-insensitively. Location compared with optional column. All mismatches reported in `metadataErrors` array but do NOT affect detection match status (L218: `detectionMatch: true` is set regardless of metadata mismatches).
- `metadataChecksSummary` in `metrics.mjs` L296-343 tracks category/severity/location match percentages separately.
- Semantic description status explicitly set to `PENDING_MANUAL_SEMANTIC_REVIEW` (L341).

### Challenge 9: Parse failures, partial/failed/unattempted handling and exclusions
- **Verdict: PASS**
- `adapters.mjs` L132-251: `normalizeScanResult` handles thrown errors (L133-151), null/invalid raw results (L154-172), missing issues arrays (L175-193), and contradictory status signals (L200-224). Parse errors correctly trigger `failed` status. Rule errors with otherwise completed scans trigger `partial` status.
- `metrics.mjs` L138: Only scans with `scanStatus === 'completed' && !hasScanError` enter the confusion matrix.
- `evaluator.mjs` L66-83: Missing scans produce synthetic `unattempted` results.
- All exclusion categories tracked in `exclusionBreakdown` (L60-66).

### Challenge 10: Zero denominators return N/A
- **Verdict: PASS**
- `metrics.mjs` L22-29: `safeRatio(numerator, denominator)` returns `{value: null, percentage: 'N/A'}` when `denominator <= 0` or non-numeric.
- Independently verified: `safeRatio(0,0)` returns `{value: null, percentage: 'N/A'}`. `safeRatio(5,0)` same. `safeRatio(5,-1)` same. `safeRatio(0,5)` correctly returns `{value: 0, percentage: '0.00%'}`.

### Challenge 11: A06/advisory exclusion
- **Verdict: PASS**
- `matching.mjs` L17-21: `DEFAULT_MATCHING_POLICY.advisoryRulePrefixes: ['OWASP-A06-']`.
- L54-57: `isAdvisoryRule` checks if ruleId starts with any advisory prefix.
- L86-96: Actual findings separated into `actualVulnFindings` and `actualAdvisoryFindings`. Advisory findings never enter vulnerability matching.
- `metrics.mjs` L145: File-level confusion matrix uses `vulnerabilities.actualCount` which excludes advisories.
- L270-294: Advisory metrics tracked separately with explicit `policyNote`.

### Challenge 12: Scenario separation from 108 controlled denominator
- **Verdict: PASS**
- `metrics.mjs` L68-99: Samples with `label === 'scenario'` are counted in `scenarioTotal` and `EXCLUDED_SCENARIO`, then `continue` skips them from controlled processing (L98).
- L136: Confusion matrix loop skips scenarios.
- L214-223: Expected-rule metrics skip scenarios.
- L242-251: Finding precision metrics skip scenarios.
- L275-283: Advisory metrics skip scenarios.
- Observed: `scanCompletion.controlledEligibility.total: 108`, `eligible: 108`, `scenarioCompletion.total: 8`. TP+TN+FP+FN = 108 = controlled eligible. Scenarios excluded.

### Challenge 13: Raw evidence preservation for both scanners
- **Verdict: PASS**
- Three run directories preserved: `phase05-batch-b/`, `phase05-batch-b-corr1/`, `phase05-batch-b-corr2/` (all exist on disk).
- Each contains both `web/` and `extension/` subdirectories with: `evaluation_report.json`, `file_results.csv`, `findings_details.csv`, `metrics_summary.csv`, `run_metadata.json`.
- `runner.mjs` L110-120: Refuses to overwrite populated directories, enforcing evidence immutability.

### Challenge 14: Full 116-sample provenance/digest verification across both engines
- **Verdict: PASS**
- Manifest: 116 files (54 vulnerable + 54 clean + 8 scenario). SHA-256: `ac9f72499b242d8d580cf617e841766d40d12d7935d65e3381d3d58841ea9199`.
- Web run_metadata: `totalFilesAttempted: 116`, `controlledFilesCount: 108`, `scenarioFilesCount: 8`, `completedScans: 116`. Manifest SHA matches.
- Extension run_metadata: identical counts and same manifest SHA.
- Both `file_results.csv` files contain 109 lines (1 header + 108 controlled). Scenarios excluded from CSV as designed (evaluator.mjs L220).
- Both evaluation reports show `scanCompletion.totalSamples: 116`, `attempted: 116`, `completed: 116`, `unattempted: 0`.

### Challenge 15: RunId/digest-bound adjudication and multiplicity
- **Verdict: PASS**
- `adjudication.mjs` L30-63: `computeEvaluationDigest` produces SHA-256 from canonical payload (runId, engine, manifest version, evaluator version, matching policy, file summaries).
- Web digest: `60c41437ad92076865b8079fab8ef482b5ef1c40bb4e8e6a0ccb03b3f9eabf1c`.
- Extension digest: `fe04dc9339887cff7e29db42b1e10a1ec23c407ed7f59f9596b6888cad49c1b7`.
- Digests are distinct (different runIds and engine labels).
- L80-92: `makeFindingKey` incorporates `occurrenceIndex` to prevent denominator collapse for identical repeated alerts.
- L101-208: `extractEvaluationFindingsMap` tracks per-coordinate occurrence counters.
- L224-399: `validateAdjudicationDocument` enforces run ID match (L259-264), engine match (L266-269), digest match (L271-277), canonical field tampering rejection (L316-342), genuine human reviewer (L360-371), and semantic reviewer (L378-392).

### Challenge 16: Package metadata reproducibility/version binding
- **Verdict: PASS**
- `05-candidate-package-metadata.json`: `schemaVersion: 1.1.0`, `packageMetadataVersion: 1.1.0`, `status: "PROPOSED / UNFROZEN"`.
- Provenance fields: `datasetBaseCommit: ca154776...`, `acceptedPhase04EvidenceCommit: 0a76a2f6...`, `evaluatorSourceCommit: 1b4f885f...`.
- `reproductionCommands` present with exact CLI invocations.
- Prior metadata preserved at `05-candidate-package-metadata-2026-09-15-corr1.json`.
- `scripts/generate-candidate-package-metadata.mjs` dynamically generates metadata from live run reports, git info, and manifest digests.

### Challenge 17: Pass A method consistency and future/procedure wording
- **Verdict: PASS**
- `05-pass-a-technical-method-draft.md` L6: "Proposed Technical Method Draft (Pending Formal Group Review and Adoption)".
- L7: "Shared Google Doc Transfer Link: PENDING GROUP REVIEW AND ADOPTION".
- L17: Uses future/procedure wording: "Once adopted, the text will be transferred..."
- L132: "These procedures represent proposed research protocols pending formal group and PC adoption."
- L55: "Formal manual human adjudication of ground-truth findings remains pending group review."
- No past-tense claims of completed laboratory testing or finalized results.

### Challenge 18: No method/result optimization or fabricated AU/human claims
- **Verdict: PASS**
- Adjudication status: `PENDING_MANUAL_GROUND_TRUTH_ADJUDICATION` throughout.
- No human reviewer names claimed in automated entries. `AUTOMATED_EVALUATOR` used only for automated target matches, explicitly rejected for completed human reviews (adjudication.mjs L362-363, L383-384).
- No AU laboratory timing results claimed. Timing boundary explicitly labeled "Node development environment only" (runner.mjs L228-230).
- Checklist L57: "They do NOT establish live browser DOM rendering speeds or VS Code extension responsiveness on physical AU computer laboratory machines."

### Challenge 19: Manifest/source provenance fields
- **Verdict: PASS**
- Run metadata includes: `runId`, `engine`, `evaluatorVersion`, `evaluatorCommit` (full SHA), `isWorkingTreeClean`, `branch`, `datasetManifestVersion`, `datasetBaseCommit`, `manifestSha256`, `environment` (Node version, platform, arch, V8 version), `dependencies`, `devDependencies`.
- Package metadata includes: `datasetBaseCommit`, `acceptedPhase04EvidenceCommit`, `evaluatorSourceCommit`, scanner source SHA-256 hashes, evaluator module SHA-256 hashes.
- Schema version tracked in all reports (`1.0.0`).

### Challenge 20: All stated limitations and human/group freeze decisions remain honest
- **Verdict: PASS**
- Checklist Section 3 (L53-64) explicitly lists 8 limitations including: Node timing only, AST vs runtime, controlled benchmark boundary (N<=108), human adjudication pending, candidate unfrozen, Google Doc migration pending, push to remote NOT RUN, Opus review NOT RUN.
- Package metadata status: "PROPOSED / UNFROZEN (Phase 05 Candidate - Pending Capstone Group Review and Adoption)".
- No claims of group freeze adoption. No claims of adviser approval.

---

## 4. Additional Independent Checks

### Diff Scope Verification
- `git diff --stat 0a76a2f d63281e` shows 52 files changed, 172,020 insertions, 7 deletions.
- All new files are in `validation/evaluator/`, `documents/research-phases/checks/`, and `scripts/`. No scanner engine code, dataset files, or detection rules were modified.

### Metric Arithmetic Cross-Check (Both Engines)
```
TP=45, TN=53, FP=1, FN=9, N=108
N = 45+53+1+9 = 108 ✓
Accuracy = 98/108 = 0.9074 ✓
Precision = 45/46 = 0.9783 ✓
Recall = 45/54 = 0.8333 ✓
Specificity = 53/54 = 0.9815
FPR = 1/54 = 0.0185
FNR = 9/54 = 0.1667
Expected-Rule Recall = 51/60 = 0.85 ✓
Target-Match Fraction = 51/52 = 0.9808
```

### Web vs Extension Consistency
Both engines produce identical confusion matrix values (TP=45, TN=53, FP=1, FN=9), expected-rule metrics (51/60), and finding precision metrics (51/52). This is consistent with deterministic static analysis engines running against the same dataset.

---

## 5. Findings Summary

| # | Finding | Severity | Evidence |
| --- | :--- | :--- | :--- |
| 1 | All 20 challenge areas satisfied | INFO | See Section 3 above |
| 2 | 52 evaluator tests pass; 48 regression tests pass | INFO | Direct execution at candidate commit |
| 3 | ESLint clean (0 errors, 0 warnings) | INFO | `npm run lint` exit code 0 |
| 4 | Worktree requires `npm install` for live scanner integration tests | LOW | Tests 17, 18, 28 fail without dependencies; pass after install. Not a code defect. |
| 5 | Both engines produce identical metrics (deterministic) | INFO | TP/TN/FP/FN and recall figures identical across web and extension |
| 6 | Adjudication precision correctly pending (1 unmatched finding) | INFO | `C-A1-001.js` line 9 OWASP-A08-001 remains `PENDING_MANUAL_ADJUDICATION` |
| 7 | Package metadata correctly labeled `PROPOSED / UNFROZEN` | INFO | No premature freeze claims |
| 8 | Prior run evidence preserved (3 versioned directories) | INFO | `phase05-batch-b/`, `phase05-batch-b-corr1/`, `phase05-batch-b-corr2/` all exist |

No CRITICAL, HIGH, or MEDIUM severity issues found.

---

## 6. Limitations of This Verification

1. **Model identity:** This report was produced under Antigravity (Agy) with user-selected "Claude Opus 4.6 (Thinking)" model. The actual served model identity cannot be independently confirmed beyond the harness label.
2. **Live benchmark rerun not performed:** The verifier did not re-execute the full 232-scan benchmark. Evidence review was based on committed run artifacts. The evaluator tests were independently executed against the actual scanner engines.
3. **Semantic description review:** Manual semantic description review of finding messages was not performed. The evaluator correctly marks this as `PENDING_MANUAL_SEMANTIC_REVIEW`.
4. **Sample file content integrity:** SHA-256 verification of all 116 sample files against the package metadata digests was not independently repeated at the file level. The manifest SHA-256 was verified to match between package metadata and run metadata.
5. **jsentinel-27 workspace:** The prior incomplete session workspace was not inspected or modified.

---

## 7. Verdict

**PASS (Scoped Technical Verification)**

The Phase 05 candidate commit `d63281e8f3d9c5beb64d4c146e1094a8c0f027b2` satisfies all 20 stated challenge areas. The evaluator correctly separates from scanner functionality, enforces one-to-one matching, handles edge cases (zero denominators, parse failures, duplicates, advisories), maintains scenario/controlled separation, preserves raw evidence for both engines, binds run provenance cryptographically, and makes no fabricated human or AU claims. All tests pass. No code defects or methodology errors were identified.

**This technical verification is distinct from the genuine human/group freeze decision.** The candidate package metadata is correctly labeled `PROPOSED / UNFROZEN`. Formal freeze adoption, Google Doc transfer, and AU laboratory testing remain pending the student group's own review and approval.

---

Verifier: Antigravity (Agy) / Claude Opus 4.6 Thinking, session `jsentinel-28`
Report Date: September 15, 2026
Base Commit: `0a76a2f61dea576a0155153a8e0bad6a4d42fdbb`
Source Commit: `1b4f885fa4d4b19621ba08ab560cd06034bc9c05`
Candidate Commit: `d63281e8f3d9c5beb64d4c146e1094a8c0f027b2`
