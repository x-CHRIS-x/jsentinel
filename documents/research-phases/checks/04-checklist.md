# Phase 04 Batch A Checklist

Date: September 14, 2026.
Branch: `ao/jsentinel-24/phase04-dataset-pilot`.
Harness: AO worker `jsentinel-24`, Agy with Gemini 3.8 Flash (High).
Manager: Astra coordinator. Verifier: Opus HOLD.

## 1. Acceptance Criteria Status

| Requirement | Status | Evidence and Verification |
| --- | --- | --- |
| 1. Create dedicated branch from exact base `ca15477` | **PASS** | Branch `ao/jsentinel-24/phase04-dataset-pilot` branched from `ca154776e3896fe4cc6db883b46d9caaf0d23089`. |
| 2. Strictly no subagents used; single session execution | **PASS** | All actions executed directly in `jsentinel-24` session without delegating to subagents. |
| 3. Preserve baseline SHA-256 hashes of prior 116 files | **PASS** | Hashes recorded in `04-baseline-hashes.json` and `04-baseline-hashes.md` prior to pilot changes. |
| 4. Identify six existing corresponding pilot pairs | **PASS** | Identified pairs: redirects (`PAIR-027`), exposed API secrets (`PAIR-023`), templateHTML (`PAIR-007`), function-resultHTML (`PAIR-009`), generalHTML (`PAIR-039`), object merge (`PAIR-049`). |
| 5. Exactly 12 pilot files prepared; other 104 unchanged | **PASS** | Only `C-A3-023.js` and `C-A8-049.js` modified; 10 pilot files verified intact; other 104 files untouched; total 116 preserved. |
| 6. Meaningful code variations and true browser mitigation | **PASS** | `C-A3-023.js` delegates to backend proxy instead of `process.env`; `C-A8-049.js` filters prototype properties before merging into fresh object. |
| 7. Synthetic secrets only | **PASS** | All API keys and tokens in `V-A3-023.js` and other samples are synthetic (`apikey_development_credential_...`, `token_prod_...`). |
| 8. Generator support synchronized for pilot reproducibility | **PASS** | `test-samples/generate-samples.cjs` updated with `--pilot` mode; reproduces the 12 files without touching the other 104 files. |
| 9. Manifest draft with explicit partial coverage | **PASS** | `test-samples/dataset-manifest.json` drafted; 12 pilot files marked `pilot-reviewed`, 104 files marked `pending-batch-b`/`pending-batch-c`. |
| 10. Ground truth separate from scanner observations | **PASS** | Manifest records independent security rationales, CWEs, and authoritative references (OWASP Top 10, CWE, MDN, W3C) separate from rule findings. |
| 11. Scanner observations record rule, category, severity, location, semantic text | **PASS** | Rule ID, OWASP 2021 category, severity, coordinate location, and semantic description documented for all pilot findings. |
| 12. Former A06 and server-only samples inventoried | **PASS** | Documented in `04-issues.md` with explicit reassignment plan for Batch B. |
| 13. Known `document.cookie`/HttpOnly issue inspected | **PASS** | Inspected and documented in `04-issues.md`; no scanner rule changes made in this batch. |
| 14. Validation test suite verifies pilot and manifest | **PASS** | `validation/pilot-manifest.test.mjs` executes 5 test cases covering counts, hashes, manifest, parsing, and dual-scanner agreement. |
| 15. Regression test suite passes with zero regressions | **PASS** | 45 test cases pass across all validation suites in `validation/`. |
| 16. Two-stage commit discipline | **PENDING** | Implementation files staged and committed first, followed by evidence documentation commit. |

## 2. Execution Record and Exit Codes

| Command Line | Purpose | Exit Code | Observed Result |
| --- | --- | --- | --- |
| `git checkout -b ao/jsentinel-24/phase04-dataset-pilot ca15477` | Create workspace branch from accepted Phase 03 base | 0 | Branch created cleanly at `ca15477`. |
| `node test-samples/generate-samples.cjs --pilot` | Regenerate pilot files and verify isolation | 0 | Generated 12 pilot files; 104 files untouched. |
| `node --test validation/pilot-manifest.test.mjs` | Run Phase 04 pilot manifest test suite | 0 | 5 of 5 tests passed (duration ~818ms). |
| `node --test validation/*.test.*` | Run complete regression test suite across project | 0 | 45 of 45 tests passed (duration ~5841ms). |

## 3. Disclosed Unrun Checks (NOT RUN)

In accordance with `AGENTS.md` and research integrity guidelines, the following paths were deliberately **NOT RUN**:
1. Full dataset regeneration (`node test-samples/generate-samples.cjs --all`): NOT RUN. Awaiting manager review and Batch B authorization before expanding remaining 104 files.
2. Formal accuracy measurement or benchmark scoring: NOT RUN. Phase 04 Batch A establishes the pilot dataset and manifest draft; accuracy scoring is reserved for Phase 05/07.
3. Phase 05 evaluator execution: NOT RUN. Evaluator prototype is dependent on frozen dataset completion.
4. VS Code UI extension testing or web UI browser clicking: NOT RUN. Manual UI testing is outside Batch A static dataset scope.
5. Push to remote or branch merge: NOT RUN. Work branches remain local in the AO workspace pending manager acceptance.
