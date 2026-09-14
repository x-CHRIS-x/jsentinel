# Phase 04 Batch B: Changes, Controlled Dataset Expansion, and Manager Corrections

Branch: `ao/jsentinel-24/phase04-dataset-pilot`. Date: September 14, 2026.
Session: AO worker `jsentinel-24`. Model route: Agy with Gemini 3.8 Flash (High).
Manager: Astra coordinator (`jsentinel-4`). Independent verifier: Opus HOLD.

## 1. Commit and Branch Reference

- Comparison Base: `ca154776e3896fe4cc6db883b46d9caaf0d23089` (docs(phase03): record manager acceptance).
- Accepted Phase 03 Chain: `caa5e6c`, `1e1ade4`, `8155a82`, `ca15477`.
- Prior Phase 04 Commits on Branch:
  - `2026e50` (feat: Phase 04 Batch A pilot pairs, manifest draft, and generator)
  - `fd5e278` (docs: Phase 04 Batch A pilot changes and baseline hashes)
  - `20c4f02` (docs: inventory reconciliation and RFC 6265 audit)
  - `5f50488` (feat: pilot ground truth, threat models, and helper contracts)
  - `5414496` (docs: pilot ground truth refinements and evidence)
  - `8b6cb52` (fix: execute actual sample code in isolated VM and remove tautological DOM claims)
  - `92951de` (docs: record correction self-check for isolated VM execution and disclosed unrun DOM checks)
  - `089b864` (feat: expand controlled benchmark to 54 pairs with browser mitigations)
  - `79aa08c` (docs: record Batch B self-check, checklist, and coverage rationale)
- Scope: Phase 04 Batch B complete with bounded corrections addressing manager review findings. Fully expanded all 54 controlled V/C pairs (108 files) while preserving all 12 pilot files and all 8 scenario files byte-identical. Total dataset contains exactly 116 files.
- Never use stale `main` or edit `main`. All work resides on dedicated branch `ao/jsentinel-24/phase04-dataset-pilot`.

## 2. Inventory and Dataset Structure

The benchmark repository contains exactly 116 files in `test-samples/samples/`:
- 54 Vulnerable benchmark samples (`V-*.js`): 6 pilot files plus 48 Batch B files.
- 54 Clean benchmark samples (`C-*.js`): 6 pilot files plus 48 Batch B files.
- 8 Simulated browser application scenarios: `admin-dashboard.jsx`, `api-gateway.js`, `chat-application.js`, `data-pipeline.js`, `ecommerce-checkout.js`, `payment-processor.js`, `student-portal.jsx`, `user-auth-service.js`.

### Strict Baseline and Pilot Preservation
1. **12 Pilot Files:** The 6 pilot pairs (`PAIR-007`, `PAIR-009`, `PAIR-023`, `PAIR-027`, `PAIR-039`, `PAIR-049`) are 100% byte-identical to their committed pilot implementations at `8b6cb52`.
2. **8 Scenario Files:** All 8 scenario files are 100% byte-identical to their pre-change baseline hashes recorded in `04-baseline-hashes.json` and `04-baseline-hashes.md`. Their ground truth status remains `pending-batch-c` with `isVulnerable: null`.

## 3. Manager Review Findings and Bounded Corrections

Following manager inspection of commit `089b864`, bounded corrections were applied to resolve specific issues:

1. **Unsafe Context for JSON Parsing (PAIR-045, PAIR-046):**
   - In `V-A8-045.js`, untrusted JSON deserialization directly controls administrative privileges (`if (session.isAdmin) enableAdminPrivileges()`), creating an explicit authorization vulnerability.
   - In `C-A8-045.js`, a self-contained `validateSessionSchema` function strictly validates schema properties and assigns `role: 'standard_user'`, rejecting client-asserted administrative privileges.
   - In `V-A8-046.js`, untrusted configuration JSON controls the target URL in `fetch(config.endpointUrl)`.
   - In `C-A8-046.js`, an executable `verifyAppConfig` function enforces an allowlist of permitted endpoints (`/api/v1/feed`, `/api/v1/profile`).

2. **Auth Token Cookie Storage (PAIR-016):**
   - Replaced benign theme preference with direct remediation of the intended authentication credential storage vulnerability.
   - `V-A2-016.js` stores auth tokens in `document.cookie` without `HttpOnly` protection.
   - `C-A2-016.js` delegates credential storage to the backend server via `POST /api/auth/token-exchange`, which returns an `HttpOnly; Secure; SameSite` cookie in the `Set-Cookie` response header.
   - Eliminating `document.cookie` assignment in the clean sample resolves both the RFC 6265 browser impossibility and the static scanner false positive.

3. **Client-Side Role Authorization Context (PAIR-029):**
   - Replaced UI menu hiding with actual administrative action execution (`POST /api/v1/users/:id/grant-superuser`).
   - `V-A5-029.js` guards the action using client-side `userContext.role === 'admin'`.
   - `C-A5-029.js` delegates authorization enforcement to the server endpoint without performing client-side role checks.

4. **Arbitrary Fetch and Ambient Credentials (PAIR-053):**
   - Audited browser cookie scoping against WHATWG Fetch Section 4.4 and RFC 6265 Section 5.3.
   - Clarified the threat model: browsers attach ambient credentials scoped to the destination host, not the calling site.
   - The security impact is client-side request forgery (CSRF / confused deputy) against internal intranet services or authenticated third-party APIs.
   - `C-A10-053.js` restricts credentialed fetch destinations to an allowlist of approved application domains.

5. **Self-Contained Helpers (PAIR-030, PAIR-034):**
   - Defined `triggerSystemPurge()` self-contained in `V-A5-030.js` and `C-A5-030.js`.
   - Defined `handleSafeAction(action)` self-contained in `C-A6-034.js` with an allowlist of safe actions.

6. **Cryptographic Key Entropy (PAIR-017):**
   - Updated `C-A2-017.js` to generate `otp_key` using 256 bits (32 bytes) of cryptographic randomness from `crypto.getRandomValues`, formatted as a 64-character hex string.
   - Documented that the 6-digit numeric OTP assumes server-side rate limiting (max 3-5 attempts) and short expiration (30-60s), while `otp_key` provides full 256-bit cryptographic strength.

7. **Manifest Metadata and Pilot Preservation:**
   - Preserved all 12 accepted pilot metadata entries from `test-samples/pilot-manifest-entries.json` with 100% fidelity.
   - Set `manifest.coverageStatus.partialCoverageExplicit: true` because 8 scenarios are pending Batch C.
   - Updated `developmentUseRationale`: distinguishes baseline regression files from newly updated Batch B files.
   - Clean entries record `expectedScannerFindings: []` as ideal security expectations.

## 4. Implementation Files Changed

| File | Change | Consequence |
| --- | --- | --- |
| `test-samples/samples/` (12 files updated) | Corrected PAIR-016, PAIR-017, PAIR-029, PAIR-030, PAIR-034, PAIR-045, and PAIR-046. | Eliminates undefined helpers, fixes entropy, establishes concrete consumers, and delegates auth cookies. |
| `test-samples/generate-samples.cjs` | Synchronized templates for corrected pairs; verified with `--check`. | Deterministic reproducibility for all 108 controlled samples. |
| `test-samples/pilot-manifest-entries.json` | Extracted and preserved the 12 canonical accepted pilot manifest entries from `92951de`. | Safeguards pilot metadata from automated overwrite. |
| `test-samples/build-dataset-manifest.cjs` | Preserves pilot entries, updates threat models, distinguishes development rationales, and sets explicit partial coverage. | Produces comprehensive, defensible 116-file manifest. |
| `test-samples/dataset-manifest.json` | Regenerated complete 116-file manifest reflecting all corrections. | Canonical dataset specification for Phase 04. |
| `validation/pilot-manifest.test.mjs` | Added Test 6 testing VM execution of updated helpers, contracts, 256-bit entropy, and partial coverage flags. | Automated verification of Batch B corrections. |
| `documents/research-phases/checks/04-batch-b-correction-self-check-2026-09-14.md` | Recorded itemized findings and resolutions report. | Audit evidence document. |
| `documents/research-phases/checks/04-changes.md` | Updated changes document with Batch B corrections. | Permanent changes log. |
| `documents/research-phases/checks/04-checklist.md` | Updated checklist with 46 tests and pass status. | Quality checklist. |
| `documents/research-phases/checks/04-issues.md` | Updated issues document with resolved findings and cookie/fetch audits. | Issues log. |

## 5. Verification Commands and Exit Codes

| Command Line | Purpose | Exit Code | Observed Result |
| --- | --- | ---: | --- |
| `node test-samples/generate-samples.cjs --check` | Verify disk samples match generator templates | 0 | Check Mode: 108 matches, 0 mismatches out of 108 checked. |
| `node --test validation/pilot-manifest.test.mjs` | Run manifest, hash, and VM correction tests | 0 | 6 of 6 tests passed (~846ms). |
| `node --test validation/*.test.mjs validation/*.test.js validation/*.test.cjs` | Run full validation suite across repository | 0 | 46 of 46 tests passed (~4565ms, zero regressions). |
| `npm run lint` | Run ESLint across web project | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm --prefix vscode-extension run lint` | Run ESLint across VS Code extension | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm run build` | Build Vite web application bundle | 0 | Built in 1.98s; 233 modules transformed. |

## 6. Disclosed Unrun Checks (NOT RUN)

1. Live browser DOM event execution and visual rendering: **NOT RUN**. Unit tests verify isolated VM execution and data transport to sink properties.
2. Formal accuracy measurement or benchmark scoring: **NOT RUN**. Reserved for Phase 05 and Phase 07.
3. Phase 05 evaluator execution: **NOT RUN**. Evaluator prototype scripts execute after dataset freeze.
4. Eight simulated browser scenarios: **NOT RUN** / **NOT MODIFIED**. Preserved byte-identical pending Batch C.
5. Push to remote or branch merge: **NOT RUN**. All branches remain local in AO workspace.

## 7. Workflow Stopping Point

This completes Phase 04 Batch B bounded corrections. All work stops here for manager review (Astra coordinator) before any scenario migration (Batch C) begins. No evaluator, freeze, accuracy benchmark, Chapter editing, or push was performed.
