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

8. **Manifest Defect Resolution (Post-Commit 697ccb4):**
   - **Elimination of Borrowed Rule IDs:** In `build-dataset-manifest.cjs`, when a browser weakness has no matching rule in the scanner registry (`PAIR-033`, `PAIR-053`, `PAIR-054`), `ruleId` is now set to `null` and `unsupported: true` is explicitly recorded. The builder no longer borrows rules from other categories.
   - **Elimination of Synthetic Placeholder Coordinates:** Replaced all 9 instances of `{ line: 1, column: 0 }` with exact AST source coordinates for weakness constructs in `V-A2-018`, `V-A6-033`, `V-A6-036`, `V-A6-037`, `V-A7-042`, `V-A9-051`, `V-A9-052`, `V-A10-053`, and `V-A10-054`. Zero placeholder coordinates remain.
   - **Canonical Rule-to-Category Mappings:** Introduced `getCanonicalRuleCategory(ruleId)` to resolve categories directly from canonical rule definitions. In `V-A8-045.js`, `OWASP-A08-001` maps to `A08:2021-Software and Data Integrity Failures` while `OWASP-A01-002` maps to `A01:2021-Broken Access Control`. In `V-A6-034.js`, `OWASP-A03-001` correctly maps to `A03:2021-Injection`.
   - **Separation of Ground Truth from Scanner Behavior:** Expected findings represent benchmark ground truth expectations (`expectedScannerFindings`). Raw scanner results are stored separately under `observedScannerFindings`.
   - **Sample Security Context Enhancements:**
     - `PAIR-029`: Explicitly documents that `V-A5-029.js` assumes missing backend RBAC enforcement on `/api/v1/users/:id/grant-superuser`. `C-A5-029.js` relies on a verified server-side RBAC contract on session credentials.
     - `PAIR-045`: Added `accessAdministrativeDiagnostics()` in `V-A8-045.js`, which unlocks confidential diagnostic data when `window.__adminMode` is true. `C-A8-045.js` documents that schema validation verifies structural integrity, while authorization is enforced by fixing `role: 'standard_user'`.
     - `PAIR-046`: `V-A8-046.js` defines an unvalidated telemetry exfiltration context under browser CORS. `C-A8-046.js` updates `verifyAppConfig` to return a safe fallback object `{ endpointUrl: '/api/v1/feed' }` for `null`, `undefined`, or primitive inputs, avoiding unhandled `TypeError` exceptions.
   - **Structural Integrity Validation:** Added Test 7 to `validation/pilot-manifest.test.mjs` verifying canonical category mappings, positive non-placeholder coordinates, unsupported rule contracts, and runtime safety. Total passing tests: 47/47.

9. **Manifest Observation Invariance and Evidence Accuracy Corrections (Post-Commit fd17002):**
   - **Elimination of Expected-Output Scanner Dependence:** Completely removed runtime scanner dependence from `build-dataset-manifest.cjs`. Every controlled pair (`001` through `054`) now explicitly defines its complete `expectedFindings` array directly in `pairMetadata` with canonical rule ID, canonical category, severity, exact AST coordinates, and reviewed weakness description. Clean files uniformly record `expectedScannerFindings: []`.
   - **Decoupling Scanner Execution to Observed Fields Only:** Scanner executions (`scanCode`) now populate only `observedScannerFindings`. Expected findings and security ground truth are strictly derived from reviewed pair metadata.
   - **Manifest Observation Invariance Test (Test 8):** Added Test 8 to `validation/pilot-manifest.test.mjs`. Confirms that replacing the observation provider with an empty mock scanner or a noisy mock scanner leaves `expectedScannerFindings`, `securityGroundTruth`, and `label` 100% deep-equal across all 116 files.
   - **Evidence Accuracy and Scope Clarifications:**
     - `PAIR-029`: Replaced "verified server contract" claims with assumed/simulated server RBAC contract; explicitly noted live backend enforcement was NOT RUN in this client-only unit scope.
     - `PAIR-045`: Documented that `accessAdministrativeDiagnostics()` models a simulated protected-resource contract; client source code is public and cannot assure production secrecy without server enforcement.
     - `PAIR-046`: Transmits synthetic sensitive client credentials (`token_synthetic_telemetry_user_session_441`, `researcher@example.internal`). Removed misleading simple-request claims, explicitly noting that `application/json` POST triggers a CORS preflight (`OPTIONS`). In `C-A8-046.js`, benign telemetry to approved destinations is preserved while blocking untrusted external destinations with a null-safe fallback.

## 4. Implementation Files Changed

| File | Change | Consequence |
| --- | --- | --- |
| `test-samples/samples/` (12 files updated) | Corrected PAIR-016, PAIR-017, PAIR-029, PAIR-030, PAIR-034, PAIR-045, and PAIR-046. | Eliminates undefined helpers, fixes entropy, establishes concrete consumers, models CORS preflights, and removes unverified server claims. |
| `test-samples/generate-samples.cjs` | Synchronized templates for corrected pairs; verified with `--check`. | Deterministic reproducibility for all 108 controlled samples. |
| `test-samples/pilot-manifest-entries.json` | Extracted and preserved the 12 canonical accepted pilot manifest entries from `92951de`. | Safeguards pilot metadata from automated overwrite. |
| `test-samples/build-dataset-manifest.cjs` | Embeds explicit `expectedFindings` across all 54 pairs in `pairMetadata`, decouples scanner executions to `observedScannerFindings` only, and parameterizes observation provider. | Produces fully decoupled, defensible 116-file manifest with zero scanner circularity. |
| `test-samples/dataset-manifest.json` | Regenerated complete 116-file manifest reflecting all corrections and explicit expected findings. | Canonical dataset specification for Phase 04 with zero placeholders, zero category mismatches, and complete scanner independence. |
| `validation/pilot-manifest.test.mjs` | Added Test 7 (structural integrity) and Test 8 (manifest observation invariance under mock empty and noisy scanners). | Automated verification of Batch B corrections, structural integrity, and observation invariance. |
| `documents/research-phases/checks/04-batch-b-manifest-invariance-self-check-2026-09-14.md` | Recorded itemized defect resolutions, observation invariance audit, and remaining limitations. | Audit evidence document for post-fd17002 fixes. |
| `documents/research-phases/checks/04-changes.md` | Updated changes document with Batch B corrections and observation invariance resolution. | Permanent changes log. |
| `documents/research-phases/checks/04-checklist.md` | Updated checklist with 48 tests and pass status. | Quality checklist. |
| `documents/research-phases/checks/04-issues.md` | Updated issues document with observation invariance resolution, evidence accuracy audits, and carry-forwards. | Issues log. |

## 5. Verification Commands and Exit Codes

| Command Line | Purpose | Exit Code | Observed Result |
| --- | --- | ---: | --- |
| `node test-samples/generate-samples.cjs --check` | Verify disk samples match generator templates | 0 | Check Mode: 108 matches, 0 mismatches out of 108 checked. |
| `node test-samples/build-dataset-manifest.cjs` | Rebuild manifest from explicit metadata | 0 | Generated 116 files (108 controlled reviewed, 8 scenarios pending). |
| `node --test validation/pilot-manifest.test.mjs` | Run manifest, hash, VM, structural, and invariance tests | 0 | 8 of 8 tests passed (~2783ms). |
| `node --test validation/*.test.mjs validation/*.test.js validation/*.test.cjs` | Run full validation suite across repository | 0 | 48 of 48 tests passed (~6910ms, zero regressions). |
| `npm run lint` | Run ESLint across web project | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm --prefix vscode-extension run lint` | Run ESLint across VS Code extension | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm run build` | Build Vite web application bundle | 0 | Built in 2.25s; 233 modules transformed. |

## 7. Phase 04 Batch C: Scenario Adaptation, Decoupled Expectations, and Dataset Distribution

Phase 04 Batch C completed the final segment of Phase 04 per `04-dataset-and-manifest.md`:

1. **Simulated Application Scenarios Adapted to Browser Workloads:**
   - Evaluated the 8 simulated scenarios in `test-samples/samples/`. Removed Express server imports, server listeners (`app.listen()`), and server CORS middleware.
   - Adapted each file into a realistic browser module while preserving every intended client security flaw:
     - `admin-dashboard.jsx`: React dashboard with DOM XSS, role checks, and open redirects.
     - `api-gateway.js`: Browser API request router with JWT handling, regex DoS, and redirect hooks.
     - `chat-application.js`: Browser WebSocket chat client with event markup rendering and script injection.
     - `data-pipeline.js`: Client data analytics pipeline with batch worker dispatching and prototype pollution.
     - `ecommerce-checkout.js`: Multi-step checkout workflow with synthetic client tokens and promo code `eval()`.
     - `payment-processor.js`: Browser payment form SDK with iframe postMessage bridges and dynamic script tags.
     - `student-portal.jsx`: React portal with grade rendering, unvalidated links, and role checks.
     - `user-auth-service.js`: Browser authentication client managing password reset flows and tokens.
   - Both AST scanner engines parse all 8 scenarios cleanly with zero syntax errors.

2. **Independent Canonical Scenario Sources and Generator Synchronization:**
   - Created `test-samples/scenario-definitions.cjs` defining templates, browser contexts, threat models, and expectations.
   - Updated `test-samples/generate-samples.cjs` to produce all 116 files with Windows CRLF normalization.
   - Verified that `node test-samples/generate-samples.cjs --check` reports 116 matches and 0 mismatches.

3. **Curated Scenario Expectations in Manifest:**
   - Curated 123 distinct expected vulnerability findings across all 8 scenarios with exact source coordinates and semantic descriptions.
   - Curated 14 component-review advisories under `OWASP-A06-001`.
   - Curated 10 unsupported browser weaknesses with explicit `ruleId: null` and `unsupported: true`.
   - Scanner executions populate `observedScannerFindings` exclusively.

4. **Manifest Observation Invariance Across All 116 Files:**
   - Extended Test 8 in `validation/pilot-manifest.test.mjs` across all 116 files.
   - Replacing the scanner observation provider with empty or noisy mock scanners leaves `expectedScannerFindings`, `expectedAdvisories`, `unsupportedWeaknesses`, `securityGroundTruth`, and `label` 100% invariant across all 116 files.

5. **Dataset Distribution Table:**
   - Created `test-samples/dataset-distribution.md` and `documents/research-phases/checks/04-dataset-distribution.md`.
   - Reconciled 108 controlled files across 7 active vulnerability modules (54 V, 54 C), 0 controlled pairs in `knownVulns.js` (explained as an informational advisory module), 8 composite simulated browser scenarios, and 116 total files.

6. **Controlled Sample Preservation:**
   - All 108 controlled benchmark files remain 100% byte-identical to commit `c650be9`.
   - Verified against `documents/research-phases/checks/04-batch-c-controlled-108-hashes.json`.

## 8. Post-Commit 38c1562 Manager Corrections: Ground Truth & Evidence Accuracy

Following integrated manager review of commit `38c1562`, bounded corrections were applied to establish true security ground truth:

1. **Elimination of Copied Scanner Output as Ground Truth:**
   - Evaluated all 133 raw scanner detections across the 8 scenarios against concrete trust boundaries, attacker control, exploit prerequisites, and demonstrable security impact.
   - Curated 105 genuine expected vulnerability findings across the 8 scenarios, rejecting false positives and syntactic pattern warnings.
   - Removed client role checks that only log to console (`admin-dashboard.jsx` line 16, `student-portal.jsx` line 30).
   - Removed non-secret internal IP address constants (`chat-application.js` line 16, `data-pipeline.js` line 19, `payment-processor.js` line 15, `user-auth-service.js` line 17).
   - Removed public AWS Access Key ID without secret (`user-auth-service.js` line 14).
   - Removed `JSON.parse` syntactic warnings where no unsafe consumer exists.
   - Preserved all scanner signals in `observedScannerFindings`.

2. **Callable Helper Assumptions vs Demonstrated Application Flows:**
   - Documented callable helper assumptions for uninvoked functions (`renderNotification`, `updateSidebar`, `navigateToPartner`, `renderGradeCard`, `renderCourseDescription`, `loadAnnouncement`).
   - Disclosed that in `admin-dashboard.jsx`, `renderLegacyWidget` is invoked with a fixed constant string (`"System Status: Online"`), making that call site fixed-safe in demonstrated UI execution, while representing a critical DOM injection sink under callable helper assumptions.

3. **Grounded Expected Advisories:**
   - Grounded all component review advisories strictly in third-party package imports.
   - Verified that 7 of the 8 scenarios import third-party packages (14 advisories total), while `user-auth-service.js` imports zero third-party packages and has 0 advisories.

4. **Severity and Threat Models for Unsupported Weaknesses:**
   - Curated 6 authentic browser weaknesses without scanner rules (`api-gateway.js` line 39, `chat-application.js` line 108, `data-pipeline.js` line 71, `ecommerce-checkout.js` line 10, `payment-processor.js` line 56, `student-portal.jsx` line 37).
   - Added explicit `severity`, `severityAssumptions`, `trustBoundary`, `attackerControlledInput`, and `securityImpact` to every unsupported record.
   - Removed the uncredited dynamic GET fetch in `admin-dashboard.jsx` due to lack of ambient credentials, state exfiltration, or concrete security impact.

5. **Controlled Dataset Terminology:**
   - Replaced "controlled single-flaw" phrasing with "controlled V/C dataset".
   - Preserved per-file labels and multi-expectation findings (e.g. `V-A8-045.js` with 2 findings).

## 9. Verification Commands and Exit Codes

| Command Line | Purpose | Exit Code | Observed Result |
| --- | --- | ---: | --- |
| `node test-samples/generate-samples.cjs --check` | Verify disk samples match generator templates | 0 | Check Mode: 116 matches, 0 mismatches out of 116 checked. |
| `node test-samples/build-dataset-manifest.cjs` | Rebuild manifest from explicit metadata | 0 | Generated 116 files (108 controlled reviewed, 8 scenarios reviewed, 0 pending). |
| `node --test validation/pilot-manifest.test.mjs` | Run manifest, hash, VM, structural, and invariance tests | 0 | 8 of 8 tests passed (~939ms). |
| `node --test validation/*.test.mjs validation/*.test.js validation/*.test.cjs` | Run full validation suite across repository | 0 | 48 of 48 tests passed (~4000ms, zero regressions). |
| `npm run lint` | Run ESLint across web project | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm --prefix vscode-extension run lint` | Run ESLint across VS Code extension | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm run build` | Build Vite web application bundle | 0 | Built in 1.81s; 233 modules transformed. |

## 10. Post-Commit 2afe0ff/e21f77f Manager Corrections: Ground Truth Refinements and Evidence Erratum

Following manager review of commits `2afe0ff` and `e21f77f`, further bounded corrections were implemented to ensure strict grounding in actual code semantics:

1. **`chat-application.js` Semantics:**
   - Omitted Firebase Web API key (line 13) from expected findings: public project identifier per Google Firebase documentation, not a private secret.
   - Omitted presence (line 62) and timestamp (line 65) cookies: non-sensitive telemetry without auth roles; client JavaScript cannot set `HttpOnly` per RFC 6265 Section 5.3.
   - Omitted `sessionSalt = Math.random()` (line 68): no security-sensitive consumer demonstrated.
   - Omitted `localStorage.setItem('chatToken', userId)` (line 71): stores non-sensitive `userId`.

2. **Fixed String Timers:**
   - Omitted 9 static string timers (`api-gateway.js` line 70, `chat-application.js` lines 99 and 100, `data-pipeline.js` lines 99 and 102, `ecommerce-checkout.js` line 31, `payment-processor.js` lines 106 and 107, and `student-portal.jsx` line 96) from expected findings due to lack of variable interpolation or attacker control.
   - Retained exactly 1 dynamic string timer: `api-gateway.js` line 73 (`setTimeout(\`reportHealth('\${serviceId}')\`, 5000)`), which interpolates user-controlled `serviceId`.

3. **Prototype Assignments on Unused Targets:**
   - Omitted 8 prototype assignment pattern hits (`api-gateway.js` lines 51 and 54, `chat-application.js` lines 82 and 88, `data-pipeline.js` lines 51 and 88, `payment-processor.js` lines 68 and 74) where targets are locally scoped empty objects that are unused and do not pollute global `Object.prototype`.

4. **Generic Diagnostic Logging:**
   - Omitted 9 generic logging pattern hits (`api-gateway.js` lines 61 and 62, `chat-application.js` lines 34 and 35, `data-pipeline.js` line 67, `payment-processor.js` lines 77 and 78, `user-auth-service.js` lines 84 and 85) without confidential credential payloads.

5. **Final Reconciled Totals:**
   - 75 Expected Findings (genuine exploitable browser vulnerabilities)
   - 14 Expected Advisories (`OWASP-A06-001` grounded in third-party package imports)
   - 48 Omitted Pattern Hits (AST heuristic detections without vulnerability context)
   - 6 Unsupported Browser Weaknesses (no scanner rule; explicit threat models)
   - Total observed scanner detections: exactly 137 (75 + 14 + 48 = 137).

## 11. Final Bounded Pre-Opus Cleanup

Following manager review of the reconciled evidence:
1. **Refined Test Assertions:** Replaced global prohibitions on `OWASP-A08-002` and `OWASP-A05-003` in `validation/pilot-manifest.test.mjs` Test 7 with precise assertions for reviewed omitted hits (prototype assignments with unused targets, generic diagnostic logging, static string timers, and generic JSON.parse warnings). Retained explicit check for dynamic timer at `api-gateway.js:73`.
2. **Controlled Dataset Terminology:** Replaced "controlled single-flaw" phrasing with "controlled V/C dataset" in `test-samples/build-dataset-manifest.cjs` and `test-samples/dataset-manifest.json` because controlled files like `V-A8-045.js` carry multiple expected findings.
3. **Clean Diffs:** Addressed trailing blank lines at EOF to ensure clean passes under `git diff --check`.

## 12. Workflow Stopping Point

This completes Phase 04 Batch C bounded ground truth corrections and final pre-Opus cleanup. All work stops here for integrated manager review (Astra coordinator `jsentinel-4`). In accordance with research phase boundaries, no evaluator execution, dataset freeze, formal accuracy benchmark scoring, thesis chapter edits, or remote git push were performed. No claims of completion or acceptance are made prior to manager review.
