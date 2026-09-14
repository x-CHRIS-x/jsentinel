# Phase 04 Issues and Inventory Notes

Date: September 14, 2026.
Branch: `ao/jsentinel-24/phase04-dataset-pilot`.
Manager: Astra coordinator (`jsentinel-4`). Independent verifier: Opus HOLD.

## 1. Resolved: Reassignment of Former A06 and Server-Only Cases in Batch B

Phase 01 retired server-side checks and established that A06 component-review signals are informational advisories rather than confirmed vulnerabilities. In Batch B, all 10 legacy pairs (20 files) that originally covered server-side headers or advisory imports were cleanly reassigned to defensible client-side browser weaknesses:

| Pair ID | Sample Files | Previous Legacy Check | Resolved Browser Weakness (Batch B) | CWE / OWASP Category |
| --- | --- | --- | --- | --- |
| `PAIR-033` | `V-A6-033.js` / `C-A6-033.js` | Express CORS wildcard (`res.setHeader`) | Cross-window `postMessage` with wildcard `*` target origin. Clean counterpart requires explicit target origin domain. | CWE-345 / OWASP A01 |
| `PAIR-034` | `V-A6-034.js` / `C-A6-034.js` | Express CORS wildcard variation 2 | Inbound message listener executing commands without origin validation. Clean counterpart validates `event.origin` and defines `handleSafeAction` self-contained. | CWE-346 / OWASP A01/A03 |
| `PAIR-035` | `V-A6-035.js` / `C-A6-035.js` | Express request logging (`console.log(req)`) | Console logging full request objects containing sensitive headers. Clean counterpart logs non-sensitive `req.path`. | CWE-532 / OWASP A05 |
| `PAIR-036` | `V-A6-036.js` / `C-A6-036.js` | Express request logging variation 2 | Console logging full authentication context objects. Clean counterpart logs non-sensitive numeric status code. | CWE-532 / OWASP A05 |
| `PAIR-037` | `V-A6-037.js` / `C-A6-037.js` | Express helmet middleware check | Unencrypted WebSocket connection `ws://` transmitting telemetry. Clean counterpart enforces `wss://`. | CWE-319 / OWASP A02 |
| `PAIR-038` | `V-A6-038.js` / `C-A6-038.js` | Express helmet variation 2 | External script inclusion over cleartext HTTP `http://`. Clean counterpart enforces HTTPS script source. | CWE-319 / OWASP A02 |
| `PAIR-051` | `V-A9-051.js` / `C-A9-051.js` | Advisory package imports (`serialize-javascript`) | Storing sensitive bearer authentication tokens in `sessionStorage`. Clean counterpart stores transient token in module memory closure. | CWE-922 / OWASP A07 |
| `PAIR-052` | `V-A9-052.js` / `C-A9-052.js` | Advisory package imports (`lodash`) | Exposing sensitive authentication tokens in `window.location.hash` URL fragment. Clean counterpart transmits token via in-memory Authorization request header. | CWE-598 / OWASP A02 |
| `PAIR-053` | `V-A10-053.js` / `C-A10-053.js` | Server SSRF (`axios.get(targetUri)`) | Client-side fetch to arbitrary user-supplied URL with ambient credentials. Clean counterpart validates origin against trusted API allowlist. | CWE-20 / OWASP A01 |
| `PAIR-054` | `V-A10-054.js` / `C-A10-054.js` | Server SSRF variation 2 | Dynamic script element injection pointing to unvalidated user-controlled URL. Clean counterpart loads pre-approved script with Subresource Integrity (SRI) hash verification. | CWE-829 / OWASP A03 |

## 2. Resolved: Manager Review Bounded Corrections

Manager inspection of commit `089b864` highlighted specific bounded issues, which have been fully corrected:

1. **Unsafe Parsing Consumers and Schema Verification (PAIR-045, PAIR-046):**
   - In `V-A8-045.js`, untrusted JSON deserialization directly controls administrative privileges (`if (session.isAdmin) enableAdminPrivileges()`), creating an explicit authorization vulnerability.
   - In `C-A8-045.js`, a self-contained `validateSessionSchema` function strictly validates schema properties and assigns `role: 'standard_user'`, rejecting client-asserted administrative privileges.
   - In `V-A8-046.js`, untrusted configuration JSON controls the target URL in `fetch(config.endpointUrl)`.
   - In `C-A8-046.js`, an executable `verifyAppConfig` function enforces an allowlist of permitted endpoints (`/api/v1/feed`, `/api/v1/profile`).

2. **Auth Token Cookie Storage (PAIR-016):**
   - Rather than shifting the problem to a benign UI preference, `C-A2-016.js` directly mitigates the intended authentication token storage vulnerability.
   - `C-A2-016.js` delegates credential storage to the backend server via `POST /api/auth/token-exchange`, which returns an `HttpOnly; Secure; SameSite` cookie in the `Set-Cookie` response header.
   - Eliminating `document.cookie` assignment in the clean sample resolves both the RFC 6265 browser impossibility and the static scanner false positive.

3. **Client-Side Role Authorization Context (PAIR-029):**
   - Replaced UI menu hiding with actual administrative action execution (`POST /api/v1/users/:id/grant-superuser`).
   - `V-A5-029.js` guards the action using client-side `userContext.role === 'admin'`.
   - `C-A5-029.js` delegates authorization enforcement to the server endpoint without performing client-side role checks.

4. **Arbitrary Fetch and Ambient Credentials (PAIR-053):**
   - Verified browser cookie scoping against WHATWG Fetch Section 4.4 and RFC 6265 Section 5.3.
   - The browser scopes cookies to the *destination* host, not the caller origin.
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
   - Updated `developmentUseRationale`: accurately distinguishes baseline regression files from newly updated Batch B files.

## 3. Resolved: Post-Commit 697ccb4 Manifest Defect Resolutions

Manager inspection of commit `697ccb4` identified manifest and sample defects, which are now resolved:

1. **Elimination of Borrowed Rule IDs for Unsupported Browser Weaknesses:**
   - Previous builder logic borrowed unrelated rules (`OWASP-A01-001`, `OWASP-A03-006`) when no active scanner rule existed for an intended browser weakness.
   - For `PAIR-033` (postMessage wildcard), `PAIR-053` (client fetch credentials), and `PAIR-054` (dynamic script inclusion), `ruleId` is now set to `null` with `unsupported: true` and documented in `ambiguityOrKnownLimitations`. No foreign rules are borrowed.

2. **Elimination of Synthetic Placeholder Coordinates (`line: 1, column: 0`):**
   - The fallback logic in `build-dataset-manifest.cjs` previously inserted `{ line: 1, column: 0 }` for scanner misses.
   - Audited all 54 pairs. Replaced every placeholder with exact AST coordinates of the weakness construct in each sample. Zero placeholder coordinates remain in `dataset-manifest.json`.

3. **Canonical Rule-to-Category Mappings:**
   - In `build-dataset-manifest.cjs`, finding categories are now mapped strictly through canonical rule definitions (`getCanonicalRuleCategory`).
   - In `V-A8-045.js`, `OWASP-A08-001` maps to `A08:2021-Software and Data Integrity Failures` (severity LOW) and `OWASP-A01-002` maps to `A01:2021-Broken Access Control` (severity MEDIUM).
   - In `V-A6-034.js`, `OWASP-A03-001` maps to `A03:2021-Injection` (severity CRITICAL).
   - Zero category mismatches exist across all 116 manifest entries.

4. **Separation of Ideal Ground Truth Expectations and Observed Scanner Output:**
   - Benchmark ground truth expectations are stored in `expectedScannerFindings` (curated ideal findings, clean files having `[]`).
   - Actual scanner runtime output is stored independently in `observedScannerFindings`. Scanner misses or false positives do not contaminate expected ground truth.

5. **Sample Security Context Enhancements:**
   - `PAIR-029`: Explicitly documents backend authorization assumptions. `V-A5-029.js` assumes missing backend RBAC enforcement where client checks are the sole barrier. `C-A5-029.js` relies on a verified server-side RBAC contract on session credentials.
   - `PAIR-045`: Added `accessAdministrativeDiagnostics()` in `V-A8-045.js` that exposes confidential diagnostic data when `window.__adminMode` is true. `C-A8-045.js` notes that schema validation checks structure and types, while authorization is enforced by setting `role: 'standard_user'`.
   - `PAIR-046`: `V-A8-046.js` defines an unvalidated telemetry exfiltration context under browser CORS. `C-A8-046.js` updates `verifyAppConfig` to return `{ endpointUrl: '/api/v1/feed' }` for `null`, `undefined`, or primitive inputs, preventing unhandled `TypeError` exceptions.

## 4. Resolved: Post-Commit fd17002 Manifest Observation Invariance and Evidence Accuracy

Manager inspection of commit `fd17002` identified remaining circularity where `build-dataset-manifest.cjs` relied on scanner output count to build expected findings, alongside evidence claims requiring precision:

1. **Elimination of Expected-Output Scanner Dependence:**
   - Previous manifest builder logic checked `meta.trueLocation && vScan.issues.length === 0`, and otherwise populated `expectedVFindings = vScan.issues.map(...)`.
   - Separating raw scanner output into `observedScannerFindings` did not fix this circularity because expected findings still depended on scanner detections.
   - We removed all runtime scanner dependence from expected finding generation. Every controlled pair (`001` through `054`) now explicitly defines its complete `expectedFindings` list in `pairMetadata` with canonical rule ID, canonical category, severity, exact AST coordinates, and reviewed weakness description.
   - Clean files uniformly record `expectedScannerFindings: []`. Raw scanner output populates only `observedScannerFindings`.

2. **Automated Manifest Observation Invariance Test (Test 8):**
   - Added Test 8 to `validation/pilot-manifest.test.mjs`.
   - The test builds the manifest under an empty mock scanner (`issues: []`) and a noisy mock scanner (`issues: [fabricatedRule]`).
   - The test asserts that `expectedScannerFindings`, `securityGroundTruth`, and `label` remain 100% byte-for-byte identical across all 116 files.
   - Only `observedScannerFindings` changes, confirming complete decoupling of benchmark truth from scanner output.

3. **Evidence Accuracy and Scope Corrections:**
   - `PAIR-029`: Replaced claims of a "verified server contract" with an assumed server-side RBAC contract. Explicitly disclosed that live backend enforcement was NOT RUN in this client-only unit test scope.
   - `PAIR-045`: Documented that `accessAdministrativeDiagnostics()` models a simulated protected-resource contract in client memory. Noted that client-side code is public and cannot guarantee production confidentiality without server enforcement.
   - `PAIR-046`: Updated payload to transmit synthetic sensitive client credentials (`token_synthetic_telemetry_user_session_441`, `researcher@example.internal`). Removed misleading "simple-request" claims, explicitly noting that `application/json` POST triggers a CORS preflight (`OPTIONS`). The clean counterpart preserves legitimate telemetry to approved application endpoints (`/api/v1/feed`, `/api/v1/profile`) with a null-safe fallback.

## 5. Authoritative Web Standards References

Manifest entries, test suites, and documentation cite authoritative, stable web specifications:
- WHATWG HTML Living Standard: Section 8.4 Dynamic markup insertion (`Element.innerHTML`)
- WHATWG DOM Standard: Section 4.2.3 Interface Node attribute `textContent`
- WHATWG Fetch Standard: Section 4.4 HTTP-network-fetch and CORS preflight triggers
- RFC 6265: Section 5.3 Step 10 (Storage Model non-HTTP API rejection)
- NIST SP 800-131A / SP 800-90A: Cryptographic Key Length and Random Number Generation

## 6. Carry-Forward Items and Disclosed Ambiguities

- **A03-001 Column-Zero Coordinate Mismatch:** An unrelated `eval()` check at column zero reports column `'unknown'` in the web scanner versus column `0` in the VS Code extension. This discrepancy is inherited from Phase 01/02 and is carried forward without altering engine behavior.
- **Client-Side Unit Test Scope:** Tests execute inside Node.js isolated VM contexts. Real browser DOM rendering, layout calculation, event loop dispatching (such as `onerror`), and live backend HTTP server enforcement were NOT RUN.
- **Client Visibility Limitations:** Client-side JavaScript is publicly visible to end users. Simulated access controls (such as `PAIR-045` diagnostic data) demonstrate client logic flaws, but production security requires backend authorization.

## 7. Resolved: Phase 04 Batch C Scenario Adaptation and Inventory

Phase 04 Batch C resolved the initial scenario conversion and decoupling requirements:

1. **Browser Workload Scenario Adaptation:**
   - The 8 baseline scenarios contained mixed server-side logic (Express server routing, `app.listen()`, server CORS middleware).
   - In Batch C, all 8 scenarios were converted into authentic browser client modules (React admin dashboard, client API gateway router, WebSocket chat client, data pipeline processor, ecommerce checkout flow, browser payment SDK, React student portal, and client auth service).
   - All server listeners and server CORS middleware were removed, while retaining all authentic client-side security weaknesses.
   - Both AST scanner engines parse all 8 scenarios cleanly with zero syntax errors and 100% location and classification agreement.

2. **Decoupled Scenario Expectations and Architecture:**
   - The manifest builder imports canonical scenario definitions from `test-samples/scenario-definitions.cjs`.
   - Raw scanner outputs populate only `observedScannerFindings`.
   - Manifest observation invariance (Test 8) covers all 116 files in `dataset-manifest.json`, proving that changing the observation scanner leaves expected findings, severities, and labels completely invariant.

3. **Preservation of 108 Controlled Files:**
   - All 54 vulnerable and 54 clean benchmark files (108 files) were held byte-identical to starting commit `c650be9`.
   - Hashes are verified against `04-batch-c-controlled-108-hashes.json`.

## 8. Resolved: Post-Commit 38c1562 Scenario Ground Truth Refinements and Threat Models

Manager inspection of commit `38c1562` identified that scenario ground truth copied scanner output patterns rather than verifying exploitability, requiring bounded corrections:

1. **Elimination of Copied Scanner Output and Ground Truth Re-evaluation:**
   - Re-evaluated all 133 raw scanner detections across the 8 scenarios against concrete trust boundaries, attacker control, and exploit prerequisites.
   - 14 non-vulnerability pattern hits were removed from `expectedScannerFindings` (retained in `observedScannerFindings`):
     - Role checks gating only `console.log` (`admin-dashboard.jsx` line 16, `student-portal.jsx` line 30).
     - Non-secret internal IP address constants (`chat-application.js` line 16, `data-pipeline.js` line 19, `payment-processor.js` line 15, `user-auth-service.js` line 17).
     - Public AWS Access Key ID (`AKIA...`) without a secret key (`user-auth-service.js` line 14).
     - Generic `JSON.parse()` syntactic calls without unsafe sinks (`api-gateway.js` line 47, `chat-application.js` lines 48 and 78, `data-pipeline.js` lines 44 and 85, `ecommerce-checkout.js` lines 38 and 69, `payment-processor.js` line 64, `user-auth-service.js` line 70).
     - Logging of non-sensitive configuration objects (`api-gateway.js` line 61).
   - Ground truth expected vulnerabilities across the 8 scenarios were refined from 123 to exactly 105.

2. **Callable Helper Assumptions vs Demonstrated Application Flows:**
   - For functions containing dangerous sinks, we explicitly distinguish whether the flaw is demonstrated in the active component flow or whether it represents a callable helper assumption:
     - In `admin-dashboard.jsx`, `renderLegacyWidget` is invoked in demonstrated JSX flow only with a constant string (`"System Status: Online"`), making that call site fixed-safe; under callable helper assumptions, it represents a critical DOM injection sink. `renderNotification`, `updateSidebar`, and `navigateToPartner` are uninvoked callable helpers.
     - In `student-portal.jsx`, `MessagePreview` and `courseHtml` are active demonstrated flows, while `renderGradeCard` and `loadAnnouncement` are callable helper sinks.

3. **Grounding Advisories in Package Import Registries:**
   - Component review advisories (`OWASP-A06-001`) are grounded strictly in third-party package imports.
   - Seven scenarios import third-party packages, totaling 14 advisories.
   - `user-auth-service.js` contains zero third-party package imports and therefore records 0 advisories.

4. **Severity and Threat Models for Unsupported Browser Weaknesses:**
   - Curated 6 genuine browser weaknesses without scanner rules with explicit `severity`, `severityAssumptions`, `trustBoundary`, `attackerControlledInput`, and `securityImpact`.
   - Removed the uncredited dynamic GET fetch in `admin-dashboard.jsx` because it lacked ambient credentials, exfiltrated no state, and had no concrete security impact.

5. **Reconciliation of Dataset Distribution Terminology:**
   - Updated distribution terminology to refer to the "controlled V/C dataset" rather than a blanket "single-flaw" set.
   - Preserved clear distinctions between sample-level labels and multi-expectation findings (e.g., `V-A8-045.js` has 2 expected findings).

## 9. Resolved: Post-Commit 2afe0ff/e21f77f Ground Truth Corrections and Reconciliation

Manager review of commits `2afe0ff` and `e21f77f` identified remaining unverified assertions and count inconsistencies, which are now resolved:

1. **`chat-application.js` Semantics:**
   - `firebaseApiKey` (line 13): Per official Google Firebase documentation, web API keys are public project identifiers used for routing, not private secrets. Without server-side privilege escalation, this client identifier is not an authenticating credential leak. Omitted from expected findings.
   - Presence and timestamp cookies (lines 62 and 65): Non-sensitive UI state and timestamp telemetry. Client JavaScript cannot set `HttpOnly` per RFC 6265 Section 5.3, and these are not authentication session tokens. Omitted from expected findings.
   - `sessionSalt = Math.random()` (line 68): Merely returned in an object with no demonstrated security-sensitive consumer. Omitted from expected findings.
   - `localStorage.setItem('chatToken', userId)` (line 71): Stores non-sensitive `userId` under key `'chatToken'`. Key name alone does not establish a sensitive bearer credential. Omitted from expected findings.

2. **Fixed String Timers:**
   - Static string literals in `setInterval` and `setTimeout` (such as `checkPipelineHealth()` and `cleanupStaleBatches()`) lack variable interpolation and attacker control. While flagged by scanner rule `OWASP-A03-002` as code smells, they cannot be exploited for arbitrary code injection.
   - Exactly 9 fixed string timers are omitted from expected findings across the 8 scenarios.
   - Exactly 1 dynamic string timer is retained as an expected finding: `api-gateway.js` line 73 (`setTimeout(\`reportHealth('\${serviceId}')\`, 5000)`), because it interpolates user-controlled `serviceId`.

3. **Prototype Assignments with Unused Targets:**
   - Direct assignments to `__proto__` or `constructor.prototype` on locally scoped, newly created empty objects (`defaults = {}`, `schema = {}`, `config = {}`).
   - Under ECMAScript prototype setter semantics (ES6+), assigning `obj.__proto__ = ...` sets the [[Prototype]] of the instance, but does not mutate global `Object.prototype`.
   - Assigning `obj.constructor.prototype = ...` targets non-writable `Object.prototype`, which is a runtime no-op.
   - Furthermore, these target objects are unused local variables that are never queried for property lookups.
   - 8 prototype assignment pattern hits omitted from expected findings: `api-gateway.js` lines 51 and 54, `chat-application.js` lines 82 and 88, `data-pipeline.js` lines 51 and 88, and `payment-processor.js` lines 68 and 74.

4. **Generic Diagnostic Logging:**
   - `console.log` statements logging generic parameters (`session`, `user`, `credentials`, `config`) without demonstrated secret or credential payloads.
   - 9 generic logging pattern hits omitted from expected findings: `api-gateway.js` lines 61 and 62, `chat-application.js` lines 34 and 35, `data-pipeline.js` line 67, `payment-processor.js` lines 77 and 78, and `user-auth-service.js` lines 84 and 85.
   - Legitimate sensitive data logs retained: `ecommerce-checkout.js` line 42 (`paymentToken`), `payment-processor.js` line 33 (`apiKey`), and `user-auth-service.js` line 42 (`password`).

5. **Authoritative Evidence Reconciliation:**
   - Derived directly from code semantics and manifest records:
     - 75 Expected Findings (genuine exploitable browser vulnerabilities)
     - 14 Expected Advisories (`OWASP-A06-001` grounded in third-party package imports)
     - 48 Omitted Pattern Hits (AST heuristic detections without vulnerability context)
     - 6 Unsupported Browser Weaknesses (no scanner rule; explicit threat models)
   - Mathematical Reconciliation: 75 + 14 + 48 = 137 observed scanner detections. Every single issue is fully accounted for.



