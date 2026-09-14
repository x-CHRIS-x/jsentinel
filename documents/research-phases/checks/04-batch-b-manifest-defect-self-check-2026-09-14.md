# Phase 04 Batch B: Manifest Defect Resolution and Structural Integrity Self-Check

Date: September 14, 2026.
Branch: `ao/jsentinel-24/phase04-dataset-pilot`.
Session: AO worker `jsentinel-24`. Model route: Agy with Gemini 3.8 Flash (High).
Manager: Astra coordinator (`jsentinel-4`). Verifier: Opus HOLD.

## 1. Executive Summary

This self-check records the bounded corrections applied to the Phase 04 Batch B dataset and manifest on branch `ao/jsentinel-24/phase04-dataset-pilot`. Following manager review of commit `697ccb4`, specific defects were identified in `test-samples/build-dataset-manifest.cjs`, `test-samples/dataset-manifest.json`, sample definitions, and validation assertions.

The corrections resolve all identified defects without expanding scope beyond Batch B. All 12 pilot files and all 8 simulated browser application scenarios remain strictly preserved byte-for-byte. The total dataset count remains exactly 116 files (54 V, 54 C, 8 scenarios).

## 2. Itemized Defect Breakdown and Resolutions

### Defect 1: Elimination of Borrowed Rule IDs for Unsupported Browser Weaknesses

- **Root Cause:** In the previous manifest builder, when the scanner emitted zero alerts for an unsupported browser weakness, the script fell back to borrowing an active rule from another category. For example, `PAIR-053` (client-side fetch with ambient credentials) borrowed `OWASP-A01-001` (open redirect), and `PAIR-054` (dynamic script inclusion) borrowed `OWASP-A03-006` (innerHTML).
- **Resolution:** Removed all borrowed rule IDs. For browser weaknesses where JSentinel has no active rule in its registry, `ruleId` is set to `null` and `unsupported: true` is explicitly recorded. The weakness description and canonical OWASP category are retained, and the missing scanner rule is documented in `ambiguityOrKnownLimitations`.
- **Affected Pairs:** `PAIR-033` (postMessage wildcard), `PAIR-053` (client fetch credentials), `PAIR-054` (dynamic script inclusion).

### Defect 2: Elimination of Placeholder Coordinates (`line: 1, column: 0`)

- **Root Cause:** When `vScan.issues.length === 0`, the previous builder generated a fallback expected finding with placeholder location `{ line: 1, column: 0 }`. Nine files in the benchmark contained this synthetic placeholder.
- **Resolution:** Audited all 54 pairs and replaced every synthetic placeholder with the true AST coordinates of the weakness construct in the sample file:
  - `V-A2-018.js`: line 8, column 4 (`const nonceVal = ... Math.random() ...`).
  - `V-A6-033.js`: line 8, column 4 (`window.parent.postMessage(...)`).
  - `V-A6-036.js`: line 8, column 4 (`console.error(...)`).
  - `V-A6-037.js`: line 7, column 6 (`const telemetryWsUrl = "ws://..."`).
  - `V-A7-042.js`: line 8, column 4 (`document.writeln(...)`).
  - `V-A9-051.js`: line 8, column 4 (`sessionStorage.setItem(...)`).
  - `V-A9-052.js`: line 8, column 4 (`window.location.hash = ...`).
  - `V-A10-053.js`: line 8, column 11 (`fetch(...)`).
  - `V-A10-054.js`: line 9, column 4 (`script.src = ...`).
- **Audit Verification:** Automated inspection of `test-samples/dataset-manifest.json` confirms exactly 0 occurrences of `{ line: 1, column: 0 }`.

### Defect 3: Resolution of Rule-to-Category Mappings

- **Root Cause:** The manifest builder previously stamped `meta.owasp` across all findings detected in a sample file. This produced invalid mappings when a sample triggered rules from different categories:
  - In `V-A8-045.js`, rule `OWASP-A01-002` (client-side role check) was labeled with category `A08:2021-Software and Data Integrity Failures` instead of `A01:2021-Broken Access Control`.
  - In `V-A6-034.js`, rule `OWASP-A03-001` (eval injection) was labeled with category `A01:2021-Broken Access Control` instead of `A03:2021-Injection`.
- **Resolution:** Introduced a canonical rule registry lookup function `getCanonicalRuleCategory(ruleId)` that derives each rule's OWASP category directly and unambiguously from its rule definition. In `V-A8-045.js`, `OWASP-A08-001` maps to category `A08:2021-Software and Data Integrity Failures` (severity LOW) and `OWASP-A01-002` maps to category `A01:2021-Broken Access Control` (severity MEDIUM). In `V-A6-034.js`, `OWASP-A03-001` maps to `A03:2021-Injection` (severity CRITICAL).
- **Audit Verification:** Automated inspection of `test-samples/dataset-manifest.json` confirms exactly 0 category mismatches across all 116 files.

### Defect 4: Separation of Ideal Ground Truth Expectations from Observed Scanner Output

- **Architecture:** Expected findings represent benchmark ground truth: what a compliant scanner should detect based on the sample weakness. Observed scanner findings represent actual scanner runtime behavior.
- **Resolution:** Manifest entries now maintain both fields independently:
  - `expectedScannerFindings`: Curated ground truth expectations. Clean files have `[]`. Unsupported weaknesses have `ruleId: null` with `unsupported: true`. Supported rules carry their canonical category, severity, and true AST location.
  - `observedScannerFindings`: Raw scanner output from `scanCode()`. Captures scanner misses on unsupported rules and scanner false positives on clean files without modifying ground truth expectations.

### Defect 5: Concrete Security Context in PAIR-029 (Client-Side Role Checks)

- **Finding:** The vulnerable sample made an admin request, while the clean sample made the same request assuming server RBAC, without articulating the backend trust model.
- **Resolution:**
  - `V-A5-029.js`: Comments and manifest explicitly state that the backend endpoint `/api/v1/users/:id/grant-superuser` lacks authorization enforcement. The bypassable client-side check is the sole barrier. Note that client snippets alone do not prove backend configuration; the sample explicitly assumes missing server enforcement.
  - `C-A5-029.js`: Comments and manifest document the explicit architectural assumption that the backend endpoint enforces server-side RBAC on session credentials. Client code dispenses with cosmetic checks. Security relies on the verified server contract.

### Defect 6: Concrete Protected Operation in PAIR-045 (Untrusted Session Deserialization)

- **Finding:** `V-A8-045.js` only set `window.__adminMode = true` without defining what protected operation or data access was affected. `C-A8-045.js` lacked documentation on schema validation scope.
- **Resolution:**
  - `V-A8-045.js`: Added function `accessAdministrativeDiagnostics()`, which returns confidential diagnostic and audit data when `window.__adminMode` is true, and denies access otherwise.
  - `C-A8-045.js`: Documented that schema validation (`validateSessionSchema`) confirms data structure and types, not authorization. Authorization safety is achieved by enforcing `role: 'standard_user'` regardless of client payload properties.

### Defect 7: Concrete Exfiltration Context and Null-Safe Handling in PAIR-046 (JSON Configuration)

- **Finding:** `V-A8-046.js` only returned `fetch(config.endpointUrl)` without security context. In `C-A8-046.js`, `verifyAppConfig(null)` returned `null`, causing `loadAppConfigSecure` to throw a `TypeError: Cannot read properties of null (reading 'endpointUrl')`.
- **Resolution:**
  - `V-A8-046.js`: Defined an explicit security-sensitive telemetry transmission context where an unvalidated endpoint URL permits exfiltration of client telemetry under cross-origin POST or simple-request rules.
  - `C-A8-046.js`: Updated `verifyAppConfig(config)` to return a safe fallback object `{ endpointUrl: '/api/v1/feed' }` whenever `config` is null, undefined, or not an object. Calling `verifyAppConfig(null)` returns the safe default without throwing.

## 3. Structural Integrity Validation

Added Test 7 to `validation/pilot-manifest.test.mjs`:
1. Asserts that every finding in `expectedScannerFindings` with a `ruleId` matches its canonical category from the rule registry.
2. Asserts that every finding has positive line coordinates and never uses `{ line: 1, column: 0 }`.
3. Asserts that unsupported weaknesses declare `ruleId: null` and `unsupported: true`.
4. Asserts that `C-A8-046.js` handles `null`, `undefined`, and primitive inputs safely.
5. Asserts that `V-A8-045.js` unlocks `accessAdministrativeDiagnostics()` when `window.__adminMode` is enabled.

## 4. Verification Commands and Exit Codes

| Command Line | Purpose | Exit Code | Observed Result |
| --- | --- | ---: | --- |
| `node test-samples/generate-samples.cjs --check` | Verify disk samples match generator templates | 0 | Check Mode: 108 matches, 0 mismatches out of 108 checked. |
| `node test-samples/build-dataset-manifest.cjs` | Rebuild dataset manifest | 0 | Generated 116 files (108 controlled reviewed, 8 scenarios pending). |
| `node --test validation/pilot-manifest.test.mjs` | Run manifest, pilot hash, and structural tests | 0 | 7 of 7 tests passed (~795ms). |
| `node --test validation/*.test.mjs validation/*.test.js validation/*.test.cjs` | Run full validation test suite | 0 | 47 of 47 tests passed (~6412ms, zero regressions). |
| `npm run lint` | Run ESLint across web project | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm --prefix vscode-extension run lint` | Run ESLint across extension | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm run build` | Build production bundle | 0 | Built in 2.26s; 233 modules transformed. |

## 5. Pilot and Baseline Preservation

- All 12 pilot files match their committed pilot hashes (`8b6cb52`) byte-for-byte.
- All 8 scenario files match their baseline hashes (`04-baseline-hashes.json`) byte-for-byte.
- Partial coverage explicit flag remains true while scenarios are pending Batch C review.
