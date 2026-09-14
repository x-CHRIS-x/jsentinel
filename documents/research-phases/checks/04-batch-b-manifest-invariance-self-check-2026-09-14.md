# Phase 04 Batch B: Manifest Observation Invariance and Evidence Accuracy Self-Check

Date: September 14, 2026.
Branch: `ao/jsentinel-24/phase04-dataset-pilot`.
Session: AO worker `jsentinel-24`. Model route: Agy with Gemini 3.8 Flash (High).
Manager: Astra coordinator (`jsentinel-4`). Verifier: Opus HOLD.

## 1. Executive Summary

This self-check records the bounded corrections resolving the manager review findings on commit `fd17002`. The core defect was an architectural circularity in `test-samples/build-dataset-manifest.cjs`, where ground-truth expectations (`expectedScannerFindings`) fell back to raw scanner output (`vScan.issues.map(...)`) whenever scanner detections occurred. Although a separate `observedScannerFindings` field was present, expected findings still depended on runtime scanner output.

The corrections completely decouple benchmark ground-truth expectations from scanner execution. Curated findings for all 108 controlled benchmark files are now derived exclusively from reviewed pair metadata and AST location anchors. Scanner executions populate only `observedScannerFindings`. An automated invariance test confirms that replacing the scanner with empty or noisy mock observations leaves ground-truth expectations, security classifications, and labels completely unchanged.

In addition, sample code comments and threat models for PAIR-029, PAIR-045, and PAIR-046 were corrected to eliminate unfounded claims of live verification and accurately state simulated contracts, CORS preflight semantics, and client-side visibility boundaries.

## 2. Itemized Defect Breakdown and Resolutions

### Defect 1: Elimination of Expected-Output Scanner Dependence

- **Root Cause:** In `build-dataset-manifest.cjs`, lines ~1316-1337 used the condition `meta.trueLocation && vScan.issues.length === 0` for misses, but defaulted to `expectedVFindings = vScan.issues.map(...)` for hits. This made benchmark ground truth dependent on the scanner being evaluated.
- **Resolution:** Removed all scanner-result dependence from `expectedScannerFindings`, `securityGroundTruth`, and `label` construction. In `pairMetadata`, every controlled pair (`001` through `054`) now explicitly defines its complete `expectedFindings` array with canonical rule ID, canonical OWASP category, severity, exact AST coordinates (`line`, `column`), and reviewed weakness description. Clean files uniformly specify `expectedScannerFindings: []`.
- **Scanner Role Decoupling:** Scanner executions (`scanCode`) now populate only `observedScannerFindings`. When evaluating scanners or rebuilding the manifest with altered observation providers, ground-truth benchmark expectations remain strictly invariant.

### Defect 2: Manifest Observation Invariance Test (Test 8)

- **Requirement:** Add an automated test proving that replacing the observation provider with empty or noisy findings alters only `observedScannerFindings`, never expected findings, security ground truth, or labels.
- **Resolution:** Added Test 8 to `validation/pilot-manifest.test.mjs`. The test executes `buildManifest()` with three distinct observation providers:
  1. Default live scanner (`scanCode`).
  2. Mock empty scanner (`() => ({ issues: [] })`).
  3. Mock noisy scanner returning synthetic findings (`id: 'MOCK-INJECTED-RULE-999'`).
- **Observed Verification:** Across all 116 manifest entries, `expectedScannerFindings`, `securityGroundTruth`, and `label` are 100% deep-equal across all three runs. Only `observedScannerFindings` reflects the mock scanner output.

### Defect 3: Telemetry Exfiltration and CORS Preflight Semantics (PAIR-046)

- **Root Cause:** Previous documentation claimed sensitive telemetry could be exfiltrated under simple-request rules. Under the Fetch specification, `application/json` POST requests include a non-simple `Content-Type` and always trigger a CORS preflight (`OPTIONS`) in web browsers. Furthermore, `{ sessionStatus: 'active' }` lacked clear confidentiality sensitivity.
- **Resolution:**
  - `V-A8-046.js`: Replaced benign payload with synthetic sensitive client session credentials: `{ sessionToken: 'token_synthetic_telemetry_user_session_441', activeUser: 'researcher@example.internal', metrics: { activeViews: 4 } }`.
  - Documented that an attacker-controlled endpoint responding with permissive CORS preflight headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Headers`) receives the client telemetry payload. Removed misleading simple-request references.
  - `C-A8-046.js`: Preserves the intended benign telemetry transmission function to approved application endpoints (`/api/v1/feed`, `/api/v1/profile`), while safely rejecting untrusted external destinations with a null-safe fallback.

### Defect 4: Simulated Protected-Resource Contract in PAIR-045

- **Root Cause:** Previous comments treated the diagnostics string literal returned by `accessAdministrativeDiagnostics()` as confidential production data, ignoring that client source code is public to browser users.
- **Resolution:** Updated comments in `V-A8-045.js`, `generate-samples.cjs`, and manifest metadata to explicitly state that the function models a simulated protected-resource contract. Client-side string literals cannot provide production confidentiality; the sample simulates unauthorized elevation of privilege against a client operational contract.

### Defect 5: Assumed Server-Side RBAC Contract in PAIR-029

- **Root Cause:** Previous comments in `C-A5-029.js` claimed security relied on a "verified server authorization contract", but no live backend server was executed or verified in unit scope.
- **Resolution:** Corrected comments in `V-A5-029.js`, `C-A5-029.js`, `generate-samples.cjs`, and manifest threat models. Explicitly stated that client snippets alone do not prove backend configuration. `V-A5-029` assumes missing server RBAC enforcement where client checks are the sole barrier. `C-A5-029` relies on an assumed/simulated server-side RBAC contract with live backend verification explicitly marked NOT RUN.

## 3. Remaining Unresolved Ambiguities and Known Limitations

To maintain research integrity, the following limitations are explicitly recorded rather than claiming unconditional resolution:

1. **Client-Only Scope vs Backend Enforcement:** Static analysis of isolated client-side JavaScript snippets cannot inspect or verify live server-side authorization enforcement. Samples representing client-side authorization weaknesses (`PAIR-029`, `PAIR-030`) necessarily model assumed backend behaviors.
2. **Client-Side Secret Secrecy:** Client-side JavaScript is fully visible to the end user. Samples representing access-control barriers (`PAIR-045`) simulate protected resources in memory; production security requires server-side resource isolation.
3. **Scanner Column-Zero Discrepancy:** In `OWASP-A03-001`, an `eval()` expression starting at column zero reports column `'unknown'` in the web scanner versus column `0` in the VS Code extension. This minor reporting discrepancy is carried forward from Phase 01/02.
4. **Pending Scenario Multi-Flaw Review:** Eight simulated browser scenarios remain marked `pending-batch-c` with `isVulnerable: null`. They are excluded from controlled confusion matrices until Phase 04 Batch C review.

## 4. Verification Commands and Exit Codes

| Command Line | Purpose | Exit Code | Observed Result |
| --- | --- | ---: | --- |
| `node test-samples/generate-samples.cjs --check` | Verify disk samples match generator templates | 0 | Check Mode: 108 matches, 0 mismatches out of 108 checked. |
| `node test-samples/build-dataset-manifest.cjs` | Rebuild dataset manifest from explicit pairMetadata | 0 | Generated 116 files (108 controlled reviewed, 8 scenarios pending). |
| `node --test validation/pilot-manifest.test.mjs` | Run manifest, hash, VM, and invariance tests | 0 | 8 of 8 tests passed (~2783ms). |
| `node --test validation/*.test.mjs validation/*.test.js validation/*.test.cjs` | Run full validation test suite | 0 | 48 of 48 tests passed (~6910ms, zero regressions). |
| `npm run lint` | Run ESLint across web project | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm --prefix vscode-extension run lint` | Run ESLint across extension | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm run build` | Build production Vite bundle | 0 | Built in 2.25s; 233 modules transformed. |

## 5. Preservation Status

- All 12 pilot files match their committed pilot hashes (`8b6cb52`) byte-for-byte.
- All 8 scenario files match their baseline hashes (`04-baseline-hashes.json`) byte-for-byte.
- Invariance test confirms that expected findings and ground-truth labels remain strictly invariant under all observation providers.
