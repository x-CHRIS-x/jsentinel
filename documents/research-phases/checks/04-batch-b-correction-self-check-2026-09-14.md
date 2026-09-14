# Phase 04 Batch B Correction Self-Check: 2026-09-14

Branch: `ao/jsentinel-24/phase04-dataset-pilot`. Date: September 14, 2026.
Session: AO worker `jsentinel-24`. Model route: Agy with Gemini 3.8 Flash (High).
Manager: Astra coordinator (`jsentinel-4`). Independent verifier: Opus HOLD.

## 1. Context, Scope, and Historical Preservation

Following manager review of the initial Batch B commit (`089b864`) and evidence commit (`79aa08c`), bounded corrections were executed directly on the same branch. All historical commits and evidence are strictly preserved.

- Comparison Base: `ca15477` (Phase 03 manager acceptance).
- Initial Batch B Implementation Commit: `089b864`.
- Initial Batch B Evidence Commit: `79aa08c`.
- Scope: Bounded Phase 04 Batch B corrections addressing manager review findings across samples, generator templates, dataset manifest, and validation tests. No Batch C work, no scanner rule modifications, no Phase 05 evaluator execution, and no remote push.

## 2. Itemized Review Findings and Resolutions

### Finding 1: Unsafe Context for JSON Parsing and Undefined Helpers (PAIR-045, PAIR-046)
- **Problem:** `V-A8-045.js` and `V-A8-046.js` only returned `JSON.parse()`, treating parsing itself as a vulnerability without an unsafe consumption context. In `C-A8-045.js`, `validateSchema` was invoked but undefined.
- **Resolution:**
  - `V-A8-045.js` now demonstrates an explicit authorization violation: parsing untrusted serialized session state and trusting unvalidated properties (`session.isAdmin`) to grant elevated privileges via `enableAdminPrivileges()`.
  - `C-A8-045.js` defines an executable, self-contained `validateSessionSchema(data)` function verifying property types and rejecting client-asserted administrative privileges, returning a safe session object with `role: 'standard_user'`.
  - `V-A8-046.js` demonstrates an unsafe network consumer: parsing untrusted configuration JSON where unvalidated properties control destination endpoint URLs passed directly to `fetch(config.endpointUrl)`.
  - `C-A8-046.js` defines an executable, self-contained `verifyAppConfig(config)` function enforcing a strict endpoint allowlist (`['/api/v1/feed', '/api/v1/profile']`) and falling back to a safe default.

### Finding 2: Auth Cookie Storage vs Theme Preference (PAIR-016)
- **Problem:** In the initial Batch B commit, `C-A2-016.js` was altered from an authentication cookie to a benign UI theme preference.
- **Resolution:**
  - Mitigated the intended authentication token storage vulnerability directly.
  - `V-A2-016.js` stores sensitive bearer authentication tokens directly in `document.cookie` without HttpOnly protection.
  - `C-A2-016.js` implements a secure token exchange contract (`POST /api/auth/token-exchange`), delegating session credential management to the backend server to issue an `HttpOnly; Secure; SameSite` cookie via the `Set-Cookie` response header.
  - Eliminates client-side `document.cookie` assignment in the clean counterpart, resolving both the RFC 6265 browser impossibility and the static scanner false positive.

### Finding 3: Client-Side Access Control Context (PAIR-029)
- **Problem:** `V-A5-029.js` only conditionally rendered an admin UI menu (`showSpecialSuperAdminMenu()`), which represents presentation logic rather than access control over sensitive resources.
- **Resolution:**
  - Updated `V-A5-029.js` to guard an actual privileged action: dispatching a request to `POST /api/v1/users/:id/grant-superuser` based on client-side `userContext.role === 'admin'`.
  - Updated `C-A5-029.js` to enforce authorization on the server API; the client sends the action request with session credentials without performing client-side role authorization.

### Finding 4: Ambient Credentials in Arbitrary Client Fetch (PAIR-053)
- **Problem:** Earlier notes incorrectly implied that client-side `fetch(url, { credentials: 'include' })` leaks the calling site's cookies to arbitrary third-party attacker hosts.
- **Resolution:**
  - Verified browser cookie scoping against WHATWG Fetch Section 4.4 and RFC 6265 Section 5.3.
  - Corrected the threat model: the browser attaches ambient credentials scoped to the *destination* host, not the caller origin.
  - The actual security impact is client-side request forgery (confused deputy): if an attacker supplies a URL targeting internal intranet endpoints (`http://localhost`, `http://192.168.x.x`) or authenticated third-party services, the browser attaches the user's ambient session credentials for that target.
  - `C-A5-053.js` restricts target destinations to an allowlist of approved application API origins.

### Finding 5: Undefined Helpers and Benign Patterns Across Samples
- **Problem:** Review identified undefined helpers (`handleSafeAction`, `triggerSystemPurge`, `validateSchema`) in sample files.
- **Resolution:**
  - Audited all 54 pairs in `test-samples/generate-samples.cjs`.
  - In `C-A6-034.js`, defined `handleSafeAction(action)` self-contained with a dictionary of safe allowed actions (`refresh`, `ping`).
  - In `V-A5-030.js` and `C-A5-030.js`, defined `triggerSystemPurge()` self-contained to dispatch `POST /api/admin/purge`.
  - In `C-A8-045.js`, defined `validateSessionSchema` self-contained.
  - In `C-A8-046.js`, defined `verifyAppConfig` self-contained.
  - All sample functions are now fully defined and executable.

### Finding 6: Crypto Key Entropy in OTP Generator (PAIR-017)
- **Problem:** `C-A2-017.js` generated `otp_key` from a single 32-bit integer, providing inadequate entropy for an authentication secret.
- **Resolution:**
  - Updated `C-A2-017.js` to generate `otp_key` using 256 bits (32 bytes) of cryptographic randomness from `crypto.getRandomValues`, formatted as a 64-character hex string (`secure_<hex>`).
  - Documented threat model assumptions: a 6-digit numeric OTP provides ~20 bits of entropy and requires server-side rate limiting (max 3-5 attempts) and short expiry windows (30-60s) to resist brute-force attacks. The 256-bit `otp_key` provides full collision resistance meeting NIST SP 800-131A standards.

### Finding 7: Manifest Builder Refinements and Pilot Preservation
- **Problem:** The manifest builder regenerated pilot entries from generic templates, overwriting the accepted Batch A pilot metadata.
- **Resolution:**
  - Extracted the exact 12 canonical pilot entries from git commit `92951de` into `test-samples/pilot-manifest-entries.json`.
  - `test-samples/build-dataset-manifest.cjs` preserves those 12 accepted pilot metadata records with 100% fidelity.
  - Updated `developmentUseRationale`: accurately documents that the 12 pilot files were audited in Batch A, the 96 non-pilot controlled files were derived from Phase 01-03 baseline samples and updated in Batch B, and the 8 scenarios were preserved from baseline regression suites pending Batch C.
  - Clean files record `expectedScannerFindings: []` as ideal expectations; observed scanner false positives are documented in `ambiguityOrKnownLimitations`.

### Finding 8: Explicit Partial Coverage Flag
- **Problem:** `manifest.coverageStatus.partialCoverageExplicit` was set to `false`.
- **Resolution:**
  - Set `partialCoverageExplicit: true` because the 8 simulated scenarios remain pending Batch C review.

## 3. Verification Commands and Observed Results

| Command Line | Purpose | Exit Code | Observed Result |
| --- | --- | ---: | --- |
| `node test-samples/generate-samples.cjs --check` | Verify disk samples match generator templates | 0 | Check Mode: 108 matches, 0 mismatches out of 108 checked. |
| `node --test validation/pilot-manifest.test.mjs` | Run manifest, hash, and VM correction tests | 0 | 6 of 6 tests passed (~846ms). |
| `node --test validation/*.test.mjs validation/*.test.js validation/*.test.cjs` | Run full validation suite across repository | 0 | 46 of 46 tests passed (~4565ms, zero regressions). |
| `npm run lint` | Run ESLint across web project | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm --prefix vscode-extension run lint` | Run ESLint across VS Code extension | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm run build` | Build Vite web application bundle | 0 | Built in 1.98s; 233 modules transformed. |

## 4. Disclosed Boundaries and Remaining Ambiguities

1. **Eight Simulated Scenarios Pending Batch C:** The 8 scenario files remain byte-identical to their baseline state and are scheduled for review and migration in Phase 04 Batch C.
2. **Live Browser DOM Execution:** Live DOM Element parsing and event loop execution (such as `onerror` dispatch) require a browser rendering engine and are explicitly **NOT RUN** in this Node.js test harness.
3. **No Scanner Modifications:** Scanner rules were not modified. Honest scanner limitations and misses remain documented in manifest limitation notes.
4. **Accuracy Scoring and Evaluator:** Formal accuracy benchmarking and Phase 05 evaluator prototypes remain **NOT RUN**.
