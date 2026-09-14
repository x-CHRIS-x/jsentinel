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

## 3. Authoritative Web Standards References

Manifest entries, test suites, and documentation cite authoritative, stable web specifications:
- WHATWG HTML Living Standard: Section 8.4 Dynamic markup insertion (`Element.innerHTML`)
- WHATWG DOM Standard: Section 4.2.3 Interface Node attribute `textContent`
- WHATWG Fetch Standard: Section 4.4 HTTP-network-fetch and credentials scoping
- RFC 6265: Section 5.3 Step 10 (Storage Model non-HTTP API rejection)
- NIST SP 800-131A / SP 800-90A: Cryptographic Key Length and Random Number Generation

## 4. Carry-Forward Items

- A03-001 Column-Zero Coordinate Mismatch: Unrelated `eval()` check at column zero reports column `'unknown'` in web scanner vs column `0` in VS Code extension. Inherited from Phase 01/02 and carried forward.
- Scenario Migration (Batch C): The 8 simulated browser application scenarios remain byte-identical to their baseline hashes. They are marked `pending-batch-c` with `isVulnerable: null` and are scheduled for review and migration in Phase 04 Batch C.
