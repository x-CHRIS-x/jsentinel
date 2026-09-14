# Phase 04 Batch B Self-Check: 2026-09-14

## 1. Identity, Scope, and Ancestry

- Worker and session: AO implementation session `jsentinel-24` (Gemini 3.8 Flash High).
- Working branch: `ao/jsentinel-24/phase04-dataset-pilot`.
- Ancestry on branch from base `ca15477`:
  - `2026e50` (feat: Phase 04 Batch A pilot pairs, manifest draft, and generator)
  - `fd5e278` (docs: Phase 04 Batch A pilot changes and baseline hashes)
  - `20c4f02` (docs: inventory reconciliation and RFC 6265 audit)
  - `5f50488` (feat: pilot ground truth, threat models, and helper contracts)
  - `5414496` (docs: pilot ground truth refinements and evidence)
  - `8b6cb52` (fix: execute actual sample code in isolated VM and remove tautological DOM claims)
  - `92951de` (docs: record correction self-check for isolated VM execution and disclosed unrun DOM checks)
- Manager: Astra coordinator (`jsentinel-4`). Independent verifier: Opus HOLD.
- Scope: Phase 04 Batch B complete. Fully expanded the remaining 48 pairs (96 controlled files) to complete all 54 V/C controlled pairs (108 files). The 8 simulated browser application scenarios remain byte-identical and marked pending Batch C. Total dataset contains exactly 116 files.

## 2. 54 Controlled Pairs and Meaningful Variation Design

All 54 pairs (108 files) were designed and audited against browser security principles:
- **12 Pilot Files Preserved:** The 6 pilot pairs (`PAIR-007`, `PAIR-009`, `PAIR-023`, `PAIR-027`, `PAIR-039`, `PAIR-049`) match their committed pilot implementations byte-for-byte.
- **8 Scenario Files Preserved:** All 8 scenario files match their pre-change baseline SHA-256 hashes byte-for-byte.
- **Meaningful Variations:** Replaced comment-only duplicates across the remaining 48 pairs with meaningful differences in mechanism, input source, sink property, DOM context, or remediation strategy:
  - Injection (A1): Differentiates direct `eval()` concatenation from formula evaluation (`eval("3 * (" + formula + ")")`), `setTimeout` vs `setInterval` dynamic strings, `new Function` expression compilation vs dynamic filter scripts, and template literal assignments vs function return assignments.
  - Cryptography & Auth (A2): Contrasts hardcoded passwords with recovery keys, transient in-memory closures with persistent web storage, and `crypto.getRandomValues()` with `crypto.randomUUID()`.
  - Sensitive Data (A3): Distinguishes cloud storage credentials from payment gateway secrets, and query string password leaks from password reset token leaks.
  - Access Control (A5): Evaluates `window.location.href` allowlist validation vs `window.location.replace` relative path verification, and client role checks vs destructive action permission flags.
  - Misconfiguration & Logging (A6): Contrasts logging plaintext passwords with logging secret tokens, and logging full request objects with logging authentication context objects.
  - XSS & DOM Injection (A7): Differentiates direct `innerHTML` badge assignment from user comment container replacement, `document.write` from `document.writeln`, and dynamic React post rendering from section banner rendering.
  - Integrity & Prototypes (A8): Contrasts raw `JSON.parse` with property type validation, direct `__proto__` property modification with constructor prototype modification, and denylist prototype filtering with strict allowlist property picking.

### Reassignment of Retired Server-Only and Advisory Cases
The 10 retired/advisory pairs (20 files) identified in earlier audits were cleanly reassigned to defensible browser-side weaknesses:
- `PAIR-033` (`V-A6-033.js` / `C-A6-033.js`): Reassigned from Express CORS wildcard to cross-window `postMessage` with wildcard `*` target origin (CWE-345 / OWASP A01). Clean counterpart enforces exact trusted target origin domain.
- `PAIR-034` (`V-A6-034.js` / `C-A6-034.js`): Reassigned to inbound message listener executing code without origin validation (CWE-346 / OWASP A01/A03). Clean counterpart verifies `event.origin` against trusted origins.
- `PAIR-035` (`V-A6-035.js` / `C-A6-035.js`): Console logging full request objects containing sensitive headers (CWE-532 / OWASP A05). Clean counterpart logs non-sensitive `req.path`.
- `PAIR-036` (`V-A6-036.js` / `C-A6-036.js`): Console logging full authentication context objects (CWE-532 / OWASP A05). Clean counterpart logs non-sensitive numeric status code.
- `PAIR-037` (`V-A6-037.js` / `C-A6-037.js`): Reassigned from Express helmet to unencrypted WebSocket connection `ws://` transmitting telemetry (CWE-319 / OWASP A02). Clean counterpart enforces `wss://`.
- `PAIR-038` (`V-A6-038.js` / `C-A6-038.js`): Reassigned to external script inclusion over cleartext HTTP `http://` (CWE-319 / OWASP A02). Clean counterpart enforces HTTPS script source.
- `PAIR-051` (`V-A9-051.js` / `C-A9-051.js`): Reassigned from advisory component import to storing sensitive bearer tokens in `sessionStorage` (CWE-922 / OWASP A07). Clean counterpart stores transient token in module memory closure.
- `PAIR-052` (`V-A9-052.js` / `C-A9-052.js`): Reassigned to exposing sensitive authentication tokens in `window.location.hash` URL fragment (CWE-598 / OWASP A02). Clean counterpart transmits token via in-memory Authorization request header.
- `PAIR-053` (`V-A10-053.js` / `C-A10-053.js`): Reassigned from server SSRF to client-side fetch to arbitrary user-supplied URL with ambient credentials (CWE-20 / OWASP A01). Clean counterpart validates origin against trusted API allowlist.
- `PAIR-054` (`V-A10-054.js` / `C-A10-054.js`): Reassigned to dynamic script element injection pointing to unvalidated user-controlled URL (CWE-829 / OWASP A03). Clean counterpart loads pre-approved script with Subresource Integrity (SRI) hash verification.

## 3. Cookie Architecture and False Positive Audit

### RFC 6265 Compliance
In accordance with RFC 6265 Section 5.3 (Storage Model, Step 10), non-HTTP APIs like `document.cookie` cannot set `HttpOnly` cookies; user agents abort and ignore the write. The legacy practice of assigning `document.cookie = "...; HttpOnly"` in clean samples was an artificial scanner-evasion artifact rather than genuine protection.

### Implemented Clean Cookie Remediations
1. `C-A2-015.js`: Replaced client cookie assignment with server-delegated session creation (`fetch("/api/auth/create-session", { credentials: "same-origin" })`), allowing the server to issue a true `Set-Cookie: ...; Secure; HttpOnly` header.
2. `C-A2-016.js`: Sets a legitimate client-side UI preference cookie using `Secure` and `SameSite=Strict` attributes (`document.cookie = "ui_theme=" + encodeURIComponent(theme) + "; path=/; Secure; SameSite=Strict;"`), correctly omitting `HttpOnly`.

### Documented Scanner False Positive
In `C-A2-016.js`, scanner rule `OWASP-A02-002` triggers because it naively demands the substring `httponly` in all `document.cookie` assignments. In the dataset manifest, `C-A2-016.js` retains its true ground truth of `isVulnerable: false` with ideal expected scanner findings of `[]`. The alert is documented as a known scanner false positive in `ambiguityOrKnownLimitations`.

## 4. Erratum on Pilot HTML References

Earlier working notes referenced draft section numbers (such as Section 4.12.1.2 for innerHTML or Section 2.5.3 for textContent). The dataset manifest and validation suites have been corrected to cite authoritative, stable web standards:
- WHATWG HTML Living Standard: Section 8.4 Dynamic markup insertion (`Element.innerHTML`)
- WHATWG DOM Standard: Section 4.2.3 Interface Node attribute `textContent`
- MDN Web Docs: `Element.innerHTML`, `Node.textContent`, `Document.cookie`, `Window.postMessage`
- RFC 6265: Section 5.3 Step 10 (Storage Model non-HTTP API rejection)

## 5. Generator and Manifest Implementation

1. **Generator (`test-samples/generate-samples.cjs`):**
   - Implements self-contained templates for all 54 pairs directly in source code.
   - Generates deterministic CRLF line endings on Windows.
   - Supports `--pilot` (12 files), `--check` / `--dry-run`, `--output <dir>`, and full controlled regeneration (108 files).
   - Leaves all 8 scenario files untouched.

2. **Dataset Manifest (`test-samples/dataset-manifest.json`):**
   - Full Batch B schema covering all 116 files.
   - 108 controlled files marked `controlled-reviewed` (or `pilot-reviewed`).
   - Every controlled file includes concrete `threatModelAndAssumptions` (trust boundary, attacker input, execution environment, impact, safe partner assumptions).
   - 8 scenario files preserved with `pending-batch-c` coverage status and `isVulnerable: null`.

## 6. Verification Commands and Exit Codes

| Command Line | Purpose | Exit Code | Observed Result |
| --- | --- | ---: | --- |
| `node test-samples/generate-samples.cjs --check` | Verify generator reproducibility against disk | 0 | Check Mode: 108 matches, 0 mismatches out of 108 checked. |
| `node --test validation/pilot-manifest.test.mjs` | Run Batch B manifest and hash preservation tests | 0 | 5 of 5 tests passed (~806ms). |
| `node --test validation/*.test.mjs validation/*.test.js validation/*.test.cjs` | Run full validation suite across repository | 0 | 45 of 45 tests passed (~4286ms, zero regressions). |
| `npm run lint` | Run ESLint across web project | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm --prefix vscode-extension run lint` | Run ESLint across VS Code extension | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm run build` | Build Vite web application bundle | 0 | Built in 2.07s; 233 modules transformed. |

## 7. Disclosed Boundaries and Limitations

1. **Live Browser DOM Execution:** Real DOM Element tree parsing and event loop execution (such as `onerror` firing) require a live rendering browser engine and are explicitly **NOT RUN** in this Node.js test harness.
2. **Eight Scenarios Pending Batch C:** The 8 simulated browser application scenarios remain byte-identical to their baseline state and are explicitly reserved for Phase 04 Batch C.
3. **No Scanner Modifications:** No scanner rules were altered in this batch. All scanner limitations, false positives, and defensible misses remain documented honestly in the manifest.
4. **Stopping Point:** All work stops at this boundary for manager review before proceeding to Phase 04 Batch C.
