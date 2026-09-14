# Phase 04 Batch B: Changes and Controlled Dataset Expansion

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
- Scope: Phase 04 Batch B complete. Expanded the remaining 48 pairs (96 controlled files) to complete all 54 V/C controlled pairs (108 files). The 8 simulated browser application scenarios remain byte-identical to baseline hashes, marked pending Batch C. Total dataset contains exactly 116 files.
- Never use stale `main` or edit `main`. All work resides on dedicated branch `ao/jsentinel-24/phase04-dataset-pilot`.

## 2. Inventory and Dataset Structure

The benchmark repository contains exactly 116 files in `test-samples/samples/`:
- 54 Vulnerable benchmark samples (`V-*.js`): 6 pilot files plus 48 newly expanded Batch B files.
- 54 Clean benchmark samples (`C-*.js`): 6 pilot files plus 48 newly expanded Batch B files.
- 8 Simulated browser application scenarios: `admin-dashboard.jsx`, `api-gateway.js`, `chat-application.js`, `data-pipeline.js`, `ecommerce-checkout.js`, `payment-processor.js`, `student-portal.jsx`, `user-auth-service.js`.

### Strict Baseline and Pilot Preservation
1. **12 Pilot Files:** The 6 pilot pairs (`PAIR-007`, `PAIR-009`, `PAIR-023`, `PAIR-027`, `PAIR-039`, `PAIR-049`) are 100% byte-identical to their committed pilot implementations at `8b6cb52`.
2. **8 Scenario Files:** All 8 scenario files are 100% byte-identical to their pre-change baseline hashes recorded in `04-baseline-hashes.json` and `04-baseline-hashes.md`. Their ground truth status remains `pending-batch-c` with `isVulnerable: null`.

## 3. 54 Controlled Pairs and Variation Design

The 54 controlled pairs (108 files) cover OWASP Top 10 client-side categories. Each pair replaces legacy comment-only duplicates with meaningful differences in vulnerability mechanism, input source, sink property, DOM context, or remediation approach:

| Category | Pairs | Primary Focus Areas | Key Mechanism Variations |
| --- | --- | --- | --- |
| A1: Injection | `PAIR-001` to `PAIR-010` (10 pairs) | `eval()`, timer strings, dynamic Function, HTML injection | Direct eval concatenation vs arithmetic formula eval; `setTimeout` vs `setInterval` string evaluation; dynamic Function constructor vs dynamic filter compilation; template literal HTML vs dynamic endpoint function return HTML. |
| A2: Cryptographic & Auth | `PAIR-011` to `PAIR-020` (10 pairs) | Hardcoded keys, storage, cookies, weak random | Hardcoded password literals vs recovery keys; in-memory transient closures vs localStorage; Math.random for session tokens vs CSRF tokens; Math.random vs `crypto.getRandomValues()` vs `crypto.randomUUID()`. |
| A3: Sensitive Data | `PAIR-021` to `PAIR-026` (6 pairs) | API secrets, URL query leaks, payment keys | Synthetic cloud storage keys vs payment gateway secrets; query string password leaks vs password reset tokens; backend proxy routing vs direct client secret embedding. |
| A5: Access Control | `PAIR-027` to `PAIR-030` (4 pairs) | Open redirects, client-side role authorization | `window.location.href` allowlist validation vs `window.location.replace` relative path verification; client role checks vs destructive action permission checks. |
| A6: Misconfiguration | `PAIR-031` to `PAIR-038` (8 pairs) | Console credential logging, postMessage origin, cleartext transports | Logging plaintext passwords vs secret tokens; logging full request objects vs full auth context objects; wildcard postMessage target origin vs exact trusted domain; unencrypted `ws://` telemetry vs cleartext `http://` script loading. |
| A7: DOM XSS | `PAIR-039` to `PAIR-044` (6 pairs) | `innerHTML`, `outerHTML`, `document.write`, React props | Dynamic badge markup vs comment container replacement; `document.write` vs `document.writeln`; raw React post rendering vs section banner rendering; safe `textContent` and `createElement` DOM insertion. |
| A8: Deserialization & Prototypes | `PAIR-045` to `PAIR-050` (6 pairs) | Prototype pollution, deep object merge, JSON handling | Raw `JSON.parse` vs validated schema parsing; direct `__proto__` assignment vs constructor prototype modification; denylist prototype filtering vs strict allowlist property picking. |
| A9: Client Storage & Tokens | `PAIR-051` to `PAIR-052` (2 pairs) | Sensitive token storage, URL hash leakage | Bearer token stored in `sessionStorage` vs transient memory closure; token exposure in `window.location.hash` vs in-memory Authorization request headers. |
| A10: Client Request & Resource Integrity | `PAIR-053` to `PAIR-054` (2 pairs) | Ambient credential requests, unvalidated script injection | Client fetch to arbitrary URLs with ambient credentials vs origin allowlist; dynamic script element injection without integrity checks vs Subresource Integrity (SRI) verified scripts. |

### Reassignment of Retired Server-Only and Advisory Cases
Ten legacy pairs (20 files) originally evaluated server-side Express headers or advisory component imports. These were reassigned to genuine browser-side security weaknesses:
- `PAIR-033` (`V-A6-033.js` / `C-A6-033.js`): Reassigned from server CORS to cross-window `postMessage` with wildcard `*` target origin (CWE-345). Clean counterpart requires explicit target origin domain.
- `PAIR-034` (`V-A6-034.js` / `C-A6-034.js`): Reassigned to inbound message listener executing code without origin validation (CWE-346). Clean counterpart validates `event.origin` against trusted origins.
- `PAIR-035` (`V-A6-035.js` / `C-A6-035.js`): Console logging full request objects containing sensitive headers (CWE-532). Clean counterpart logs non-sensitive `req.path`.
- `PAIR-036` (`V-A6-036.js` / `C-A6-036.js`): Console logging full authentication context objects (CWE-532). Clean counterpart logs non-sensitive numeric status code.
- `PAIR-037` (`V-A6-037.js` / `C-A6-037.js`): Reassigned from Express helmet to unencrypted WebSocket connection `ws://` transmitting telemetry (CWE-319). Clean counterpart enforces `wss://`.
- `PAIR-038` (`V-A6-038.js` / `C-A6-038.js`): Reassigned to external script inclusion over cleartext HTTP `http://` (CWE-319). Clean counterpart enforces HTTPS script source.
- `PAIR-051` (`V-A9-051.js` / `C-A9-051.js`): Reassigned from advisory component import to storing sensitive bearer tokens in `sessionStorage` (CWE-922). Clean counterpart stores transient token in module memory closure.
- `PAIR-052` (`V-A9-052.js` / `C-A9-052.js`): Reassigned to exposing sensitive authentication tokens in `window.location.hash` URL fragment (CWE-598). Clean counterpart transmits token via in-memory Authorization request header.
- `PAIR-053` (`V-A10-053.js` / `C-A10-053.js`): Reassigned from server SSRF to client-side fetch to arbitrary user-supplied URL with ambient credentials (CWE-20). Clean counterpart validates origin against trusted API allowlist.
- `PAIR-054` (`V-A10-054.js` / `C-A10-054.js`): Reassigned to dynamic script element injection pointing to unvalidated user-controlled URL (CWE-829). Clean counterpart loads pre-approved script with Subresource Integrity (SRI) hash verification.

### Cookie Architecture and RFC 6265 Compliance
Per RFC 6265 Section 5.3 Step 10, non-HTTP APIs like `document.cookie` cannot set `HttpOnly` cookies. Browser engines reject or ignore the attribute. The legacy practice of assigning `document.cookie = "...; HttpOnly"` in clean samples was an artificial scanner-evasion artifact.

In Batch B, two distinct clean cookie patterns are implemented:
1. `C-A2-015.js`: Replaces client cookie assignment with server-delegated session creation (`fetch("/api/auth/create-session", { credentials: "same-origin" })`), allowing the server to issue a true `Set-Cookie: ...; Secure; HttpOnly` header.
2. `C-A2-016.js`: Sets a legitimate client-side UI preference cookie using `Secure` and `SameSite=Strict` attributes (`document.cookie = "ui_theme=" + encodeURIComponent(theme) + "; path=/; Secure; SameSite=Strict;"`), correctly omitting `HttpOnly`.

Scanner rule `OWASP-A02-002` evaluates string literals and flags `C-A2-016.js` because it statically requires the substring `httponly`. In accordance with research integrity rules, `C-A2-016.js` retains its true ground truth of `isVulnerable: false` with ideal expected scanner findings of `[]`. The alert is documented as a known scanner false positive in `ambiguityOrKnownLimitations`.

## 4. Implementation Files Changed

| File | Change | Consequence |
| --- | --- | --- |
| `test-samples/samples/` (96 files) | Generated and refreshed 48 controlled pairs with browser mitigations and meaningful variations. | Completes all 54 controlled V/C pairs (108 files) while keeping 12 pilot files and 8 scenarios untouched. |
| `test-samples/generate-samples.cjs` | Expanded generator templates to cover all 54 pairs with Windows CRLF normalization and `--check` CLI flag. | Provides reproducible, deterministic generation of all 108 controlled benchmark files. |
| `test-samples/build-dataset-manifest.cjs` | Created deterministic manifest builder script. | Automates building the full 116-file manifest with verified ground truth, threat models, and scanner observations. |
| `test-samples/dataset-manifest.json` | Updated dataset manifest to cover all 116 files with 108 `controlled-reviewed` entries and 8 `pending-batch-c` entries. | Establishes comprehensive ground truth, threat models, CWEs, and scanner expectations for the controlled benchmark. |
| `validation/pilot-manifest.test.mjs` | Expanded validation suite to test all 108 controlled files, 8 scenario baseline hashes, 12 pilot hashes, Babel AST parsing, and isolated VM sample execution. | Automated verification harness for Batch B dataset integrity. |
| `documents/research-phases/checks/04-batch-b-self-check-2026-09-14.md` | Recorded detailed self-check report for Batch B. | Primary Batch B verification and audit evidence document. |
| `documents/research-phases/checks/04-changes.md` | Updated changes document to record Batch B scope, pairs inventory, and file modifications. | Permanent changes log for Phase 04. |
| `documents/research-phases/checks/04-checklist.md` | Updated Phase 04 checklist with Batch B acceptance criteria status and command results. | Quality and integrity checklist. |
| `documents/research-phases/checks/04-issues.md` | Updated issues document with resolved reassignments, RFC 6265 cookie false positive audit, and reference erratum. | Permanent technical issues and resolutions record. |

## 5. Verification Commands and Exit Codes

| Command Line | Purpose | Exit Code | Observed Result |
| --- | --- | ---: | --- |
| `node test-samples/generate-samples.cjs --check` | Verify generator reproducibility against disk | 0 | Check Mode: 108 matches, 0 mismatches out of 108 checked. |
| `node --test validation/pilot-manifest.test.mjs` | Run Batch B manifest and hash preservation tests | 0 | 5 of 5 tests passed (~806ms). |
| `node --test validation/*.test.mjs validation/*.test.js validation/*.test.cjs` | Run full validation suite across repository | 0 | 45 of 45 tests passed (~4286ms, zero regressions). |
| `npm run lint` | Run ESLint across web project | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm --prefix vscode-extension run lint` | Run ESLint across VS Code extension | 0 | Clean pass; 0 errors, 0 warnings. |
| `npm run build` | Build Vite web application bundle | 0 | Built in 2.07s; 233 modules transformed. |

## 6. Disclosed Unrun Checks (NOT RUN)

In accordance with `AGENTS.md` and research integrity guidelines, the following paths were deliberately **NOT RUN**:
1. Live browser DOM event execution and visual layout rendering: Real DOM Element tree parsing and event loop execution (such as `onerror` event firing) require a live rendering browser engine and are explicitly **NOT RUN** in this Node.js test harness. Asserting string assignment verifies data transport to the DOM sink, not event-handler execution or visual rendering.
2. Formal accuracy measurement or benchmark scoring: **NOT RUN**. Phase 04 establishes the controlled dataset and manifest. Accuracy scoring is reserved for Phase 05 and Phase 07.
3. Phase 05 evaluator execution: **NOT RUN**. Evaluator prototype scripts will run after the entire dataset is frozen.
4. Eight simulated browser scenarios: **NOT RUN** / **NOT MODIFIED**. All 8 scenario files remain byte-identical to baseline hashes and are pending Batch C.
5. Push to remote or branch merge: **NOT RUN**. Work branches remain local in the AO workspace pending manager acceptance.

## 7. Workflow Stopping Point

This completes Phase 04 Batch B. All work stops here for manager review (Astra coordinator) before any scenario migration (Batch C) begins. No evaluator, freeze, accuracy benchmark, Chapter editing, or push was performed.
