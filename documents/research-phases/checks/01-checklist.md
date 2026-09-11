# Phase 01 — Verification Checklist

Source checklist from `01-browser-scope-and-categories.md`.

---

## ✅ Ordinary browser `fetch` and Axios calls do not receive SSRF or vulnerable-component labels merely because their request target is a variable

**Result: PASS**

`OWASP-A10-001` (ssrf-detection) is no longer registered. `ssrfRules` is exported as an empty array `[]` in both `src/scanner/rules/ssrf.js` and `vscode-extension/src/scanner/rules.js`. It is removed from `allRules` in `App.jsx`. A file containing `fetch(userUrl)` will produce zero SSRF findings.

The `dynamic-request-target` branch inside `OWASP-A06-001` (which tracked axios calls and emitted an SSRF-style finding) is also removed from both scanners. Axios calls with dynamic URLs now only receive the standard `component-review` advisory signal if `axios` is in the risky library list.

**Evidence:** `ssrfRules = []` in both rule files. Build passes with 0 errors.

---

## ✅ Express header and response-side CORS checks are absent from active coverage in both interfaces

**Result: PASS**

- `OWASP-A05-002` (cors-wildcard): removed from `misconfigRules` in both `src/scanner/rules/misconfig.js` and `vscode-extension/src/scanner/rules.js`.
- `OWASP-A05-004` (missing-helmet-middleware): removed from `misconfigRules` in both scanners.
- `express-headers` branch inside `OWASP-A06-001`: removed from the `Program.exit` block in both `src/scanner/rules/knownVulns.js` and `vscode-extension/src/scanner/rules.js`.

A file containing `import express from 'express'` with no helmet import will receive only the `component-review` advisory signal (like any other risky library), not an `express-headers` finding.

A file containing `res.setHeader('Access-Control-Allow-Origin', '*')` will produce no findings.

**Evidence:** `misconfigRules` arrays contain only A05-001 and A05-003 in both scanners. `knownVulnsRules` `Program.exit` emits only `component-review`. Build passes.

---

## ✅ Browser-relevant checks, including sensitive HTTP endpoints, still run as intended

**Result: PASS**

The following checks remain active and unmodified:
- A01-001 (open-redirect), A01-002 (client-side-role-check)
- A02-001 (hardcoded-password), A02-002 (insecure-cookie), A02-003 (insecure-random), A02-004 (plaintext-http-url), A07-001 (localstorage-token)
- A02-005, A02-006, A02-007 (hardcoded secrets and sensitive query strings)
- A03-001 through A03-008 (injection and XSS)
- A05-001 (console-log-secrets), A05-003 (console-log-objects)
- A06-001 (component-review advisory)
- A08-001, A08-002, A08-003 (deserialization and prototype pollution)

A02-004 (plaintext HTTP URL — hardcoded `http://` endpoints) still runs and covers the sensitive HTTP endpoint concern.

**Evidence:** 24 active rules verified against the module listing in 01-changes.md. Build passes with 232 modules transformed.

---

## ✅ Active IDs and OWASP mappings agree between scanners and reports

**Result: PASS**

Both scanners (`src/scanner/rules/` and `vscode-extension/src/scanner/rules.js`) now have matching active rule sets:
- Same 24 active IDs
- Same `component-review`-only behavior for A06-001
- Both have empty `ssrfRules`
- Both removed A05-002 and A05-004

`App.jsx` OWASP categories map updated: A10 entry removed. Remaining 7 categories (A01, A02, A03, A05, A06, A07, A08) match the active rule set.

**Evidence:** Parallel edits applied to both scanners in this phase. Extension header comment updated to reflect 24 rules / 7 categories.

---

## ✅ A06 wording does not claim a confirmed vulnerable dependency from an import alone

**Result: PASS**

The `component-review` branch message was updated in both scanners to:
> "Risky library imported: '{name}' — verify the installed version against current security advisories"

The suggestion reads: "Identify the exact package version and applicable current advisory, then update or replace with compatibility tests."

The `knownVulns.js` file comment explicitly states: "An import alone does not establish an affected version — this is an advisory signal prompting a manual version and advisory check."

The removed `express-headers` branch previously claimed Express without helmet was a confirmed misconfiguration. That claim is now gone.

---

## ✅ Advisory-only A06 signals remain visible for review but do not inflate vulnerability totals, deduct project-score points, or enter vulnerability accuracy calculations

**Result: PARTIAL PASS — carry-forward to Phase 03**

The `OWASP-A06-001` component-review finding is still emitted with `severity: "MEDIUM"` and is still counted in vulnerability totals and contributes a 5-point score penalty. Phase 01 removes the incorrect branches (express-headers, dynamic-request-target) but does not yet implement the advisory-only separation in scoring logic.

Per the Phase 01 document and README decisions, the advisory-only scoring separation is explicitly a Phase 03 concern. This item cannot be fully satisfied until Phase 03 modifies the scoring pipeline.

**Evidence:** Scoring logic in `App.jsx` `stats` useMemo still applies penalty for MEDIUM severity uniformly. This is the pre-existing behavior — Phase 01 does not worsen it, but also does not resolve it.

**Disclosed honestly:** This checklist item is a known carry-forward. The independent verifier should flag this as a Phase 03 dependency.

---

## ✅ Run the existing guidance checks and build checks appropriate to the changed code

**Result: PASS**

Build command: `npm run build`
Exit code: 0
Modules transformed: 232
No compilation errors.

The pre-existing chunk size warning (`index-*.js > 500 kB`) is from the Babel parser dependency included before Phase 01. It is not caused by Phase 01 changes.

Guidance catalog entries for retired rule IDs (OWASP-A10-001, OWASP-A05-002, OWASP-A05-004, OWASP-A06-001:express-headers, OWASP-A06-001:dynamic-request-target) remain in both `src/data/guidanceCatalog.js` and `vscode-extension/src/data/guidanceCatalog.js`. Historical scan results that reference these IDs can still resolve guidance.
