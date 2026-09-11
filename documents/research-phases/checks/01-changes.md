# Phase 01 — Changes

Branch: `work/phase-01-scope`

## Files modified

### `src/scanner/rules/ssrf.js`
**Change:** Replaced the entire active SSRF rule (`OWASP-A10-001`) with an empty export array.
**Reason:** SSRF (Server-Side Request Forgery) requires a server making outbound HTTP requests to internal resources. Browser `fetch()` and `axios.get/post()` are client-side HTTP calls. Flagging them as SSRF produced false positives that mislabeled every dynamic API call as a server-side attack.
**Key diff:** `export const ssrfRules = [];` — rule body replaced with retirement comment block.

---

### `src/scanner/rules/misconfig.js`
**Change:** Removed `OWASP-A05-002` (cors-wildcard) and `OWASP-A05-004` (missing-helmet-middleware) from the `misconfigRules` export array. Retained `OWASP-A05-001` and `OWASP-A05-003`.
**Reason:**
- `OWASP-A05-002` detected `res.setHeader('Access-Control-Allow-Origin', '*')` — an Express server-side response header call. Browsers do not set CORS response headers; only servers do. This check produces false positives for browser code.
- `OWASP-A05-004` detected Express imported without helmet — both are Node.js server packages. Browser JS cannot import or run them.

---

### `src/scanner/rules/knownVulns.js`
**Change:** Removed the `express-headers` branch and the `dynamic-request-target` (axios SSRF tracking) branch from `OWASP-A06-001`'s `Program.exit` block. Retained only the `component-review` branch. Also removed the now-unnecessary `isValidated` helper, `hasHelmet` state, and `axiosCalls` tracking state.
**Reason:**
- `express-headers` branch: checking Express + helmet presence is a server-side concern. Browser JS files cannot import Express meaningfully.
- `dynamic-request-target` branch: this was the same SSRF misclassification as `OWASP-A10-001`, just embedded inside the A06 rule.
**Key diff:** `Program.exit` now iterates `imports` and emits only `guidanceId: "OWASP-A06-001:component-review"` for all entries.

---

### `src/App.jsx`
**Changes:**
1. Removed `import { ssrfRules } from './scanner/rules/ssrf'` — replaced with explanatory comment.
2. Removed `...ssrfRules` from the `allRules` spread in `processFiles`.
3. Removed the `A10` entry from the `owaspCategories` map — no active checks remain in that category.

---

### `vscode-extension/src/scanner/rules.js`
**Changes:**
1. Updated file header comment: rule count changed from 27 to 24 active checks, categories changed from 8 to 7, listed retirements.
2. Removed `OWASP-A05-002` (cors-wildcard) and `OWASP-A05-004` (missing-helmet) from `misconfigRules`.
3. Removed helmet tracking, axiosCalls tracking, `express-headers` branch, and `dynamic-request-target` branch from `knownVulnsRules`. Only component-review remains.
4. Replaced the active `ssrfRules` array with `const ssrfRules = []` and a retirement comment.
5. Added comment to `allRules` spread noting ssrfRules is empty.

---

## Active rule count after Phase 01

| Module | Active IDs | Count |
|---|---|---|
| `accessControl.js` | A01-001, A01-002 | 2 |
| `auth.js` | A02-001, A02-002, A02-003, A02-004, A07-001 | 5 |
| `sensitiveData.js` | A02-005, A02-006, A02-007 | 3 |
| `injection.js` | A03-001, A03-002, A03-003, A03-004, A03-005 | 5 |
| `xss.js` | A03-006, A03-007, A03-008 | 3 |
| `knownVulns.js` | A06-001 (component-review only) | 1 |
| `deserialization.js` | A08-001, A08-002, A08-003 | 3 |
| `misconfig.js` | A05-001, A05-003 | 2 |
| **Total** | | **24** |

Categories with active checks: A01, A02, A03, A05, A06, A07, A08 — **7 categories**.

---

## Build verification

Command: `npm run build`
Result: Exit code 0. 232 modules transformed. No errors.
Chunk size warning is pre-existing (Babel parser bundle size) and unrelated to Phase 01 changes.

---

## Commit hash

To be recorded after `git commit` at end of phase.
