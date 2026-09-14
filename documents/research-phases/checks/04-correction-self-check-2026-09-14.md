# Phase 04 Correction Self-Check: 2026-09-14

## 1. Identity, Scope, and Reference

- Worker and session: AO implementation session `jsentinel-24` (Gemini 3.8 Flash High).
- Working branch: `ao/jsentinel-24/phase04-dataset-pilot`.
- Ancestry on branch from base `ca15477`:
  - `2026e50` (Phase 04 Batch A pilot pairs, manifest draft, and synchronized generator)
  - `fd5e278` (Phase 04 Batch A pilot changes, checklist, issues, and baseline hashes)
  - `20c4f02` (Phase 04 inventory count reconciliation and RFC 6265 audit)
  - `5f50488` (Phase 04 pilot ground truth, threat models, and executable helper contracts)
  - `5414496` (Phase 04 pilot ground truth documentation and evidence)
- Manager: Astra coordinator (`jsentinel-4`). Independent verifier: Opus HOLD.
- Scope: Bounded Phase 04 correction addressing manager review feedback on runtime evidence in `validation/pilot-manifest.test.mjs`.

## 2. Manager Review Rationale and Required Corrections

Manager review identified three bounded issues in the prior runtime test harness:
1. **Duplicated Test Functions:** Test 4 reimplemented redirect, merge, and helper functions in test code instead of loading and executing the actual sample files from `test-samples/samples/`.
2. **Tautological Mock Assertions:** Asserting `mock.content = string` on a plain JavaScript object cannot establish browser `textContent` or HTML rendering behavior.
3. **Unsubstantiated Event Execution Claims:** Prior handoff notes implied markup execution was observed. Asserting `.includes('onerror=')` proves string payload transport to a sink, but does not prove live browser DOM event execution or rendering.

The manager required:
- Replace duplicated implementations with isolated VM execution of the actual sample files.
- Disclose minimal mock contexts (such as mock `window.location`).
- Remove tautological plain-object DOM claims.
- Explicitly disclose live browser DOM execution as NOT RUN.
- Preserve prior evidence through this new correction record and correct handoff claims.

## 3. Implemented Corrections

### Actual Sample Code Execution in Isolated VM
`validation/pilot-manifest.test.mjs` was updated to import `node:vm` and load sample code directly from disk:

1. **Browser Redirects (`V-A5-027.js` vs `C-A5-027.js`):**
   - Loads code directly from `test-samples/samples/V-A5-027.js` and `test-samples/samples/C-A5-027.js`.
   - Runs in isolated VM contexts with a disclosed minimal mock window: `{ window: { location: { href: 'https://app.example.com/initial' } } }`.
   - Invokes `redirectToExternal` loaded from `V-A5-027.js`, verifying it unconditionally sets `window.location.href` to an untrusted external URL (`https://phishing.evil.com/login`).
   - Invokes `redirectToExternalSecure` loaded from `C-A5-027.js`, verifying it rejects non-allowlisted destinations (leaving location unchanged) while accepting allowlisted domains (`https://api.example.com`).

2. **Object Merge and Prototype Pollution (`V-A8-049.js` vs `C-A8-049.js`):**
   - Loads code directly from `test-samples/samples/V-A8-049.js` and `test-samples/samples/C-A8-049.js`.
   - Runs in isolated VM contexts with `{ Object, JSON }`.
   - Passes an attacker payload parsed from JSON containing an own `__proto__` property: `JSON.parse('{"__proto__": {"pollutedPilot": true}}')`.
   - Invokes `mergeConfigurations` loaded from `V-A8-049.js`, verifying that `Object.assign` copies the own `__proto__` property and pollutes the target object prototype (`target.pollutedPilot === true`).
   - Invokes `mergeConfigurationsSecure` loaded from `C-A8-049.js`, verifying that `sanitizeInputProperties` strips `__proto__`, `constructor`, and `prototype`, returning a clean object without mutating the base target or polluting prototypes.

3. **Function-Result Helper and Sink Contracts (`V-A1-009.js` vs `C-A1-009.js`):**
   - Loads code directly from `test-samples/samples/V-A1-009.js` and `test-samples/samples/C-A1-009.js`.
   - Runs in isolated VM contexts.
   - Invokes `getRawHtmlFromEndpoint` and `updateContent` loaded from `V-A1-009.js`, verifying the helper returns the raw markup string and assigns it to the `container.innerHTML` sink property.
   - Invokes `getCleanTextFromEndpoint` and `updateContentSecure` loaded from `C-A1-009.js`, verifying the helper returns a clean text string and assigns it to the `container.textContent` sink property.

### Removal of Tautological Mock Objects
The artificial `textNodeMock.content = string` test block was removed. Setting property values on plain JavaScript objects does not represent DOM text rendering.

### Explicit Boundary for Live Browser DOM Execution
Live browser parsing, DOM Element tree construction, and event handler execution (such as `onerror` firing during resource load failure) require a browser layout and rendering engine. These operations are explicitly NOT RUN in this Node.js test harness. 

Asserting string property assignment verifies data transport to the sink property. Authoritative behavioral security distinction between `innerHTML` (HTML parser execution per HTML Living Standard Section 4.12.1.2) and `textContent` (character data rendering per HTML Living Standard Section 2.5.3) is established through web specifications and AST inspection, not mock objects.

## 4. Corrected Handoff Claims

The prior handoff stated that runtime exploit behavior demonstrations were performed. To avoid misrepresenting evidence:
- Confirmed: Algorithmic redirection checks, prototype property filtering, and sink property assignments were executed directly from sample code in isolated VM contexts.
- Clarified: No live browser markup execution or script firing was observed, as browser rendering engines were not run.

## 5. Verification Commands and Results

| Command | Exit Code | Result Summary |
| --- | --- | --- |
| `node --test validation/pilot-manifest.test.mjs` | 0 | 5 of 5 tests passed (~744ms). |
| `node --test validation/*.test.mjs validation/*.test.js` | 0 | 32 of 32 tests passed (~3868ms, zero regressions). |
| `node test-samples/generate-samples.cjs --pilot` | 0 | Generated 12 pilot files; 104 files untouched. |
| `git status` | 0 | Only test and evidence documentation files modified. |
