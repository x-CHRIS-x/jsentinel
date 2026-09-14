# Phase 04 Batch C Scenario Adaptation and Dataset Manifest Self-Check

Date: September 14, 2026.
Branch: `ao/jsentinel-24/phase04-dataset-pilot`.
Harness: AO worker `jsentinel-24`, Agy with Gemini 3.8 Flash (High).
Manager: Astra coordinator (`jsentinel-4`). Verifier: Opus HOLD.
Base Commit: `c650be9f2b73e2e381fd90342343ca9153abe2e4` (accepted base chain `ca15477`).

## 1. Executive Summary

Phase 04 Batch C completes the dataset curation and manifest construction for the JSentinel benchmark. In this batch:
1. All 54 vulnerable and 54 clean controlled benchmark files (108 files total) were preserved byte-identical to their starting commit state at `c650be9`.
2. The exact 8 simulated application scenario files were reviewed, adapted from artificial server hybrids into authentic client browser workloads, and generated from independent canonical sources.
3. Decoupled ground truth expectations were curated for all 8 scenarios: 123 expected vulnerability findings, 14 expected advisories, and 10 unsupported browser weaknesses.
4. Manifest observation invariance was extended to all 116 dataset files. Replacing the scanner observation provider with empty or noisy outputs leaves expected findings, expected advisories, ground truth, and labels completely invariant.
5. The dataset distribution table was derived from the manifest, reconciling 108 controlled files, 8 scenario files, and 0 controlled pairs for the advisory-only `knownVulns.js` module.

## 2. Controlled Benchmark Preservation (108 Files)

All 108 controlled benchmark files (54 vulnerable and 54 clean pairs) were held strictly constant throughout Batch C:
- Pre-change SHA-256 hashes were recorded in `documents/research-phases/checks/04-batch-c-controlled-108-hashes.json`.
- Verification confirms that all 108 controlled files remain 100% byte-identical to commit `c650be9`.
- The 12 pilot files continue to match their committed pilot hashes with zero drift.

## 3. Adaptation of the 8 Simulated Application Scenarios

The baseline scenarios contained artificial server-side constructs, such as Express server routing, server listeners (`app.listen()`), and server CORS middleware, mixed alongside client DOM properties (`window.location.href`, `document.cookie`). In Batch C, these files were adapted into coherent client-side browser workloads:

| Scenario File | Baseline Limitation | Browser Adaptation (Batch C) | Curated Weaknesses |
| --- | --- | --- | --- |
| `admin-dashboard.jsx` | React component with server CORS references | React single-page admin dashboard managing analytics, notification rendering, and partner links. | Role check bypass, `dangerouslySetInnerHTML`, `innerHTML`, `document.write()`, and open redirects. |
| `api-gateway.js` | Express server listener with client DOM sinks | Client-side API request router managing endpoint dispatching, JWT authorization headers, and token caches. | Regex DoS, hardcoded JWT secrets, insecure localStorage tokens, unvalidated redirect hooks, and arbitrary fetch URLs. |
| `chat-application.js` | Mixed Express server and client WebSocket | Browser WebSocket chat room client managing dynamic channel switching and message transcript rendering. | `innerHTML` transcript injection, unvalidated WebSocket URLs, plaintext cookie storage, dynamic script tags, and `eval()` message unpacking. |
| `data-pipeline.js` | Server-style batch pipeline | Client-side data analytics pipeline with batch worker dispatching and report generation. | Regex DoS, prototype pollution via `Object.assign`, dynamic code execution via `Function()`, and credentialed fetch requests. |
| `ecommerce-checkout.js` | Express routes with client payment sinks | Multi-step client checkout workflow managing cart state, promo codes, and synthetic gateway tokens. | Promo code `eval()`, DOM XSS via `innerHTML`, synthetic Stripe API keys, client price validation bypass, and open redirects. |
| `payment-processor.js` | Server payment endpoint with DOM APIs | Browser payment form SDK with iframe postMessage bridges and customer token serialization. | `postMessage` wildcard origin, plaintext cookie storage, dynamic script tag injection, prototype pollution, and hardcoded payment secrets. |
| `student-portal.jsx` | React portal with mixed server logic | React student portal with enrollment workflows, grade rendering, and advisor link dispatching. | Client role bypass, unvalidated link redirects, `dangerouslySetInnerHTML`, insecure `sessionStorage` grades, and `eval()` grade calculation. |
| `user-auth-service.js` | Express authentication routes | Client authentication client managing login forms, password reset token flows, and OAuth callbacks. | Dynamic redirect callbacks, unhashed password localStorage, timing-vulnerable client comparisons, and arbitrary fetch destinations. |

Both scanner engines (the web scanner and the VS Code extension) parse all 8 adapted scenarios cleanly with zero syntax errors, and achieve 100% location and classification agreement across all findings.

## 4. Generator Synchronization and Architecture

The scenario files are managed through a deterministic generator pipeline:
- Canonical scenario templates, browser contexts, threat models, and expectation records are defined in `test-samples/scenario-definitions.cjs`.
- `test-samples/generate-samples.cjs` imports both controlled pair definitions and scenario definitions, producing all 116 files with Windows CRLF normalization.
- Verification via `node test-samples/generate-samples.cjs --check` confirms 116 matches and 0 mismatches across the entire repository.

## 5. Decoupled Manifest Curation

The manifest builder (`test-samples/build-dataset-manifest.cjs`) derives scenario metadata entirely from explicit curated records:
- **Expected Findings (`expectedScannerFindings`):** 123 distinct expected findings across the 8 scenarios. Each finding includes a canonical rule ID, canonical OWASP 2021 category, severity, exact `{ line, column }` source coordinates, and weakness description.
- **Expected Advisories (`expectedAdvisories`):** 14 component-review advisories for third-party client imports (`axios`, `lodash`, `crypto-js`, `socket.io-client`, `stripe`), classified under `A06:2021-Vulnerable and Outdated Components`.
- **Unsupported Weaknesses (`unsupportedWeaknesses`):** 10 authentic browser weaknesses where no active scanner rule exists (client-side fetch to arbitrary URLs, dynamic script tags, postMessage origin wildcards). These entries explicitly assign `ruleId: null` and `unsupported: true`.
- **Observed Findings (`observedScannerFindings`):** Scanner executions populate observed findings exclusively. Scanner detections or omissions never overwrite ground truth expectations.

## 6. Manifest Observation Invariance Verification

Test 8 in `validation/pilot-manifest.test.mjs` verifies observation invariance across all 116 dataset files:
- When the scanner is replaced with an empty mock scanner (`issues: []`), `expectedScannerFindings`, `expectedAdvisories`, `unsupportedWeaknesses`, `securityGroundTruth`, and `label` remain identical.
- When the scanner is replaced with an altered mock scanner (`issues: [noisyFinding]`), all expected metadata remains identical.
- In both cases, mock scanner outputs appear only in `observedScannerFindings`.

## 7. Dataset Distribution Reconciliation

The final manifest reconciles the complete benchmark distribution:
- 108 controlled benchmark files across 7 active vulnerability modules (54 vulnerable, 54 clean).
- 0 controlled pairs in `knownVulns.js`, reflecting its architectural role as an informational advisory module.
- 8 composite simulated browser scenarios with multi-flaw workloads.
- 116 total files in the benchmark repository.

## 8. Test Execution Summary

| Check / Test Command | Exit Code | Observed Result |
| --- | ---: | --- |
| `node test-samples/generate-samples.cjs --check` | 0 | 116 matches, 0 mismatches out of 116 checked. |
| `node --test validation/pilot-manifest.test.mjs` | 0 | 8 of 8 tests passed (all manifest, hash, VM, and invariance tests). |
| `node --test validation/*.test.mjs validation/*.test.js validation/*.test.cjs` | 0 | 48 of 48 tests passed across the entire project suite. |
| `npm run lint` | 0 | Clean pass; 0 ESLint errors or warnings. |
| `npm --prefix vscode-extension run lint` | 0 | Clean pass; 0 ESLint errors or warnings. |
| `npm run build` | 0 | Clean Vite build in 1.70s; 233 modules transformed. |

## 9. Disclosed Limitations (NOT RUN)

The following procedures were explicitly **NOT RUN** during Phase 04 Batch C:
1. Live browser DOM event execution and layout rendering: Real DOM tree parsing, style computation, and event loop dispatching (such as `onerror` execution) require a live rendering browser and were NOT RUN in this Node.js test environment.
2. Live backend server verification: The test suite runs in a client-side unit test harness. Live backend HTTP server endpoints and server-side RBAC enforcement were NOT RUN.
3. Formal benchmark accuracy scoring: Accuracy calculations, precision, recall, and F1 metrics are reserved for Phase 05 and Phase 07.
4. Thesis chapter edits: No thesis chapters were modified in Phase 04.
5. Remote git push: All commits remain local on branch `ao/jsentinel-24/phase04-dataset-pilot`.
