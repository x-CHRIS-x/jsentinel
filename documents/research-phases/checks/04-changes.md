# Phase 04 Batch A: Changes and Pilot Review Target

Branch: `ao/jsentinel-24/phase04-dataset-pilot`. Date: September 14, 2026.
Session: AO worker `jsentinel-24`. Model route: Agy with Gemini 3.8 Flash (High).
Manager: Astra coordinator. Independent verifier: Opus HOLD.

## 1. Commit and Branch Reference

- Comparison Base: `ca154776e3896fe4cc6db883b46d9caaf0d23089` (docs(phase03): record manager acceptance).
- Accepted Phase 03 Chain: `caa5e6c`, `1e1ade4`, `8155a82`, `ca15477`.
- Scope: Phase 04 Batch A ONLY (pilot inventory, six V/C pairs, manifest draft, generator synchronization, baseline preservation).
- Never use stale `main` or edit `main`. All work resides on dedicated branch `ao/jsentinel-24/phase04-dataset-pilot`.

## 2. Inventory of the Current Dataset and Generator

The pre-existing dataset in `test-samples/samples/` contains exactly 116 files:
- 54 Vulnerable benchmark samples (`V-*.js`)
- 54 Clean benchmark samples (`C-*.js`)
- 8 Simulated browser application scenarios (`admin-dashboard.jsx`, `api-gateway.js`, `chat-application.js`, `data-pipeline.js`, `ecommerce-checkout.js`, `payment-processor.js`, `student-portal.jsx`, `user-auth-service.js`)

Prior to changes, raw file sizes and SHA-256 baseline hashes for all 116 files were calculated and preserved in `04-baseline-hashes.json` and `04-baseline-hashes.md`.

## 3. Verified Six Pilot Pairs (12 Files)

Six existing corresponding pairs were identified, audited, and synchronized for the pilot:

| Pilot Area | Pair ID | Module | Vulnerable File | Clean File | Weakness / CWE | Scanner Rule |
| --- | --- | --- | --- | --- | --- | --- |
| Browser Redirects | `PAIR-027-REDIRECT` | `accessControl.js` | `V-A5-027.js` | `C-A5-027.js` | CWE-601 Open Redirect | `OWASP-A01-001` |
| Exposed API Secrets | `PAIR-023-API-SECRETS` | `sensitiveData.js` | `V-A3-023.js` | `C-A3-023.js` | CWE-798 Hardcoded Secrets | `OWASP-A02-006` |
| Template HTML | `PAIR-007-TEMPLATE-HTML` | `injection.js` | `V-A1-007.js` | `C-A1-007.js` | CWE-79 DOM XSS | `OWASP-A03-004` |
| Function-Result HTML | `PAIR-009-FUNCTION-RESULT-HTML` | `injection.js` | `V-A1-009.js` | `C-A1-009.js` | CWE-79 DOM XSS | `OWASP-A03-005` |
| General HTML | `PAIR-039-GENERAL-HTML` | `xss.js` | `V-A7-039.js` | `C-A7-039.js` | CWE-79 DOM XSS | `OWASP-A03-006` |
| Object Merge | `PAIR-049-OBJECT-MERGE` | `deserialization.js` | `V-A8-049.js` | `C-A8-049.js` | CWE-1321 Prototype Pollution | `OWASP-A08-003` |

### Code and Variation Improvements
1. `C-A3-023.js` (Exposed API Secrets): The legacy template used `process.env.SECRET_KEY`, which is a server-side pattern that either evaluates to `undefined` in pure browsers or inlines secret strings into the client bundle at build time. The pilot implementation updates `C-A3-023.js` to dispatch operations via an internal backend proxy route (`/api/gateway/dispatch`), truly mitigating credential leakage in client code.
2. `C-A8-049.js` (Object Merge): The legacy clean template invoked an undefined helper `sanitizeInputProperties`. The pilot implementation provides a complete, self-contained property filter stripping `__proto__`, `constructor`, and `prototype`, and merges into a new empty object `{}` rather than mutating the configuration target.
3. `V-A1-009.js` and `C-A1-009.js` (Function-Result HTML): Replaced undefined endpoint helper calls with concrete, executable synchronous functions. `V-A1-009.js` defines `getRawHtmlFromEndpoint(source)` returning dynamic markup with event-handler payload semantics. `C-A1-009.js` defines `getCleanTextFromEndpoint(source)` and assigns to `textContent`. This establishes a documented attacker-controlled return contract rather than assuming any arbitrary function call is vulnerable.
4. The other 8 pilot files (`V-A5-027.js`, `C-A5-027.js`, `V-A3-023.js`, `V-A1-007.js`, `C-A1-007.js`, `V-A7-039.js`, `C-A7-039.js`, `V-A8-049.js`) retain their verified code structures, locations, and synthetic credentials.
5. The remaining 104 files in `test-samples/samples/` are completely unchanged.

## 4. Generator Support Synchronized

`test-samples/generate-samples.cjs` was updated to support pilot mode:
- Added `--pilot` execution flag (and defaults to pilot mode when `--all` is omitted) to regenerate only the 12 pilot files.
- Synchronized templates for A1-05, A3-02, and A8-03 to match the audited pilot implementations.
- Preserves CRLF line endings matching checked-out Windows worktree files.
- Running `node test-samples/generate-samples.cjs --pilot` rewrites only the 12 pilot files and leaves the other 104 files untouched.

## 5. Dataset Manifest Draft

`test-samples/dataset-manifest.json` contains a draft specification covering all 116 files:
- Explicit Partial Coverage: The manifest clearly discloses that 12 files are `pilot-reviewed`, 96 controlled samples are `pending-batch-b`, and 8 scenario samples are `pending-batch-c`.
- Ground Truth Separation: For the 104 unreviewed files, `securityGroundTruth.isVulnerable` is explicitly set to `null` and `expectedScannerFindings` is set to `null`. Legacy classification from filename prefixes is preserved separately under `legacyClassification`. This distinguishes unreviewed status from verified zero findings (`[]`).
- Known Development Exposure: The 104 pending entries record `developmentUse: true` with documented regression exposure rationale, reflecting their historical use in Phase 01 to 03 engine parity harnesses.
- Threat Models and Assumptions: The 12 pilot files define concrete `threatModelAndAssumptions` detailing trust boundaries, attacker-controlled inputs, execution environment, impact supporting severity, and safe partner assumptions.
- Scanner Observations: Expected scanner findings record rule ID, OWASP 2021 category, severity, coordinate locations, and semantic descriptions.
- Metadata per Entry: Stable sample ID, pair ID, primary module, label, intended behavior, development use flag, AI reviewer status (`Agy (Gemini 3.8 Flash High)`), human review status (`PENDING`), and known limitations.

## 6. Implementation Files Changed

| File | Change | Consequence |
| --- | --- | --- |
| `test-samples/samples/C-A3-023.js` | Updated clean implementation to route requests through backend proxy. | Replaces server-only `process.env` with genuine browser mitigation. |
| `test-samples/samples/C-A8-049.js` | Added self-contained prototype property filtering logic. | Truly mitigates prototype pollution when merging configuration objects. |
| `test-samples/samples/V-A1-009.js` | Defined executable synchronous helper `getRawHtmlFromEndpoint(source)`. | Provides concrete attacker-controlled markup contract. |
| `test-samples/samples/C-A1-009.js` | Defined synchronous text helper `getCleanTextFromEndpoint(source)` and assigned to `textContent`. | Implements genuine browser-safe text rendering. |
| `test-samples/generate-samples.cjs` | Synchronized templates for A1, A3, and A8, added `--pilot` mode, normalized CRLF. | Reproduces 12 pilot files without modifying the other 104 files. |
| `test-samples/dataset-manifest.json` | Created complete 116-file manifest draft with unreviewed ground truth separation and pilot threat models. | Establishes ground truth and scanner expectations for Phase 04 pilot. |
| `validation/pilot-manifest.test.mjs` | Updated test suite to execute actual sample files in isolated VM contexts and disclose unrun DOM checks. | Automated regression and runtime verification harness for Phase 04 pilot. |
| `documents/research-phases/checks/04-baseline-hashes.json` | Generated machine-readable inventory of 116 baseline file hashes. | Preserves pre-change state for verification audit. |
| `documents/research-phases/checks/04-baseline-hashes.md` | Generated human-readable baseline inventory table. | Transparent audit trail for dataset preservation. |
| `documents/research-phases/checks/04-changes.md` | Recorded Phase 04 Batch A changes, scope, and stopping point. | Primary change documentation. |
| `documents/research-phases/checks/04-checklist.md` | Recorded Phase 04 criteria checklist and command results. | Quality and integrity checklist. |
| `documents/research-phases/checks/04-issues.md` | Recorded inventory of former A06/server-only reassignments, inventory reconciliation history, and RFC 6265 cookie audit. | Documented known issues and Batch B/C requirements. |
| `documents/research-phases/checks/04-correction-self-check-2026-09-14.md` | Recorded correction self-check for isolated VM sample execution and disclosed unrun DOM checks. | Documents correction rationale and updated evidence claims. |

## 7. Workflow Stopping Point

This completes Phase 04 Batch A. All work stops here for manager review (Astra coordinator) before any full dataset expansion (Batch B) or scenario migration (Batch C) begins. No evaluator, freeze, accuracy benchmark, Chapter editing, or push was performed.
