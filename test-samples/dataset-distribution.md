# Dataset Distribution Table

Date: September 14, 2026.
Phase: Phase 04 Batch C.
Manifest: `test-samples/dataset-manifest.json` (version 1.0.0).

This document presents the distribution of benchmark sample files across rule modules in JSentinel. The dataset contains 116 files in total. The controlled evaluation set consists of 54 matched pairs (108 files: 54 vulnerable, 54 clean). Eight composite simulated browser application workloads complete the dataset and are evaluated separately from the single-flaw confusion matrix.

## 1. Distribution Inventory Table

| Primary Module | OWASP Top 10 Category | Vulnerable (V) | Clean (C) | Total Files |
| --- | --- | :---: | :---: | :---: |
| `accessControl.js` | A01:2021-Broken Access Control | 6 | 6 | 12 |
| `auth.js` | A07:2021-Identification and Authentication Failures / A02:2021-Cryptographic Failures | 9 | 9 | 18 |
| `deserialization.js` | A08:2021-Software and Data Integrity Failures | 6 | 6 | 12 |
| `injection.js` | A03:2021-Injection | 11 | 11 | 22 |
| `knownVulns.js` | A06:2021-Vulnerable and Outdated Components (Advisory-Only) | 0 | 0 | 0 |
| `misconfig.js` | A05:2021-Security Misconfiguration | 4 | 4 | 8 |
| `sensitiveData.js` | A02:2021-Cryptographic Failures | 11 | 11 | 22 |
| `xss.js` | A03:2021-Injection (Cross-Site Scripting) | 7 | 7 | 14 |
| **Controlled Subtotal** | **54 Pairs Across 7 Active Vulnerability Modules** | **54** | **54** | **108** |
| `Simulated Scenarios` | Composite Multi-Flaw Browser Workloads | - | - | 8 |
| **Grand Total** | **Entire Benchmark Dataset** | **54** | **54** | **116** |

## 2. Notes on Module Classification and Advisory Rules

### Active Advisory Module (`knownVulns.js`)
The scanner engine retains an active rule module, `knownVulns.js`, implementing rule `OWASP-A06-001`. In agreement with Phase 01 architectural decisions, component-review signals for imported packages are classified as informational advisories rather than confirmed security vulnerabilities. Advisories emit informational diagnostics without deducting score points or counting as true positive vulnerability detections.

Because the controlled benchmark evaluates binary vulnerability detection (vulnerable versus clean), `knownVulns.js` contains 0 controlled vulnerability pairs in the confusion matrix. The advisory behavior of `knownVulns.js` is verified through automated test suites in `validation/browser-scope.test.mjs` and `validation/html-overlapping.test.mjs`. In addition, all 8 simulated scenario files import third-party client libraries and define curated `expectedAdvisories` for component review.

### Primary Module Assignment
Every controlled file is assigned to exactly one primary module based on its evaluated vulnerability mechanism. For example, `auth.js` evaluates client session management, credential transport, and token storage across both A07 and A02 categories. Files that remediate server-side headers by moving to browser DOM checks are classified under the module governing their client weakness.

### Simulated Scenarios (Multi-Flaw Workloads)
The 8 simulated scenario files model multi-component browser web applications:
1. `admin-dashboard.jsx`: React dashboard with DOM XSS sinks, client role checks, and open redirects.
2. `api-gateway.js`: Client API routing module with client origin validation and token handling.
3. `chat-application.js`: Browser WebSocket chat client with event markup handling and storage.
4. `data-pipeline.js`: Client batch analytics processor with JSON parsing and web workers.
5. `ecommerce-checkout.js`: Multi-step checkout workflow with synthetic client tokens and DOM insertion.
6. `payment-processor.js`: Browser payment form SDK with token serialization and dynamic script injection.
7. `student-portal.jsx`: React portal with grade rendering, unvalidated links, and role checks.
8. `user-auth-service.js`: Browser authentication client managing password reset flows and tokens.

These 8 files contain multiple flaws per file. They evaluate scanner behavior on realistic composite codebases and are intentionally excluded from the single-flaw controlled confusion matrix.
