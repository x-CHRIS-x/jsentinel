# Project: JSentinel Static Analysis Remediation Guidance Overhaul

## Architecture
JSentinel is a dual-target localized static analysis security scanner for JavaScript/TypeScript web applications:
- **Web Application** (React + Vite + Tailwind CSS): AST traversal in-browser via Babel, displaying interactive vulnerability findings, non-prescriptive 6-part contextual remediation guidance panels, and PDF/JSON export pipelines.
- **VS Code Extension** (VS Code Extension API + AST Traversal): Diagnostic integration, non-destructive rich Markdown Hover cards, webview sidebar dashboard, and Section 7/8 PDF reports.
- **Canonical Guidance Layer**: Dual synchronized catalogs (`src/data/guidanceCatalog.js` ESM and `vscode-extension/src/data/guidanceCatalog.js` CJS) providing educational, structured remediation metadata without automated patches or code replacements.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Canonical Guidance Schema | 10 required fields per record, zero forbidden keys, frozen immutable schema | M1 | PLAN.md §1.1 |
| 2 | Dual Catalog Synchronization | 32 records (27 base + 5 variants) identical across ESM and CJS | M1 | PLAN.md §1.1 |
| 3 | Multi-Scenario Variant Guidance IDs | Dynamic routing for A02-005 (credential / network) and A06-001 (component / headers / request) | M1 | PLAN.md §1.2 |
| 4 | Guidance Integrity Verification | `scripts/verify-guidance.js` checking schema, forbidden keys, sync, and invariants | M1 | PLAN.md §1.4 |
| 5 | Web UI 6-Part Guidance Panel | Clean short action header, 6 structured sections, actual source line evidence | M2 | PLAN.md §2.1 |
| 6 | Web UI Educational Disclaimers | Standard non-prescriptive disclaimer banner in header and findings list | M2 | PLAN.md §2.2 |
| 7 | Zero Patch / Fix Removal (Web) | Elimination of "Copy Fix", "Apply Patch", diff views, and automated replacement | M2 | PLAN.md §2.3 |
| 8 | Extension Diagnostic & Hover Guidance | Rich Markdown hovers with structured guidance; zero QuickFix / CodeLens patch logic | M3 | PLAN.md §3.1 |
| 9 | Extension Sidebar Dashboard | Educational remediation guidance panel in Webview sidebar | M3 | PLAN.md §3.2 |
| 10 | Extension 100% Scan Accuracy | 108 test fixtures and 8 scenario suites passing with 0 FP, 0 FN via `verify-scan.js` | M3 | PLAN.md §3.3 |
| 11 | Web PDF Export Parity | Section 6 rendering structured guidance and illustrative pattern labels | M4 | PLAN.md §4.1 |
| 12 | Extension PDF Export Parity | Section 7/8 rendering structured guidance with illustrative pattern labels | M4 | PLAN.md §4.2 |
| 13 | JSON Export Schema Parity | Non-breaking JSON format with safe short actions and educational disclaimers | M4 | PLAN.md §4.3 |
| 14 | Adversarial & E2E Verification | `tests/adversarial-stress-m1.js`, `test:e2e` (Tiers 1-4), `lint`, `build`, extension build | M5 | PLAN.md §5.1 |
| 15 | Core AST & Thesis Document Integrity | Strict preservation of 27 AST visitors, CVSS weights, and Chapters 1-3 docs | M5 | PLAN.md §5.2 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Canonical Guidance Architecture & Zero-Patch Data Integrity | ESM/CJS catalogs (32 entries), zero forbidden keys, variant mapping, `verify-guidance.js` | none | DONE |
| M2 | Web Application Guidance Modernization | 6-part Guidance Panel, disclaimer banners, source line evidence, removal of patch buttons | M1 | DONE |
| M3 | VS Code Extension Parity & CodeLens Modernization | Hover provider, diagnostics, sidebar webview, 108 fixture scan verification | M1 | DONE |
| M4 | Export Parity (PDF & JSON) | Web/Extension PDF Section 6/7/8 illustrative labels, JSON exporter metadata | M2, M3 | DONE |
| M5 | Full Verification & Acceptance Testing | All test suites (`verify-guidance`, `verify-scan`, `adversarial-stress-m1`, `test:e2e`, lint, build) | M1, M2, M3, M4 | DONE |

## Interface Contracts
### `src/data/guidanceCatalog.js` & `vscode-extension/src/data/guidanceCatalog.js`
- `getGuidance(guidanceIdOrRuleId)` -> returns frozen `RemediationGuidance` object or `null`.
- `validateGuidanceRecord(record)` -> returns boolean validation status.
- `GUIDANCE_CATALOG` -> frozen dictionary of all 32 guidance entries.
- Structure of `RemediationGuidance`:
  - `guidanceId`: string (e.g., `OWASP-A01-001`, `OWASP-A02-005:credential`)
  - `ruleId`: string (e.g., `OWASP-A01-001`)
  - `category`: string
  - `severity`: `'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'`
  - `shortAction`: string
  - `whyReviewThis`: string
  - `recommendedAction`: string
  - `whatJSentinelCannotDetermine`: string
  - `possibleApproaches`: Array<{ title: string, description: string, illustrativeSnippet?: string }>
  - `howToVerify`: Array<string>
  - `educationalDisclaimer`: string
- Forbidden keys: `replacementCode`, `goodSnippet`, `badSnippet`, `deterministic`, `fix`, `applyFix`, `patch`.

### Finding Enrichment Contract
- Every finding object emitted by scanner engines (`src/scanner/` and `vscode-extension/src/scannerEngine.js`) MUST include:
  - `ruleId`: string
  - `guidanceId`: string (e.g., specific variant if applicable)
  - `sourceLine`: string (actual trimmed snippet of source code flagged)
  - `line`: number
  - `column`: number
  - `severity`: string
  - `confidence`: string
  - `message`: string
  - `suggestion`: string (aligned with `shortAction`)

## Code Layout
- Web Application Core: `src/`
  - Rules & Visitors: `src/scanner/rules/`
  - Engine: `src/scanner/index.js`
  - Guidance Catalog (ESM): `src/data/guidanceCatalog.js`
  - UI Components: `src/components/`, `src/App.jsx`
  - Exporters: `src/utils/pdfGenerator.js`, `src/utils/jsonExporter.js`
- VS Code Extension Core: `vscode-extension/src/`
  - Extension Entry: `vscode-extension/src/extension.js`
  - Engine & Rules: `vscode-extension/src/scannerEngine.js`, `vscode-extension/src/rules.js`
  - Guidance Catalog (CJS): `vscode-extension/src/data/guidanceCatalog.js`
  - Providers: `vscode-extension/src/diagnosticsProvider.js`, `vscode-extension/src/hoverProvider.js`, `vscode-extension/src/sidebarProvider.js`
  - Exporter: `vscode-extension/src/utils/pdfGenerator.js`
- Test Suites & Validation:
  - `scripts/verify-guidance.js`
  - `tests/adversarial-stress-m1.js`
  - `tests/e2e/` (Tiers 1-4)
  - `vscode-extension/verify-scan.js`
  - `vscode-extension/tests/`
