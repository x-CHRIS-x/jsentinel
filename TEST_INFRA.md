# E2E Test Infra: JSentinel Static Analysis Remediation Guidance

## Test Philosophy
- Opaque-box and requirement-driven static analysis validation.
- Zero-tolerance for automated code replacements, patches, or forbidden keys.
- Comprehensive multi-tier test methodology: Feature Coverage (Tier 1), Boundary & Corner Cases (Tier 2), Cross-Feature Combinations (Tier 3), Real-World Application Workloads (Tier 4), and Adversarial Stress Testing (Tier 5 / M1 Stress).

## Feature Inventory & Test Mapping
| # | Feature | Requirement Source | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
|---|---------|-------------------|:------:|:------:|:------:|:------:|
| 1 | Canonical Guidance Schema | PLAN.md §1.1 | 5 | 5 | ✓ | ✓ |
| 2 | Dual Catalog Synchronization | PLAN.md §1.1 | 5 | 5 | ✓ | ✓ |
| 3 | Multi-Scenario Variant Guidance IDs | PLAN.md §1.2 | 5 | 5 | ✓ | ✓ |
| 4 | Guidance Integrity Verification | PLAN.md §1.4 | 5 | 5 | ✓ | ✓ |
| 5 | Web UI 6-Part Guidance Panel | PLAN.md §2.1 | 5 | 5 | ✓ | ✓ |
| 6 | Web UI Educational Disclaimers | PLAN.md §2.2 | 5 | 5 | ✓ | ✓ |
| 7 | Zero Patch / Fix Removal (Web) | PLAN.md §2.3 | 5 | 5 | ✓ | ✓ |
| 8 | Extension Hover Guidance | PLAN.md §3.1 | 5 | 5 | ✓ | ✓ |
| 9 | Extension Sidebar Dashboard | PLAN.md §3.2 | 5 | 5 | ✓ | ✓ |
| 10 | Extension 100% Scan Accuracy (108 fixtures) | PLAN.md §3.3 | 5 | 5 | ✓ | ✓ |
| 11 | Web PDF Export Parity | PLAN.md §4.1 | 5 | 5 | ✓ | ✓ |
| 12 | Extension PDF Export Parity | PLAN.md §4.2 | 5 | 5 | ✓ | ✓ |
| 13 | JSON Export Schema Parity | PLAN.md §4.3 | 5 | 5 | ✓ | ✓ |
| 14 | Adversarial Stress & E2E Suites | PLAN.md §5.1 | 5 | 5 | ✓ | ✓ |
| 15 | Core AST & Thesis Document Integrity | PLAN.md §5.2 | 5 | 5 | ✓ | ✓ |

## Test Architecture
- **Guidance Schema & Catalog Integrity**: `node scripts/verify-guidance.js`
- **Extension Accuracy Test**: `node vscode-extension/verify-scan.js` (108 fixtures across 8 categories)
- **Adversarial Stress Test**: `node tests/adversarial-stress-m1.js`
- **End-to-End Test Suite**: `npm run test:e2e` (Tiers 1–4)
- **Static Analysis & Build**: `npm run lint`, `npm run build`
- **Extension Package / Build**: `npm --prefix vscode-extension run build` or `npm --prefix vscode-extension run compile`

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Full Web App Scan & Guidance Inspection | Scanner -> AST -> Guidance UI -> Disclaimer | High |
| 2 | VS Code Extension Scan & Hover Inspection | Extension Engine -> Hover Provider -> Sidebar | High |
| 3 | Web PDF Export Generation & Structure | PDF Generator -> Guidance Sections -> Pattern Labels | Medium |
| 4 | Extension PDF Export Generation & Structure | Extension PDF Generator -> Findings Table -> Pattern Labels | Medium |
| 5 | JSON Export with Legacy Backward Compatibility | JSON Exporter -> Metadata -> Guidance Keys | Medium |

## Coverage Thresholds
- Tier 1: ≥5 per feature
- Tier 2: ≥5 per feature (where boundaries exist)
- Tier 3: Pairwise coverage of major feature interactions
- Tier 4: ≥5 realistic application scenarios
- Tier 5 (Adversarial): Multi-layer invariant fuzzing and forbidden-key scanning across all source files
