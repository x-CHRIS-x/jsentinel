# Project: JSentinel OWASP Top 10:2021 Migration

## Architecture
JSentinel consists of two primary runtime targets that share AST detection rule semantics:
1. **Web Application (Vite + React)**:
   - `src/scanner/rules/*.js`: 27 standalone rule definition modules (aligned to OWASP 2021).
   - `src/utils/scannerEngine.js`: Web scanning engine aggregating rule visitors.
   - `src/App.jsx`: Web dashboard with category metrics, filters, and remediation guides (`codeFixGuide`).
   - `src/utils/pdfGenerator.js`: Client-side jsPDF report generator with `pdfCodeFixGuide` and category matrix.
   - `src/utils/jsonExporter.js`: JSON audit report exporter.
2. **VS Code Extension (CommonJS)**:
   - `vscode-extension/src/scanner/rules.js`: Bundled dictionary of 27 AST detection rules (aligned to OWASP 2021).
   - `vscode-extension/src/scanner/scannerEngine.js`: Core extension scanner with `assignConfidenceLevels` (aligned).
   - `vscode-extension/src/hoverProvider.js`: Editor hover tooltips with category URLs and risk explanations (aligned).
   - `vscode-extension/src/sidebarProvider.js`: Sidebar webview with categories, risk explanations, and `CODE_FIX_GUIDE` (aligned).
   - `vscode-extension/src/utils/pdfGenerator.js`: Extension PDF exporter mirror (aligned).
   - `vscode-extension/verify-scan.js`: Automated test harness evaluating 54 vulnerable + 54 clean + 8 realistic project samples.

## Code Layout
- `src/scanner/rules/`: Individual web AST rule definitions
- `src/utils/`: Web engine and exporters (`scannerEngine.js`, `pdfGenerator.js`, `jsonExporter.js`)
- `src/App.jsx`: React dashboard UI
- `vscode-extension/src/scanner/`: Extension rules and engine
- `vscode-extension/src/`: Extension providers (`hoverProvider.js`, `sidebarProvider.js`)
- `vscode-extension/src/utils/`: Extension utilities (`pdfGenerator.js`)
- `vscode-extension/verify-scan.js`: Verification test harness

## Feature Inventory
| # | Feature / Rule | Old ID | New ID | New OWASP 2021 Category | Severity | CVSS | Milestone | Status | Source |
|---|----------------|--------|--------|------------------------|----------|------|-----------|--------|--------|
| 1 | open-redirect | OWASP-A5-001 | OWASP-A01-001 | A01:2021-Broken Access Control | HIGH | 7.4 | M1, M2, M3 | DONE | Master Spec |
| 2 | client-side-role-check | OWASP-A5-002 | OWASP-A01-002 | A01:2021-Broken Access Control | MEDIUM | 5.3 | M1, M2, M3 | DONE | Master Spec |
| 3 | hardcoded-password | OWASP-A2-001 | OWASP-A02-001 | A02:2021-Cryptographic Failures | CRITICAL | 9.8 | M1, M2, M3 | DONE | Master Spec |
| 4 | insecure-cookie | OWASP-A2-003 | OWASP-A02-002 | A02:2021-Cryptographic Failures | MEDIUM | 4.2 | M1, M2, M3 | DONE | Master Spec |
| 5 | insecure-random | OWASP-A2-004 | OWASP-A02-003 | A02:2021-Cryptographic Failures | HIGH | 7.5 | M1, M2, M3 | DONE | Master Spec |
| 6 | plaintext-http-url | OWASP-A2-005 | OWASP-A02-004 | A02:2021-Cryptographic Failures | MEDIUM | 5.9 | M1, M2, M3 | DONE | Master Spec |
| 7 | hardcoded-secret-patterns | OWASP-A3-001 | OWASP-A02-005 | A02:2021-Cryptographic Failures | CRITICAL | 9.1 | M1, M2, M3 | DONE | Master Spec |
| 8 | hardcoded-api-key | OWASP-A3-002 | OWASP-A02-006 | A02:2021-Cryptographic Failures | CRITICAL | 9.1 | M1, M2, M3 | DONE | Master Spec |
| 9 | sensitive-query-string | OWASP-A3-003 | OWASP-A02-007 | A02:2021-Cryptographic Failures | MEDIUM | 5.3 | M1, M2, M3 | DONE | Master Spec |
| 10 | eval-detection | OWASP-A1-001 | OWASP-A03-001 | A03:2021-Injection | CRITICAL | 10.0 | M1, M2, M3 | DONE | Master Spec |
| 11 | dynamic-timer | OWASP-A1-002 | OWASP-A03-002 | A03:2021-Injection | HIGH | 8.8 | M1, M2, M3 | DONE | Master Spec |
| 12 | unsafe-function-constructor | OWASP-A1-003 | OWASP-A03-003 | A03:2021-Injection | CRITICAL | 10.0 | M1, M2, M3 | DONE | Master Spec |
| 13 | innerhtml-template-literal | OWASP-A1-004 | OWASP-A03-004 | A03:2021-Injection | HIGH | 8.8 | M1, M2, M3 | DONE | Master Spec |
| 14 | innerhtml-function-call | OWASP-A1-005 | OWASP-A03-005 | A03:2021-Injection | HIGH | 8.8 | M1, M2, M3 | DONE | Master Spec |
| 15 | inner-html-detection | OWASP-A7-001 | OWASP-A03-006 | A03:2021-Injection | HIGH | 8.2 | M1, M2, M3 | DONE | Master Spec |
| 16 | document-write-detection | OWASP-A7-002 | OWASP-A03-007 | A03:2021-Injection | CRITICAL | 9.3 | M1, M2, M3 | DONE | Master Spec |
| 17 | dangerously-set-inner-html | OWASP-A7-003 | OWASP-A03-008 | A03:2021-Injection | HIGH | 8.2 | M1, M2, M3 | DONE | Master Spec |
| 18 | console-log-secrets | OWASP-A6-001 | OWASP-A05-001 | A05:2021-Security Misconfiguration | MEDIUM | 5.5 | M1, M2, M3 | DONE | Master Spec |
| 19 | cors-wildcard | OWASP-A6-002 | OWASP-A05-002 | A05:2021-Security Misconfiguration | MEDIUM | 6.5 | M1, M2, M3 | DONE | Master Spec |
| 20 | console-log-objects | OWASP-A6-003 | OWASP-A05-003 | A05:2021-Security Misconfiguration | MEDIUM | 5.5 | M1, M2, M3 | DONE | Master Spec |
| 21 | missing-helmet-middleware | OWASP-A6-004 | OWASP-A05-004 | A05:2021-Security Misconfiguration | LOW | 3.3 | M1, M2, M3 | DONE | Master Spec |
| 22 | risky-library-import | OWASP-A9-001 | OWASP-A06-001 | A06:2021-Vulnerable and Outdated Components | MEDIUM | 4.8 | M1, M2, M3 | DONE | Master Spec |
| 23 | localstorage-token | OWASP-A2-002 | OWASP-A07-001 | A07:2021-Identification and Authentication Failures | HIGH | 8.2 | M1, M2, M3 | DONE | Master Spec |
| 24 | unsafe-json-parse | OWASP-A8-001 | OWASP-A08-001 | A08:2021-Software and Data Integrity Failures | LOW | 3.7 | M1, M2, M3 | DONE | Master Spec |
| 25 | prototype-pollution | OWASP-A8-002 | OWASP-A08-002 | A08:2021-Software and Data Integrity Failures | HIGH | 7.5 | M1, M2, M3 | DONE | Master Spec |
| 26 | unsafe-object-assign | OWASP-A8-003 | OWASP-A08-003 | A08:2021-Software and Data Integrity Failures | MEDIUM | 5.3 | M1, M2, M3 | DONE | Master Spec |
| 27 | ssrf-detection | OWASP-A10-001 | OWASP-A10-001 | A10:2021-Server-Side Request Forgery (SSRF) | HIGH | 8.6 | M1, M2, M3 | DONE | Master Spec |
| 28 | Web Dashboard Synchronized | - | - | 8 Active OWASP 2021 Categories + codeFixGuide | - | - | M2 | DONE | Master Spec |
| 29 | Report Exporters Synchronized | - | - | PDF & JSON 2021 Categories & Fix Guides | - | - | M2 | DONE | Master Spec |
| 30 | VS Code Hover & Sidebar Synced | - | - | Tooltips, Categories, Explanations, Fix Guides | - | - | M3 | DONE | Master Spec |
| 31 | VS Code PDF Generator Synced | - | - | Buffer PDF Generator 2021 Data Matrix | - | - | M3 | DONE | Master Spec |
| 32 | Zero Regressions & Build Clean | - | - | 108/108 verify-scan.js + npm run build pass | - | - | M4 | DONE | Master Spec |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | AST Detection Rules & Engine Alignment | Update 27 rules in `src/scanner/rules/*.js`, `vscode-extension/src/scanner/rules.js`, and `assignConfidenceLevels` in `vscode-extension/src/scanner/scannerEngine.js` | None | DONE |
| M2 | Web Dashboard & Exporters Synchronization | Update `src/App.jsx` (`codeFixGuide`, categories, filter, denominator), `src/utils/pdfGenerator.js` (`pdfCodeFixGuide`, matrix), and `src/utils/jsonExporter.js` | M1 | DONE |
| M3 | VS Code Extension UI Synchronization | Update `vscode-extension/src/hoverProvider.js`, `vscode-extension/src/sidebarProvider.js`, and `vscode-extension/src/utils/pdfGenerator.js` | M1 | DONE |
| M4 | Comprehensive Verification, Build & Forensic Audit | Run `verify-scan.js`, `npm run build`, adversarial legacy ID check, Reviewer and Forensic Auditor verification | M1, M2, M3 | DONE |

## Interface Contracts
### 8 Active OWASP Top 10:2021 Categories
1. `A01` -> `A01:2021-Broken Access Control` (URL: `https://owasp.org/Top10/A01_2021-Broken_Access_Control/`)
2. `A02` -> `A02:2021-Cryptographic Failures` (URL: `https://owasp.org/Top10/A02_2021-Cryptographic_Failures/`)
3. `A03` -> `A03:2021-Injection` (URL: `https://owasp.org/Top10/A03_2021-Injection/`)
4. `A05` -> `A05:2021-Security Misconfiguration` (URL: `https://owasp.org/Top10/A05_2021-Security_Misconfiguration/`)
5. `A06` -> `A06:2021-Vulnerable and Outdated Components` (URL: `https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/`)
6. `A07` -> `A07:2021-Identification and Authentication Failures` (URL: `https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/`)
7. `A08` -> `A08:2021-Software and Data Integrity Failures` (URL: `https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/`)
8. `A10` -> `A10:2021-Server-Side Request Forgery (SSRF)` (URL: `https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/`)
