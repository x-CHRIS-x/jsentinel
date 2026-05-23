# JSentinel — VS Code Extension

**JSENTINEL: A Client-Side Static Analysis System for Detecting JavaScript Security Vulnerabilities Using an Abstract Syntax Tree (AST) Traversal Algorithm**

A VS Code / Antigravity IDE extension that scans JavaScript and TypeScript files for OWASP Top 10 security vulnerabilities using AST traversal — directly in your editor.

## Features

- **Scan Active File** — Run `JSentinel: Scan Active File` from the command palette to scan the currently open file
- **Scan Workspace** — Run `JSentinel: Scan Workspace` to scan all JS/TS files in the workspace
- **Scan on Save** — Automatically scans files when saved (configurable)
- **27 Detection Rules** — Covers 9 OWASP Top 10 categories with CVSS v3.1 severity scoring
- **Shannon Entropy** — Detects hardcoded secrets through mathematical randomness analysis
- **Confidence Levels** — Each finding includes HIGH / MEDIUM / LOW confidence rating

## OWASP Categories Covered

| Category | Rules |
|----------|-------|
| A1 - Injection | eval(), setTimeout strings, new Function(), innerHTML template/function |
| A2 - Broken Authentication | Hardcoded passwords, localStorage tokens, insecure cookies, Math.random(), HTTP URLs |
| A3 - Sensitive Data Exposure | JWT tokens, AWS keys, API keys, query string secrets |
| A5 - Broken Access Control | Open redirects, client-side role checks |
| A6 - Security Misconfiguration | Console logging secrets, CORS wildcards, missing helmet |
| A7 - Cross-Site Scripting | innerHTML, document.write(), dangerouslySetInnerHTML |
| A8 - Software Integrity | JSON.parse(), prototype pollution, Object.assign() |
| A9 - Vulnerable Components | Known risky library imports |
| A10 - SSRF | Dynamic fetch/axios URLs |

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `jsentinel.scanOnSave` | `true` | Automatically scan files on save |
| `jsentinel.scanOnOpen` | `false` | Automatically scan files when opened |
| `jsentinel.severityFilter` | `ALL` | Minimum severity to report (ALL, CRITICAL, HIGH, MEDIUM, LOW) |

## Commands

- `JSentinel: Scan Active File` — Scan the currently open file
- `JSentinel: Scan Workspace` — Scan all JS/TS files in the workspace
- `JSentinel: Clear All Diagnostics` — Clear all JSentinel diagnostics

## How It Works

1. Files are parsed into an Abstract Syntax Tree (AST) using `@babel/parser`
2. 27 detection rules traverse the AST using `@babel/traverse`
3. Detected issues are mapped to VS Code Diagnostics (Problems panel + inline underlines)
4. Shannon Entropy analysis detects high-randomness strings that may be secrets

## Installation (Development)

```bash
cd vscode-extension
npm install
```

Then press `F5` in VS Code to launch the Extension Development Host.

## Credits

Arellano University Capstone Project — Ledama, Lim, Luchavez, Crispo
