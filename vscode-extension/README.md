# JSentinel: VS Code Extension

**JSENTINEL: A Client-Side Static Analysis System for Detecting JavaScript Security Vulnerabilities Using an Abstract Syntax Tree (AST) Traversal Algorithm**

A VS Code / Antigravity IDE extension that scans JavaScript and TypeScript files for OWASP Top 10 security vulnerabilities using AST traversal directly in your editor.

## Features

- **Scan Active File**: Run `JSentinel: Scan Active File` from the command palette to scan the currently open file
- **Scan Workspace**: Run `JSentinel: Scan Workspace` to scan all JS/TS files in the workspace
- **Scan on Save**: Automatically scans files when saved (configurable)
- **24 Active Checks**: 23 vulnerability-pattern checks and 1 informational component-review check across 7 OWASP Top 10 (2021) categories in 8 modules
- **Confidence Levels**: Each finding includes HIGH / MEDIUM / LOW confidence rating

## OWASP Categories Covered

| Category | Rules |
|----------|-------|
| A01 - Broken Access Control | Open redirects, client-side role checks |
| A02 - Cryptographic Failures | Hardcoded secrets, weak randomness, sensitive HTTP endpoints |
| A03 - Injection | Dynamic code execution and XSS patterns |
| A05 - Security Misconfiguration | Sensitive console logging, debugger statements |
| A06 - Vulnerable and Outdated Components | Informational import review; no version confirmation |
| A07 - Identification and Authentication Failures | Token storage and insecure cookie patterns |
| A08 - Software and Data Integrity Failures | Deserialization and object-assignment patterns |

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `jsentinel.scanOnSave` | `true` | Automatically scan files on save |
| `jsentinel.scanOnOpen` | `false` | Automatically scan files when opened |
| `jsentinel.severityFilter` | `ALL` | Minimum severity to report (ALL, CRITICAL, HIGH, MEDIUM, LOW) |

## Commands

- `JSentinel: Scan Active File`: Scan the currently open file
- `JSentinel: Scan Workspace`: Scan all JS/TS files in the workspace
- `JSentinel: Clear All Diagnostics`: Clear all JSentinel diagnostics

## How It Works

1. Files are parsed into an Abstract Syntax Tree (AST) using `@babel/parser`
2. 24 active checks traverse the AST using `@babel/traverse`
3. Detected issues are mapped to VS Code Diagnostics (Problems panel + inline underlines)

## Installation (Development)

```bash
cd vscode-extension
npm install
```

Then press `F5` in VS Code to launch the Extension Development Host.

## Credits

Arellano University - Andres Bonifacio Campus Capstone Project: Ledama, Lim, Luchavez, Crispo

New scans carry the `JSentinel browser-scope v2` ruleset identifier. A06 import notices request a version and advisory review; they do not prove a vulnerable dependency and do not affect vulnerability totals or project scores. The project score uses fixed severity deductions and is not a CVSS score. Historical findings retain their original classification; records without a stored version are marked as legacy/version not recorded.
