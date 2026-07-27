# Project: JSentinel Smart Scan Rules & UI Clean Up

## Architecture
- `src/scanner/rules/` contains scanning rules implemented as AST visitor objects.
- `vscode-extension/src/scanner/` contains duplicate rules or single exports (we need to see if it links to `src/scanner/rules/` or has its own copies).
- `vscode-extension/src/diagnosticsProvider.js` manages VS Code inline diagnostics generation.

## Code Layout
- `src/scanner/rules/`: browser AST scan rules files.
- `vscode-extension/src/scanner/`: VS Code scan rules files.
- `vscode-extension/src/diagnosticsProvider.js`: diagnostics reporting logic in VS Code.
- `vscode-extension/verify-scan.js`: Verification test harness.

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | Exploration | Exploration and structure investigation | none | DONE |
| 2 | Smart AST Rules | Update rules for SSRF, Open Redirect, Client-side role checks, JSON.parse, Risky Library Imports, and sync them | M1 | DONE |
| 3 | Diagnostics UI Cleanup | Simplify diagnostics message in VS Code | M1 | DONE |
| 4 | Verification | Run verify-scan.js and fix bugs | M2, M3 | DONE (Reviewers: a08aebbe-07a0-46f5-81a0-f678d5bff818, c40d7451-be4a-441d-b1f7-e863dd02e3d4; Challengers: 8220952f-5022-477c-8283-d24da14cc873, d0b7f2c5-add5-47d4-a896-e59425bae0e6; Auditor: 882fa9db-1a68-44eb-a0d1-cbc94210359e) |
