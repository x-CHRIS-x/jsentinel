# Phase 04 Issues and Inventory Notes

Date: September 14, 2026.
Branch: `ao/jsentinel-24/phase04-dataset-pilot`.

## 1. Inventory of Former A06 and Server-Only Reassignments for Batch B

Phase 01 retired server-side checks and established that A06 component-review signals are informational advisories rather than confirmed vulnerabilities. The legacy dataset contains 12 files (6 pairs) that currently fall outside active browser vulnerability detection. These must be reassigned to supported browser vulnerability variations during Phase 04 Batch B:

| Legacy Pair / Files | Legacy Category / Check | Issue in Browser Scope | Batch B Reassignment Need |
| --- | --- | --- | --- |
| `V-A6-033.js` / `C-A6-033.js` | A05-002 CORS wildcard (`res.setHeader`) | Server-side Express header check; retired from active browser scan. | Reassign to active browser weakness (e.g., client storage exposure or postMessage origin validation). |
| `V-A6-034.js` / `C-A6-034.js` | A05-002 CORS wildcard variation 2 | Server-side Express header check; retired from active browser scan. | Reassign to active browser weakness variation. |
| `V-A6-035.js` / `C-A6-035.js` | A06-003 Express request logging (`console.log(req)`) | Server-side Express request logging; retired from active browser scan. | Reassign to active browser weakness (e.g., URL parameter token exposure or DOM storage leakage). |
| `V-A6-036.js` / `C-A6-036.js` | A06-003 Express request logging variation 2 | Server-side Express request logging; retired from active browser scan. | Reassign to active browser weakness variation. |
| `V-A6-037.js` / `C-A6-037.js` | A06-004 Express helmet middleware | Server-side Express middleware check; retired from active browser scan. | Reassign to active browser weakness (e.g., unencrypted HTTP endpoint communication). |
| `V-A6-038.js` / `C-A6-038.js` | A06-004 Express helmet variation 2 | Server-side Express middleware check; retired from active browser scan. | Reassign to active browser weakness variation. |
| `V-A9-051.js` / `C-A9-051.js` | A06-001 Package imports (`serialize-javascript`, `lodash`) | Advisory review signal, not a confirmed vulnerability; excluded from vulnerability matrix. | Reassign controlled pair to active browser vulnerability; retain advisory behavior testing in scenarios or regressions. |
| `V-A9-052.js` / `C-A9-052.js` | A06-001 Package imports variation 2 | Advisory review signal, not a confirmed vulnerability; excluded from vulnerability matrix. | Reassign controlled pair to active browser vulnerability. |
| `V-A10-053.js` / `C-A10-053.js` | A10-001 SSRF (`axios.get(targetUri)`) | Dynamic browser requests are not SSRF; retired from active browser scan. | Reassign to active browser weakness (e.g., additional DOM injection or client access control variation). |
| `V-A10-054.js` / `C-A10-054.js` | A10-001 SSRF variation 2 | Dynamic browser requests are not SSRF; retired from active browser scan. | Reassign to active browser weakness variation. |

Reassigning these 6 pairs (12 files) will ensure that all 54 controlled V/C pairs represent genuine browser vulnerabilities with active detection rules, maintaining the exact 108 controlled sample count and 116 total dataset size.

## 2. Technical Audit of the `document.cookie` / `HttpOnly` Browser Limitation

### The Browser Limitation
According to RFC 6265 (Section 5.3) and MDN Web Docs, the `HttpOnly` flag cannot be set by client-side JavaScript via `document.cookie`. When client-side script executes:
```javascript
document.cookie = "session=" + userId + "; path=/; Secure; HttpOnly;";
```
The browser's cookie parser parses the string, ignores the `HttpOnly` directive, and stores the cookie without HttpOnly protection. The cookie remains readable and writable by any JavaScript executing in the origin, including malicious scripts running under XSS. Only an HTTP response header (`Set-Cookie: ...; HttpOnly`) issued by an HTTP server can establish an HttpOnly cookie.

### Current Scanner Rule Implementation
In both JSentinel scanner implementations (`src/scanner/rules/auth.js` and `vscode-extension/src/scanner/rules.js`), rule `OWASP-A02-002` evaluates string literals and binary expressions assigned to `document.cookie`:
```javascript
if (!cookieVal.includes('httponly') || !cookieVal.includes('secure')) {
  issues.push({ id: "OWASP-A02-002", ... });
}
```
The scanner performs a static substring search. When both `'httponly'` and `'secure'` appear in the string, the scanner suppresses the finding.

### Impact on Benchmark Ground Truth
Legacy sample `C-A2-014.js` (and clean template `A2` id `03`) relies on this suppression by including `; Secure; HttpOnly; SameSite=Strict;` in a `document.cookie` assignment. Statically, the scanner treats this file as clean. However, in reality, the code does not protect the cookie in a browser. Labeling `C-A2-014.js` as a secure remediation is therefore a false claim based on scanner evasion rather than genuine browser security.

### Policy and Next Steps
Per assignment instructions:
1. No scanner rules are altered in this assignment.
2. This limitation is cataloged as a known issue.
3. In Batch B, the benchmark pair must be reviewed: either remediating the clean partner to a defensible client architecture (for example, server-issued session cookies) or scheduling a bounded rule correction and documenting the remaining scanner limitation before benchmark freeze. Under no circumstances should ground truth be distorted to match scanner heuristics.

## 3. Carry-Forward Items

- A03-001 Column-Zero Coordinate Mismatch: Unrelated `eval()` check at column zero reports column `'unknown'` in web scanner vs column `0` in VS Code extension. Inherited from Phase 01/02 and carried forward.
- Partial Manifest Coverage: The manifest draft currently covers 12 pilot files as `pilot-reviewed`. The remaining 104 files are explicitly pending Batch B and Batch C.
