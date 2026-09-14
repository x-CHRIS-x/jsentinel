# Phase 04 Issues and Inventory Notes

Date: September 14, 2026.
Branch: `ao/jsentinel-24/phase04-dataset-pilot`.

## 1. Inventory of Former A06 and Server-Only Reassignments for Batch B

Phase 01 retired server-side checks and established that A06 component-review signals are informational advisories rather than confirmed vulnerabilities. 

### Actual Inventory Reconciliation and Correction History
An initial working draft conflated the count of generator templates with generated variation pairs, stating "6 pairs / 12 files". The actual inventory across the 116 dataset contains 5 retired or advisory templates generating **10 pairs (20 files)** that fall outside browser vulnerability detection:
- Express CORS wildcard: 1 template generating 2 pairs (`PAIR-033`, `PAIR-034`) = 4 files
- Express request logging: 1 template generating 2 pairs (`PAIR-035`, `PAIR-036`) = 4 files
- Express helmet middleware: 1 template generating 2 pairs (`PAIR-037`, `PAIR-038`) = 4 files
- Outdated component imports: 1 advisory template generating 2 pairs (`PAIR-051`, `PAIR-052`) = 4 files
- Dynamic SSRF Axios requests: 1 template generating 2 pairs (`PAIR-053`, `PAIR-054`) = 4 files
- **Total:** 10 pairs (20 files).

The complete inventory of these 10 pairs is detailed below:

| Legacy Pair / Files | Legacy Category / Check | Issue in Browser Scope | Batch B Reassignment Plan |
| --- | --- | --- | --- |
| `V-A6-033.js` / `C-A6-033.js` | A05-002 CORS wildcard (`res.setHeader`) | Server-side Express header check; retired from active browser scan. | Reassign to defensible browser weakness (e.g., client storage exposure or postMessage origin validation). |
| `V-A6-034.js` / `C-A6-034.js` | A05-002 CORS wildcard variation 2 | Server-side Express header check; retired from active browser scan. | Reassign to defensible browser weakness variation. |
| `V-A6-035.js` / `C-A6-035.js` | A06-003 Express request logging (`console.log(req)`) | Server-side Express request logging; retired from active browser scan. | Reassign to defensible browser weakness (e.g., URL parameter token exposure or DOM storage leakage). |
| `V-A6-036.js` / `C-A6-036.js` | A06-003 Express request logging variation 2 | Server-side Express request logging; retired from active browser scan. | Reassign to defensible browser weakness variation. |
| `V-A6-037.js` / `C-A6-037.js` | A06-004 Express helmet middleware | Server-side Express middleware check; retired from active browser scan. | Reassign to defensible browser weakness (e.g., unencrypted HTTP endpoint communication). |
| `V-A6-038.js` / `C-A6-038.js` | A06-004 Express helmet variation 2 | Server-side Express middleware check; retired from active browser scan. | Reassign to defensible browser weakness variation. |
| `V-A9-051.js` / `C-A9-051.js` | A06-001 Package imports (`serialize-javascript`, `lodash`) | Advisory review signal, not a confirmed vulnerability; excluded from vulnerability matrix. | Reassign controlled pair to defensible browser vulnerability; retain advisory behavior testing in scenarios or regressions. |
| `V-A9-052.js` / `C-A9-052.js` | A06-001 Package imports variation 2 | Advisory review signal, not a confirmed vulnerability; excluded from vulnerability matrix. | Reassign controlled pair to defensible browser vulnerability. |
| `V-A10-053.js` / `C-A10-053.js` | A10-001 SSRF (`axios.get(targetUri)`) | Dynamic browser requests are not SSRF; retired from active browser scan. | Reassign to defensible browser weakness (e.g., additional DOM injection or client access control variation). |
| `V-A10-054.js` / `C-A10-054.js` | A10-001 SSRF variation 2 | Dynamic browser requests are not SSRF; retired from active browser scan. | Reassign to defensible browser weakness variation. |

### Ground Truth Integrity Policy
Reassigning these 10 pairs (20 files) replaces server-only operations and advisory-only component checks with defensible browser-side vulnerability patterns. Research benchmark integrity does not require all 54 controlled pairs to have passing active detection in JSentinel. 

Defensible browser weaknesses that JSentinel currently misses (or handles incompletely) must retain their legitimate vulnerability labels, rather than being replaced or altered to manufacture higher scanner coverage or artificial benchmark scores. Any remaining scanner misses will be reported honestly as false negatives during Phase 05 evaluation.

## 2. Technical Audit of the `document.cookie` / `HttpOnly` Browser Limitation

### Verified Source Standards and Browser Behavior
According to RFC 6265 Section 5.3 (Storage Model, Step 10), when a user agent receives a cookie from a non-HTTP API (such as the JavaScript `document.cookie` DOM API) and the `HttpOnly` attribute is present:
> "If the cookie was received from a 'non-HTTP' API and the cookie's http-only-flag is set, abort these steps and ignore the cookie entirely."

MDN Web Docs similarly confirms this restriction:
> "A cookie with the HttpOnly attribute is inaccessible to the JavaScript Document.cookie API; it is only sent to the server... you cannot set the HttpOnly flag from JavaScript."

Whether a specific browser engine strictly aborts and rejects the write per RFC 6265 Step 10 or discards the attribute, client-side JavaScript cannot create a functional, protected HttpOnly cookie. Only an HTTP response header (`Set-Cookie: ...; HttpOnly`) delivered by a server can establish an HttpOnly cookie.

### Current Scanner Rule Implementation
In both JSentinel scanner implementations (`src/scanner/rules/auth.js` and `vscode-extension/src/scanner/rules.js`), rule `OWASP-A02-002` evaluates string literals and binary expressions assigned to `document.cookie`:
```javascript
if (!cookieVal.includes('httponly') || !cookieVal.includes('secure')) {
  issues.push({ id: "OWASP-A02-002", ... });
}
```
The scanner performs a static substring search. When both `'httponly'` and `'secure'` appear in the string, the scanner suppresses the finding.

### Impact on Benchmark Ground Truth
Legacy sample `C-A2-014.js` (and clean template `A2` id `03`) relies on this suppression by including `; Secure; HttpOnly; SameSite=Strict;` in a `document.cookie` assignment. Statically, the scanner treats this file as clean. However, in reality, the code cannot provide HttpOnly protection in a browser. Labeling `C-A2-014.js` as a secure remediation is a false ground truth claim based on scanner evasion rather than genuine security.

### Policy and Next Steps
Per assignment instructions:
1. No scanner rules are altered in this assignment.
2. This limitation is cataloged as a known issue.
3. In Batch B, the benchmark pair must be reviewed: either remediating the clean partner to a defensible client architecture (for example, server-issued session cookies) or scheduling a bounded rule correction and documenting the remaining scanner limitation before benchmark freeze. Under no circumstances should ground truth be distorted to match scanner heuristics.

## 3. Carry-Forward Items

- A03-001 Column-Zero Coordinate Mismatch: Unrelated `eval()` check at column zero reports column `'unknown'` in web scanner vs column `0` in VS Code extension. Inherited from Phase 01/02 and carried forward.
- Partial Manifest Coverage: The manifest draft currently covers 12 pilot files as `pilot-reviewed`. The remaining 104 files are explicitly pending Batch B and Batch C.
