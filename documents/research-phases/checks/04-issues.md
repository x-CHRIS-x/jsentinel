# Phase 04 Issues and Inventory Notes

Date: September 14, 2026.
Branch: `ao/jsentinel-24/phase04-dataset-pilot`.
Manager: Astra coordinator (`jsentinel-4`). Independent verifier: Opus HOLD.

## 1. Resolved: Reassignment of Former A06 and Server-Only Cases in Batch B

Phase 01 retired server-side checks and established that A06 component-review signals are informational advisories rather than confirmed vulnerabilities. In Batch B, all 10 legacy pairs (20 files) that originally covered server-side headers or advisory imports were cleanly reassigned to defensible client-side browser weaknesses.

### Inventory and Implemented Reassignments

The 10 pairs (20 files) were reassigned as follows:

| Pair ID | Sample Files | Previous Legacy Check | Resolved Browser Weakness (Batch B) | CWE / OWASP Category |
| --- | --- | --- | --- | --- |
| `PAIR-033` | `V-A6-033.js` / `C-A6-033.js` | Express CORS wildcard (`res.setHeader`) | Cross-window `postMessage` with wildcard `*` target origin. Clean counterpart requires explicit target origin domain. | CWE-345 / OWASP A01 |
| `PAIR-034` | `V-A6-034.js` / `C-A6-034.js` | Express CORS wildcard variation 2 | Inbound message listener executing commands without origin validation. Clean counterpart validates `event.origin`. | CWE-346 / OWASP A01/A03 |
| `PAIR-035` | `V-A6-035.js` / `C-A6-035.js` | Express request logging (`console.log(req)`) | Console logging full request objects containing sensitive headers. Clean counterpart logs non-sensitive `req.path`. | CWE-532 / OWASP A05 |
| `PAIR-036` | `V-A6-036.js` / `C-A6-036.js` | Express request logging variation 2 | Console logging full authentication context objects. Clean counterpart logs non-sensitive numeric status code. | CWE-532 / OWASP A05 |
| `PAIR-037` | `V-A6-037.js` / `C-A6-037.js` | Express helmet middleware check | Unencrypted WebSocket connection `ws://` transmitting telemetry. Clean counterpart enforces `wss://`. | CWE-319 / OWASP A02 |
| `PAIR-038` | `V-A6-038.js` / `C-A6-038.js` | Express helmet variation 2 | External script inclusion over cleartext HTTP `http://`. Clean counterpart enforces HTTPS script source. | CWE-319 / OWASP A02 |
| `PAIR-051` | `V-A9-051.js` / `C-A9-051.js` | Advisory package imports (`serialize-javascript`) | Storing sensitive bearer authentication tokens in `sessionStorage`. Clean counterpart stores transient token in module memory closure. | CWE-922 / OWASP A07 |
| `PAIR-052` | `V-A9-052.js` / `C-A9-052.js` | Advisory package imports (`lodash`) | Exposing sensitive authentication tokens in `window.location.hash` URL fragment. Clean counterpart transmits token via in-memory Authorization request header. | CWE-598 / OWASP A02 |
| `PAIR-053` | `V-A10-053.js` / `C-A10-053.js` | Server SSRF (`axios.get(targetUri)`) | Client-side fetch to arbitrary user-supplied URL with ambient credentials. Clean counterpart validates origin against trusted API allowlist. | CWE-20 / OWASP A01 |
| `PAIR-054` | `V-A10-054.js` / `C-A10-054.js` | Server SSRF variation 2 | Dynamic script element injection pointing to unvalidated user-controlled URL. Clean counterpart loads pre-approved script with Subresource Integrity (SRI) hash verification. | CWE-829 / OWASP A03 |

### Ground Truth Integrity Policy
Reassigning these 10 pairs (20 files) replaces server-only operations and advisory-only component checks with defensible browser-side vulnerability patterns. Research benchmark integrity does not require all 54 controlled pairs to have passing active detection in JSentinel.

Defensible browser weaknesses that JSentinel currently misses retain their legitimate vulnerability labels, rather than being altered to manufacture artificial scanner coverage. Scanner misses will be reported transparently as false negatives during Phase 05 evaluation.

## 2. Technical Audit of the `document.cookie` / `HttpOnly` Browser Limitation

### Verified Source Standards and Browser Behavior
According to RFC 6265 Section 5.3 (Storage Model, Step 10), when a user agent receives a cookie from a non-HTTP API (such as the JavaScript `document.cookie` DOM API) and the `HttpOnly` attribute is present:
> "If the cookie was received from a 'non-HTTP' API and the cookie's http-only-flag is set, abort these steps and ignore the cookie entirely."

MDN Web Docs confirms this restriction:
> "A cookie with the HttpOnly attribute is inaccessible to the JavaScript Document.cookie API; it is only sent to the server... you cannot set the HttpOnly flag from JavaScript."

Client-side JavaScript cannot create a functional, protected HttpOnly cookie. Only an HTTP response header (`Set-Cookie: ...; HttpOnly`) delivered by a server can establish an HttpOnly cookie.

### Current Scanner Rule Implementation
In both JSentinel scanner implementations (`src/scanner/rules/auth.js` and `vscode-extension/src/scanner/rules.js`), rule `OWASP-A02-002` evaluates string literals and binary expressions assigned to `document.cookie`:
```javascript
if (!cookieVal.includes('httponly') || !cookieVal.includes('secure')) {
  issues.push({ id: "OWASP-A02-002", ... });
}
```
The scanner performs a static substring search. When both `'httponly'` and `'secure'` appear in the string, the scanner suppresses the finding.

### Batch B Remediations and False Positive Handling
In Batch B, two distinct clean cookie patterns were implemented:
1. `C-A2-015.js`: Replaced client-side cookie assignment with server-delegated session creation (`fetch("/api/auth/create-session", { credentials: "same-origin" })`). The server issues a true `Set-Cookie: ...; Secure; HttpOnly` response header.
2. `C-A2-016.js`: Sets a legitimate client-side UI preference cookie using `Secure` and `SameSite=Strict` attributes (`document.cookie = "ui_theme=" + encodeURIComponent(theme) + "; path=/; Secure; SameSite=Strict;"`), correctly omitting `HttpOnly`.

Because scanner rule `OWASP-A02-002` demands the substring `httponly`, it flags `C-A2-016.js`. In accordance with integrity rules:
1. No scanner rules were altered in this batch.
2. `C-A2-016.js` retains its true ground truth of `isVulnerable: false` with ideal expected scanner findings of `[]`.
3. The finding is documented in the manifest under `ambiguityOrKnownLimitations` as a known scanner false positive.

## 3. Erratum on Authoritative Web Standards References

Earlier working notes cited preliminary draft section numbers for DOM insertion and node interfaces. Manifest entries, test suites, and documentation have been corrected to reference authoritative, stable specifications:
- WHATWG HTML Living Standard: Section 8.4 Dynamic markup insertion (`Element.innerHTML`)
- WHATWG DOM Standard: Section 4.2.3 Interface Node attribute `textContent`
- MDN Web Docs: `Element.innerHTML`, `Node.textContent`, `Document.cookie`, `Window.postMessage`
- RFC 6265: Section 5.3 Step 10 (Storage Model non-HTTP API rejection)

## 4. Carry-Forward Items

- A03-001 Column-Zero Coordinate Mismatch: Unrelated `eval()` check at column zero reports column `'unknown'` in web scanner vs column `0` in VS Code extension. Inherited from Phase 01/02 and carried forward.
- Scenario Migration (Batch C): The 8 simulated browser application scenarios remain byte-identical to their baseline hashes. They are marked `pending-batch-c` with `isVulnerable: null` and are scheduled for review and migration in Phase 04 Batch C.
