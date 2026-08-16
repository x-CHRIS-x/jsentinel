# JSentinel

**Full Title:** JSentinel: A Client-Side Static Analysis System for Detecting JavaScript Security Vulnerabilities Using an Abstract Syntax Tree (AST) Traversal Algorithm

JSentinel is a browser-based static analysis tool designed for web developers to detect security vulnerabilities in client-side JavaScript code. The system operates entirely within the user's web browser, ensuring that source code remains private and is never transmitted to an external server.

---

## Key Features

- **100% Client-Side Static Analysis:** All parsing, AST traversal, and report generation execute locally in browser memory.
- **AST-Based Vulnerability Detection:** Converts source code into an Abstract Syntax Tree using `@babel/standalone` and traverses nodes via the depth-first visitor pattern.
- **OWASP Top 10 Coverage:** Implements 27 detection rules across 9 OWASP vulnerability categories.
- **CVSS v3.1 Severity Scoring:** Pre-assigned base scores and vector strings classify each finding into standard severity bands (CRITICAL, HIGH, MEDIUM, LOW).
- **Weighted Penalty Security Score:** Projects are scored on a 0 to 100 scale using the formula:
  $$\text{Score} = \max(0, 100 - \sum \text{penalties})$$
  Penalties: CRITICAL = 20 pts, HIGH = 10 pts, MEDIUM = 5 pts, LOW = 1 pt.
- **Interactive Dashboard:** Inspect source code with highlighted vulnerability lines, view remediation code fixes, and toggle false positive flags.
- **10 Standard Reports:** Generates file matrix summaries, OWASP category distributions, historical scan comparisons, false positive registries, developer audit logs, and downloadable PDF/JSON reports.
- **Local Persistence:** Retains scan history, audit trails, and false positive annotations in browser `localStorage`.

---

## Tech Stack

| Component | Technology |
|---|---|
| Frontend Framework | React 19 + Vite 8 |
| Styling | Tailwind CSS v4 |
| AST Parsing & Traversal | @babel/standalone, @babel/traverse |
| Document Export | jsPDF, jspdf-autotable |
| Persistence | Browser localStorage API |

---

## Detection Rules Matrix (27 Rules Across 9 OWASP Categories)

### A1 - Injection
- `OWASP-A1-001` (CRITICAL): `eval()` dynamic code execution
- `OWASP-A1-002` (HIGH): String timer execution in `setTimeout` or `setInterval`
- `OWASP-A1-003` (CRITICAL): `new Function()` constructor with dynamic string
- `OWASP-A1-004` (HIGH): `innerHTML` assignment with template literal interpolation
- `OWASP-A1-005` (HIGH): `innerHTML` assignment with function call return value

### A2 - Broken Authentication & Cryptographic Failures
- `OWASP-A2-001` (CRITICAL): Hardcoded passwords in variables or assignments
- `OWASP-A2-002` (HIGH): Sensitive authentication tokens cached in `localStorage`
- `OWASP-A2-003` (MEDIUM): Insecure `document.cookie` manipulation without HttpOnly/Secure flags
- `OWASP-A2-004` (HIGH): Cryptographically insecure `Math.random()` for security tokens
- `OWASP-A2-005` (MEDIUM): Plaintext `http://` connection URLs

### A3 - Sensitive Data Exposure
- `OWASP-A3-001` (CRITICAL / MEDIUM): Hardcoded JWT tokens, AWS access keys, or public IP addresses
- `OWASP-A3-002` (CRITICAL): Hardcoded API keys and secrets in variable declarations
- `OWASP-A3-003` (MEDIUM): Sensitive parameters exposed in URL query strings

### A5 - Broken Access Control
- `OWASP-A5-001` (HIGH): Unvalidated dynamic values in `window.location` or `location.replace()` (Open Redirect)
- `OWASP-A5-002` (MEDIUM): Client-side role and administrative checks guarding application logic

### A6 - Security Misconfiguration
- `OWASP-A6-001` (MEDIUM): Sensitive variable names logged to `console`
- `OWASP-A6-002` (MEDIUM): Permissive CORS wildcard policy (`Access-Control-Allow-Origin: *`)
- `OWASP-A6-003` (MEDIUM): Sensitive request/session/config objects logged to `console`
- `OWASP-A6-004` (LOW): Express application imported without `helmet` security middleware

### A7 - Cross-Site Scripting (XSS)
- `OWASP-A7-001` (HIGH): Direct assignment to `.innerHTML`
- `OWASP-A7-002` (CRITICAL): Use of `document.write()`
- `OWASP-A7-003` (HIGH): React `dangerouslySetInnerHTML` attribute

### A8 - Software and Data Integrity Failures
- `OWASP-A8-001` (LOW): Unvalidated `JSON.parse()` on untrusted input
- `OWASP-A8-002` (HIGH): Prototype pollution via `__proto__` or `constructor.prototype`
- `OWASP-A8-003` (MEDIUM): Dynamic `Object.assign()` target mutation

### A9 - Vulnerable and Outdated Components
- `OWASP-A9-001` (MEDIUM): Imports of known vulnerable packages (e.g. `lodash`, `axios`, `serialize-javascript`, `vm2`, `jsonwebtoken`)

### A10 - Server-Side Request Forgery (SSRF)
- `OWASP-A10-001` (HIGH): Dynamic unvalidated request endpoints passed to `fetch()` or `axios`

---

## Installation & Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/x-CHRIS-x/jsentinel.git
   cd jsentinel
   ```

2. Install project dependencies:
   ```bash
   npm install
   ```

3. Start the local development server:
   ```bash
   npm run dev
   ```

4. Build for production:
   ```bash
   npm run build
   ```

5. Run test verification suite:
   ```bash
   node test-samples/test-runner.cjs
   ```

---

## Research Attribution

- **Institution:** Arellano University - Andres Bonifacio Campus (AU-ABC)
- **Course:** Capstone Project (BSIT)
- **Adviser:** Dr. Rhonnel S. Paculanan
- **Researchers:** John Chris Ledama, Charles Selwyn Lim, Marc Jorem Luchavez, Gian Crispo
