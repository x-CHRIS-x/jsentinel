# Challenger Report — Static Analysis Rule Robustness

## Challenge Summary

**Overall risk assessment**: HIGH

While the static analysis scanner (JSentinel) correctly flags standard, naive implementations of vulnerabilities (e.g. `eval(userInput)` or `localStorage.setItem('session_token', token)`), it is highly fragile and can be bypassed using very common JavaScript patterns. The primary risk is **high false negatives** (bypass vectors) and **false positives** on clean code due to rigid AST matching criteria.

---

## Challenges

### [High] Challenge 1: Computed Property Access Bypass
- **Assumption challenged**: Vulnerable object properties (e.g. `innerHTML`, `__proto__`, `constructor`, `prototype`, `localStorage`, `cookie`) are always accessed via static dot notation (e.g. `element.innerHTML`).
- **Attack scenario**: Developers or attackers can write code using computed bracket access to avoid detection, which is common in production bundles or obfuscated code:
  - `element['innerHTML'] = userInput;`
  - `obj['__proto__'][key] = value;`
  - `window['localStorage'].setItem('session_token', token);`
  - `document['cookie'] = "session=123;";`
- **Blast radius**: Bypasses detection rules `OWASP-A1-004`, `OWASP-A1-005`, `OWASP-A2-002`, `OWASP-A2-003`, `OWASP-A7-001`, and `OWASP-A8-002` entirely.
- **Mitigation**: Update all `MemberExpression` visitors to check both `property.name` (for `Identifier`) and `property.value` (for `StringLiteral` / `TemplateLiteral`).

### [High] Challenge 2: Global `window` Object Access Bypass
- **Assumption challenged**: Global API calls and objects (e.g., `eval`, `setTimeout`, `setInterval`, `Function`, `localStorage`, `document`) are always referenced directly as identifiers rather than as properties of the `window` object.
- **Attack scenario**: A user or library can invoke these functions via the `window` object:
  - `window.eval(userInput);`
  - `window.setTimeout(userInput, 1000);`
  - `window.localStorage.setItem('token', val);`
- **Blast radius**: Bypasses `OWASP-A1-001`, `OWASP-A1-002`, `OWASP-A1-003`, `OWASP-A2-002`, and `OWASP-A7-002`.
- **Mitigation**: Normalize callee checks to resolve member expressions where the object is `window` and the property is the target API name.

### [High] Challenge 3: Hardcoded Secrets inside Object Literals & Reassignments Bypass
- **Assumption challenged**: Secrets are only declared in standard variable declarations (e.g., `const password = "..."`) or direct assignments.
- **Attack scenario**:
  - *Object properties*: `const config = { password: "SuperSecretPassword" };`
  - *Intermediate reassignments*: `let key; key = "API_KEY_VALUE";`
  - *Template literals*: `const password = \`mysecret\`;`
- **Blast radius**: Bypasses `OWASP-A2-001`, `OWASP-A3-002`, `OWASP-A3-001`, and Shannon Entropy checks.
- **Mitigation**: Add checks for `ObjectProperty` in AST traversals to scan values of keys containing sensitive words. Add `AssignmentExpression` to `OWASP-A3-002`. Support `TemplateLiteral` value extractions.

### [Medium] Challenge 4: Open Redirect Bypasses (`location` / `location.assign`)
- **Assumption challenged**: Redirects only occur by assigning to `location.href` or calling `location.replace()`.
- **Attack scenario**:
  - `window.location = targetUrl;`
  - `location = targetUrl;`
  - `location.assign(targetUrl);`
- **Blast radius**: Bypasses `OWASP-A5-001`.
- **Mitigation**: Expand `AssignmentExpression` to match assignments directly to `location` / `window.location`. Include `assign` alongside `replace` in the `CallExpression` visitor.

### [Medium] Challenge 5: Client-Side Role Check Bypasses (Ternary and Switch Statements)
- **Assumption challenged**: Authorization logic checks always reside inside `IfStatement` conditions.
- **Attack scenario**:
  - `const menu = user.role === 'admin' ? <AdminMenu /> : <UserMenu />;` (Ternary operator)
  - `switch (user.role) { case 'admin': showMenu(); }` (Switch statement)
- **Blast radius**: Misses critical authorization checks in React components and routing files.
- **Mitigation**: Register visitors for `ConditionalExpression` and `SwitchStatement` to inspect for properties like `role`, `isAdmin`, or `admin`.

### [Medium] Challenge 6: Direct Axios Call and Other HTTP Methods SSRF Bypass
- **Assumption challenged**: SSRF calls are limited to `fetch(url)` or `axios.get(url)`/`axios.post(url)`.
- **Attack scenario**:
  - `axios(url)` (Direct call)
  - `axios.put(url)`, `axios.patch(url)`, `axios.delete(url)` (Other HTTP methods)
- **Blast radius**: Misses SSRF vectors in writes/updates or direct configurations.
- **Mitigation**: Support direct Axios call expressions and all common HTTP method member expressions.

### [Medium] Challenge 7: Simple Validation False Positives in `isValidated`
- **Assumption challenged**: Variable validation only occurs through calls to helper functions containing `include`, `indexof`, `test`, `validate`, or `check` in the condition.
- **Attack scenario**:
  - Direct comparisons: `if (url === 'https://example.com')`
  - Intermediate validation variables: `const ok = allowed.includes(url); if (ok) { fetch(url); }`
- **Blast radius**: Causes a high rate of false positives on clean files that implement valid, standard JavaScript checks.
- **Mitigation**: Update `isValidated` to handle binary expressions and simple boolean flags.

---

## Stress Test Results

| Scenario | Expected Behavior | Actual/Predicted Behavior | Pass/Fail |
|---|---|---|---|
| `element['innerHTML'] = x` | Flagged as injection (A1-004/A7-001) | Bypassed (Not flagged) | **FAIL** |
| `window.eval('1+1')` | Flagged as critical injection (A1-001) | Bypassed (Not flagged) | **FAIL** |
| `const config = { pwd: "123" }` | Flagged as hardcoded password (A2-001) | Bypassed (Not flagged) | **FAIL** |
| `location = targetUrl` | Flagged as open redirect (A5-001) | Bypassed (Not flagged) | **FAIL** |
| `location.assign(url)` | Flagged as open redirect (A5-001) | Bypassed (Not flagged) | **FAIL** |
| `const user = u.role === 'admin' ? 1 : 2` | Flagged as client-side check (A5-002) | Bypassed (Not flagged) | **FAIL** |
| `axios(targetUrl)` | Flagged as SSRF risk (A10-001) | Bypassed (Not flagged) | **FAIL** |
| `if (url === 'https://api.com') fetch(url)`| Clean (Not flagged) | Flagged as SSRF risk | **FAIL** |

---

## Unchallenged Areas

- **Dynamic imports**: Dynamic imports `import(variable)` were not challenged because they fall under the general limitations of static analysis.
- **Obfuscation**: Complete identifier renaming and code obfuscation were not challenged since they require runtime analysis, which is out of scope.
