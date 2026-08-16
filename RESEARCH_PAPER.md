# JSentinel: A Client-Side Static Analysis System for Detecting JavaScript Security Vulnerabilities Using an Abstract Syntax Tree (AST) Traversal Algorithm

**Researchers:** John Chris Ledama, Charles Selwyn Lim, Marc Jorem Luchavez, Gian Crispo  
**Adviser:** Dr. Rhonnel S. Paculanan  
**Institution:** Arellano University - Andres Bonifacio Campus (AU-ABC)  
**Program:** Bachelor of Science in Information Technology (BSIT)  

---

## Abstract
Modern web applications rely heavily on client-side JavaScript to provide interactive features and dynamic user experiences. However, security vulnerabilities such as Cross-Site Scripting (XSS), DOM injection, and insecure credential handling frequently persist in production environments. Traditional static analysis tools often require external server deployments, command-line installations, or paid subscriptions, which create adoption barriers for student developers and small teams. This study presents **JSentinel**, a client-side static application security testing (SAST) system that analyzes JavaScript source code directly within the web browser. Using the Babel parser, JSentinel converts source code into an Abstract Syntax Tree (AST) and performs depth-first traversal to detect structural vulnerability patterns across nine OWASP Top 10 categories. Detected flaws are classified using a CVSS v3.1-inspired weighted penalty model that computes an aggregate project security score from 0 to 100. Because all parsing and analysis execute in client-side runtime memory, user source code remains confidential and is never transmitted over a network.

---

## 1. Introduction
Modern web applications rely on JavaScript to handle critical user interface operations, asynchronous API requests, and local state management. Despite widespread adoption, front-end security practices often receive less attention than server-side controls. Common errors, such as assigning unsanitized strings to `innerHTML`, calling dangerous functions like `eval()`, or leaving hardcoded credentials in front-end files, expose web applications to client-side exploitation.

JSentinel addresses this challenge by providing a lightweight, browser-based static analysis tool that requires no installation, external accounts, or backend servers. Developers can upload individual files or full directory trees to obtain instant security feedback, line-level code highlights, remediation guidance, and structured audit reports.

---

## 2. Theoretical Framework

The system is grounded in four established theoretical domains:
1. **Compiler Theory (Aho & Ullman, 1972):** Explains the transformation of raw source code into an Abstract Syntax Tree (AST) via lexical analysis and syntax parsing.
2. **Static Application Security Testing (SAST) Theory (Chess & McGraw, 2004):** Establishes the principles of non-executing code examination using pattern matching over program syntax structures.
3. **OWASP Risk-Based Security Framework (OWASP, 2021):** Provides the vulnerability taxonomy for categorizing identified flaws into recognized risk classifications.
4. **Common Vulnerability Scoring System (CVSS v3.1) (FIRST, 2019):** Supplies the severity classification metrics (Attack Vector, Complexity, Privileges, User Interaction, Scope, Confidentiality, Integrity, Availability) that feed into JSentinel's weighted penalty scoring model.

---

## 3. System Architecture & Methodology

### 3.1 Code Parsing & Traversal
- **Parser:** `@babel/standalone` converts JavaScript and TypeScript files (`.js`, `.jsx`, `.ts`, `.tsx`) into AST structures with `errorRecovery: true` to support partial analysis of syntax-impaired files.
- **Traversal:** Visitor functions inspect AST node types (`CallExpression`, `AssignmentExpression`, `VariableDeclarator`, `MemberExpression`, `JSXAttribute`, `ImportDeclaration`) without executing the code.

### 3.2 Detection Rule Base
JSentinel implements 27 detection rules across 9 OWASP categories:
- **A1: Injection** (`eval`, dynamic `setTimeout`/`setInterval`, `new Function()`, dynamic `innerHTML`)
- **A2: Broken Authentication** (Hardcoded passwords, `localStorage` tokens, insecure cookies, `Math.random()`, HTTP URLs)
- **A3: Sensitive Data Exposure** (Hardcoded JWTs, AWS keys, public IPs, hardcoded API secrets, query parameters)
- **A5: Broken Access Control** (Open redirects, client-side role checks)
- **A6: Security Misconfiguration** (Console logging of credentials/objects, CORS wildcards, missing Helmet middleware)
- **A7: Cross-Site Scripting (XSS)** (`innerHTML`, `document.write()`, React `dangerouslySetInnerHTML`)
- **A8: Software & Data Integrity Failures** (Unchecked `JSON.parse()`, prototype pollution, unsafe `Object.assign()`)
- **A9: Vulnerable Components** (Imports of vulnerable dependencies like `lodash`, `axios`, `serialize-javascript`)
- **A10: Server-Side Request Forgery** (Dynamic HTTP request URLs)

### 3.3 Scoring Model
Project security scores are calculated on a 0 to 100 scale:
$$\text{Score} = \max\left(0, 100 - \sum \text{Penalties}\right)$$
- **CRITICAL:** 20.0 penalty points
- **HIGH:** 10.0 penalty points
- **MEDIUM:** 5.0 penalty points
- **LOW:** 1.0 penalty point

---

## 4. Evaluation & ISO/IEC 25010 Alignment

The system is evaluated against five ISO/IEC 25010 software quality characteristics:
1. **Functional Suitability:** Verified through automated testing against 100+ vulnerable and remediated code samples (achieving 100% detection rate on true positives and 0% false positives on remediated samples).
2. **Performance Efficiency:** Scans 500-line source files in under two seconds with minimal browser memory overhead.
3. **Usability:** Color-coded severity badges, line-by-line code viewer, and interactive remediation suggestions.
4. **Security & Confidentiality:** Pure client-side execution ensures zero transmission of source code to external servers.
5. **Reliability:** Per-rule `try-catch` isolation and Babel `errorRecovery` guarantee resilient execution even on malformed scripts.

---

## 5. References

- Aho, A. V., & Ullman, J. D. (1972). *The theory of parsing, translation, and compiling*. Prentice-Hall.
- Chess, B., & McGraw, G. (2004). Static analysis for security. *IEEE Security & Privacy*, 2(6), 76-79.
- FIRST.org. (2019). *Common Vulnerability Scoring System Version 3.1: Specification Document*. Forum of Incident Response and Security Teams.
- ISO/IEC. (2011). *Systems and software engineering: Systems and software quality requirements and evaluation (SQuaRE): System and software quality models* (ISO/IEC Standard No. 25010:2011).
- OWASP Foundation. (2021). *OWASP Top 10: The ten most critical web application security risks*.
