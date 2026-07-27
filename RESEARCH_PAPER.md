# CodeGuard-JS: A Localized Static Analysis Tool for Detecting Latent Security Vulnerabilities for Web Developers

## Abstract
Web applications are increasingly prone to security vulnerabilities, often stemming from development errors, lack of security knowledge, or rapid prototyping. Traditional static analysis tools often require code to be sent to external servers, raising privacy concerns. This paper presents **CodeGuard-JS**, a browser-based, local-first static analysis tool that detects security vulnerabilities in JavaScript code using Abstract Syntax Tree (AST) parsing. By leveraging client-side execution, the tool preserves code privacy while identifying critical issues such as Injection, XSS, and Broken Authentication based on OWASP standards. The tool employs a CVSS-inspired scoring model to provide developers with actionable risk assessments without server-side dependencies.

## 1. Introduction
The prevalence of security vulnerabilities in web applications is often the result of several factors: inadequate security training, "AI-assisted vibe coding," reliance on insecure tutorials, and immense time pressure during development. For students and junior developers, these "latent" vulnerabilities—issues that exist but have not yet been exploited—represent a significant risk.

CodeGuard-JS address these challenges by providing a localized, instant-feedback mechanism. Unlike cloud-based scanners (e.g., SonarQube, Snyk), CodeGuard-JS runs entirely in the developer's browser, ensuring that sensitive source code never leaves the local machine.

## 2. Objectives and Alignment
The primary objective of this research is to develop a functional static analysis prototype that:
1.  Detects security patterns in JavaScript/TypeScript code using AST traversal.
2.  Provides a quantitative security score to prioritize remediation.
3.  Operates as a zero-server, privacy-first web application.

### CHED CMO 25 Alignment
This research aligns with **CHED CMO 25 s.2015** in two key areas:
*   **Web Applications Development:** Developing advanced, client-side tools for the web ecosystem.
*   **IT Security Analysis, Planning, and Implementation:** Providing proactive security assessment and vulnerability detection.

## 3. Methodology

### 3.1 Architecture
The tool is built using **React** and **Vite** for a modern, responsive UI. It utilizes a local-first processing model where files uploaded via drag-and-drop or folder selection are processed entirely within the browser's main thread (or worker).

### 3.2 AST Parsing and Traversal
At the core of CodeGuard-JS is the **Babel Parser** (`@babel/parser`). Raw JavaScript code is converted into an **Abstract Syntax Tree (AST)**—a structured representation of the code's logic.
*   **Traversal:** The tool uses `@babel/traverse` to walk through the AST nodes.
*   **Detection Rules:** Rules are implemented as visitor patterns that target specific node types (e.g., `CallExpression`, `AssignmentExpression`). For example, detecting `eval()` involves identifying a `CallExpression` where the callee's name is "eval".

### 3.3 Scoring Model
CodeGuard-JS implements a weighted penalty model inspired by **CVSS v3.1** severity definitions.
*   **Weights:** CRITICAL (20 pts), HIGH (10 pts), MEDIUM (5 pts), LOW (1 pt).
*   **Algorithm:** $Score = \max(0, 100 - \sum penalties)$.
*   **Visualization:** The UI displays the score using color-coded thresholds: Green (>80), Orange (50-80), and Red (<50).

## 4. Implementation Details
The application supports scanning individual files and entire directories (traversing subfolders while ignoring `node_modules`). 
*   **UI/UX:** Built with Tailwind CSS, featuring a neutral "Zinc" dark mode and high-contrast light mode to improve visibility of code IDE sections.
*   **Reports:** Professional PDF reports are generated using `jsPDF` and `jspdf-autotable`, allowing developers to export scan findings, including line numbers and remediation suggestions.

## 5. Limitations
*   **Dynamic Analysis:** As a static tool, it cannot detect vulnerabilities that only manifest at runtime (e.g., indirect calls like `let e = eval; e("...")`).
*   **Performance:** Large projects (>50 files) may experience slower processing times due to the single-threaded nature of browser-based parsing.
*   **Scope:** Current detection is focused on JavaScript/TypeScript; server-side languages like PHP or Python are identified as future work.

## 6. Conclusion and Future Work
CodeGuard-JS demonstrates the feasibility of sophisticated security analysis within a browser environment. It provides a vital educational tool for students to catch security errors early in the development lifecycle. Future iterations of this research will explore:
*   Integration as an IDE extension (VS Code).
*   Expanding detection rules to include more complex NoSQL injection patterns.
*   Supporting multi-language analysis (Python/Java) via WASM-based parsers.

## References
*   FIRST. (2019). *Common Vulnerability Scoring System v3.1 Specification*.
*   OWASP. (2021). *OWASP Top 10:2021 — The 10 Most Critical Web Application Security Risks*.
*   CHED. (2015). *CHED Memorandum Order No. 25: Revised Policies, Standards, and Guidelines for Bachelor of Science in Computer Science (BSCS), Bachelor of Science in Information Systems (BSIS), and Bachelor of Science in Information Technology (BSIT) Programs*.
