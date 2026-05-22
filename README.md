# JSentinel

JSentinel is a localized static analysis tool designed for web developers to detect latent security vulnerabilities in JavaScript code. It operates entirely within the browser, ensuring that no code is ever sent to a server, providing maximum privacy and security.

## Features

- Localized Analysis: All processing happens on your machine.
- AST-Based Detection: Uses Babel to parse code into an Abstract Syntax Tree (AST) for precise vulnerability mapping.
- OWASP Alignment: Detects issues mapped to OWASP Top 10 categories.
- Folder Upload Support: Analyze entire projects at once (ignores node_modules, dist, etc.).
- Professional UI: IDE-style dashboard with syntax highlighting and dark mode support.
- Exportable Reports: Download scan results as PDF reports using jsPDF.

## Tech Stack

- Frontend: React + Vite
- Styling: Tailwind CSS
- Parsing: @babel/standalone + @babel/traverse
- Reporting: jsPDF

## Detection Rules (OWASP Mapped)

- A1: Injection: eval(), dynamic setTimeout/setInterval.
- A2: Broken Authentication: Hardcoded passwords, localStorage tokens.
- A3: Sensitive Data Exposure: Hardcoded API keys, credentials, IPs.
- A6: Security Misconfiguration: CORS wildcard, console.log sensitive data.
- A7: Cross-Site Scripting (XSS): innerHTML, document.write(), dangerouslySetInnerHTML.
- A8: Insecure Deserialization: Unsafe JSON.parse().
- A9: Known Vulnerabilities: Risky library imports.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/x-CHRIS-x/jsentinel.git
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the development server:
   ```bash
   npm run dev
   ```

## How it Works

1. Upload: User selects a file or folder.
2. Filter: The tool filters for .js, .jsx, .ts, .tsx, and .html files.
3. Parse: Babel converts the code into an AST.
4. Scan: Custom rules traverse the AST nodes to find security patterns.
5. Report: Results are displayed with line numbers and descriptions.

