# JSentinel

> **Live Demo:** [https://jsentinel.vercel.app/](https://jsentinel.vercel.app/)

JSentinel is a browser-based static analysis tool that detects security vulnerabilities in JavaScript and TypeScript source code. It parses source code into an Abstract Syntax Tree (AST) using Babel and scans for security risks locally in the browser without uploading code to an external server.

## Features

- **Client-Side Static Analysis:** All parsing, AST traversal, and report generation run locally in browser memory.
- **AST Pattern Matching:** Traverses AST nodes via `@babel/traverse` to identify insecure patterns and dangerous functions.
- **OWASP Vulnerability Coverage:** Checks for injection (`eval`, string timers, DOM XSS), broken authentication, hardcoded secrets, prototype pollution, open redirects, and vulnerable dependencies.
- **Severity Scoring:** Classifies findings into CRITICAL, HIGH, MEDIUM, and LOW severities with weighted project security scores (0–100).
- **Interactive UI:** Highlights vulnerable code lines, provides remediation examples, and allows false positive flagging.
- **Exportable Reports:** Generates downloadable PDF and JSON scan reports.

## Tech Stack

| Component | Technology |
|---|---|
| Frontend Framework | React 19 + Vite |
| Styling | Tailwind CSS v4 |
| AST Engine | @babel/parser, @babel/traverse |
| Report Generation | jsPDF, jspdf-autotable |

## Getting Started

### Prerequisites

- **Node.js** v18 or higher
- **npm**

### Installation (Web Dashboard)

1. Clone the repository:
   ```bash
   git clone https://github.com/x-CHRIS-x/jsentinel.git
   cd jsentinel
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

4. Build for production:
   ```bash
   npm run build
   ```

### Installation (VS Code Extension)

You can run the JSentinel scanner directly inside Visual Studio Code using the pre-built `.vsix` package:

1. **Download the Extension:**
   - Download the package directly from [`vscode-extension/jsentinel-1.0.0.vsix`](vscode-extension/jsentinel-1.0.0.vsix) or from the [Releases](https://github.com/x-CHRIS-x/jsentinel/releases) tab.
2. **Install into VS Code:**
   - Open Visual Studio Code.
   - Open the Extensions view (`Ctrl+Shift+X` / `Cmd+Shift+X`).
   - Click the `...` menu (Views and More Actions) at the top of the Extensions pane.
   - Select **Install from VSIX...** and select `jsentinel-1.0.0.vsix`.
   - *Alternative (via command line):*
     ```bash
     code --install-extension vscode-extension/jsentinel-1.0.0.vsix
     ```

## Project Structure

```text
jsentinel/
├── src/
│   ├── scanner/      # AST detection rules and scanning engine
│   ├── utils/        # Babel parser and PDF/JSON export utilities
│   ├── App.jsx       # Scanner dashboard UI
│   └── main.jsx      # Application entry point
├── vscode-extension/ # VS Code extension
└── public/           # Static assets
```

## Research Attribution

- **Institution:** Arellano University - Andres Bonifacio Campus (AU-ABC)
- **Course:** Capstone Project (BSIT)
- **Adviser:** Dr. Rhonnel S. Paculanan
- **Researchers:** John Chris Ledama, Charles Selwyn Lim, Marc Jorem Luchavez, Gian Crispo
