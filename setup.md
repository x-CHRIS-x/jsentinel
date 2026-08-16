# JSentinel / CodeGuard-JS: Laptop Setup & Capstone Inspection Guide

> Quick reference for opening, inspecting, and presenting the JSentinel repository during the title defense and panel evaluation.

---

## 1. Laptop Setup Instructions

### Prerequisites
Make sure your laptop has the following software installed:
- **Node.js** (v18 LTS or higher recommended)
- **Git**
- **VS Code** (Visual Studio Code)

---

### Step 1: Clone the Repository & Checkout Branch
Open PowerShell or Command Prompt on your laptop:

```bash
git clone https://github.com/x-CHRIS-x/jsentinel.git
cd jsentinel
git checkout feature/panelist-revisions
```

---

### Step 2: Install Web Application Dependencies & Start Server
In the root `jsentinel` folder, run:

```bash
npm install
npm run dev
```

- Open your web browser and navigate to `http://localhost:5173`.
- Test uploading a file/folder or dragging `.js` / `.jsx` / `.ts` / `.tsx` test files to verify client-side AST vulnerability scanning.

---

### Step 3: (Optional) Launching the VS Code Extension Demo
If demonstrating the VS Code extension live to panelists or professor:

1. Open VS Code and open the `vscode-extension` subfolder, or navigate to it in your terminal:
   ```bash
   cd vscode-extension
   ```
2. Install extension dependencies:
   ```bash
   npm install
   ```
3. Open `vscode-extension` in VS Code and press **`F5`** to launch the **Extension Development Host**.
4. In the new Extension Host window, open a sample file (such as `test-samples/samples/user-auth-service.js`).
5. Verify inline squigglies, hover diagnostics, and the sidebar panel dashboard.

---

## 2. Capstone Inspection Requirements Checklist (July 27 & 28)

According to professor requirements for the inspection:

### 🖨️ Required Printed Portions (DO NOT print full documentation):
1. **Specific Objectives**: Print only the page/section listing your specific objectives. Verify that every objective functions properly in the project.
2. **Respondents of the Study**: Print only the section detailing your target respondents and sample size per group.
3. **ISO 25010 Evaluation Form**: Print only the evaluation form. Ensure the evaluation criteria align directly with your specific objectives.

### 🔋 Presentation & Hardware Readiness:
- Make sure your laptop is fully charged and operating reliably.
- Designated presenter will lead the demonstration; group members attend for compliance and support.
