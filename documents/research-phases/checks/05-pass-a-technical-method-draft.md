# Pass A: Chapter III Technical Method Proposed Checkpoint Draft

Date: September 15, 2026  
Phase: Phase 05 Batch C  
Prepared by: AI Draft prepared in worker session `jsentinel-26` for student group review  
Document Status: Proposed Technical Method Draft (Pending Formal Group Review and Adoption)  
Shared Document Link: `[Shared Google Doc Transfer Link: PENDING GROUP REVIEW AND ADOPTION]`  
Reference Base Commit: `0a76a2f61dea576a0155153a8e0bad6a4d42fdbb`  
Dataset Manifest Version: `1.0.0` (116 files)  

---

## 1. Overview, Purpose, and Governance

This document establishes the proposed Pass A technical method checkpoint for Chapter III (Research Methodology). It defines the dataset distribution, ground-truth provenance, technical evaluation metrics, proposed laboratory procedures, and survey methodology.

In accordance with project workflow rules, this technical method must be formally reviewed and adopted by the student group during Pass A. Once adopted, the text will be transferred into the shared Google Doc *before* formal Phase 07 laboratory testing begins. (Pass B in Phase 08 is reserved for post-testing reconciliation across Chapters I through V). Zero direct modifications are made to live paper chapters or the shared Google Doc at this checkpoint.

---

## 2. Benchmark Dataset and Distribution (Table 1)

The benchmark evaluation dataset comprises 116 JavaScript and JSX files. It consists of 108 controlled test files (54 matched pairs of vulnerable and corrected implementations) and 8 composite simulated browser application workloads.

Table 1 presents the dataset distribution across the scanner rule modules:

### Table 1. Benchmark Sample Distribution Across Detection Modules

| Primary Module | OWASP Top 10:2021 Category | Vulnerable (V) | Clean (C) | Total Files |
| :--- | :--- | :---: | :---: | :---: |
| `accessControl.js` | A01:2021 - Broken Access Control | 6 | 6 | 12 |
| `auth.js` | A07:2021 - Identification & Auth Failures / A02:2021 - Cryptographic Failures | 9 | 9 | 18 |
| `deserialization.js` | A08:2021 - Software and Data Integrity Failures | 6 | 6 | 12 |
| `injection.js` | A03:2021 - Injection | 11 | 11 | 22 |
| `knownVulns.js` | A06:2021 - Vulnerable and Outdated Components (Advisory) | 0 | 0 | 0 |
| `misconfig.js` | A05:2021 - Security Misconfiguration | 4 | 4 | 8 |
| `sensitiveData.js` | A02:2021 - Cryptographic Failures | 11 | 11 | 22 |
| `xss.js` | A03:2021 - Injection (Cross-Site Scripting) | 7 | 7 | 14 |
| **Controlled Subtotal** | **54 Matched Pairs Across 7 Active Modules** | **54** | **54** | **108** |
| `Simulated Scenarios` | Composite Multi-Flaw Browser Workloads | - | - | 8 |
| **Grand Total** | **Entire Benchmark Dataset** | **54** | **54** | **116** |

Every file is counted exactly once in Table 1. Each controlled pair isolates a specific client-side vulnerability alongside a safe remediation. The safe counterpart applies genuine browser mitigations such as strict origin verification, parameter allowlists, DOM text sanitization, or Web Crypto APIs.

The advisory module, `knownVulns.js`, implements rule `OWASP-A06-001`. It flags third-party library imports for component-review advisories rather than confirmed static vulnerabilities. Because the controlled matrix measures binary vulnerability detection, `knownVulns.js` contains zero controlled vulnerability pairs in the confusion matrix. Its diagnostic signaling is evaluated separately in automated tests and within the composite scenarios.

The 8 simulated scenario files model multi-component browser web applications, such as administrative dashboards, payment gateways, and API routers. These files contain multiple flaws per file and third-party imports. They evaluate how the scanner handles composite structures and are evaluated separately from the 108 controlled unit files.

---

## 3. Ground-Truth Provenance and Detection Scope

The ground-truth expectations for all 116 files were established independently of the scanner engines. Flaw descriptions, line coordinates, and safe partner assumptions are documented in `test-samples/dataset-manifest.json`.

The initial dataset curation and coordinate mapping were completed using AI-assisted review (Gemini 3.8 Flash High). Formal manual human adjudication of ground-truth findings remains pending group review. The evaluation system marks all unreviewed findings as `PENDING` to prevent false claims of human sign-off.

### Active Rules vs Tested Coverage
The scanner engines register 24 active detection rules across 7 OWASP Top 10 categories:
- A01 (Broken Access Control): 2 rules
- A02 (Cryptographic Failures): 7 rules
- A03 (Injection): 8 rules
- A05 (Security Misconfiguration): 2 rules
- A06 (Vulnerable and Outdated Components): 1 advisory rule
- A07 (Identification and Authentication Failures): 1 rule
- A08 (Software and Data Integrity Failures): 3 rules

Five historical rules were retired during Phase 01: `OWASP-A05-002` (server CORS wildcard), `OWASP-A05-004` (server Helmet headers), two `OWASP-A06-001` sub-branches, and `OWASP-A10-001` (server SSRF). These checks inspected server-side HTTP headers or network boundaries outside browser client code.

Rule distribution across benchmark categories reflects common client-side weaknesses rather than an equal quota per rule. Categories like A02 and A03 contain more test samples because dynamic code execution and insecure client storage are prevalent browser defects.

Furthermore, three controlled vulnerability samples (`V-A10-053`, `V-A10-054`, and `V-A6-033`) represent documented unsupported weaknesses (`ruleId: null, unsupported: true` in `dataset-manifest.json`). The active 24-rule registry does not implement detection for ambient credential fetch, dynamic script.src injection, or wildcard postMessage targetOrigin. These samples test whether the benchmark honestly reports scanner coverage gaps.

### Coordinate Handling and Known Limitation
Both web and extension engines use Babel AST parsers, where line numbers are 1-indexed and column numbers are 0-indexed (`path.node.loc.start.column`). A known discrepancy exists where certain rule visitors used `col || 'unknown'`, which treated column 0 as falsy and returned string `'unknown'`. To prevent coordinate false negatives while preserving auditability, evaluation enforces exact line coordinates (`locationTolerance: 0`, `matchColumn: false`) while retaining raw column values in all exported reports.

---

## 4. Technical Evaluation Protocol and Metrics

The evaluation framework strictly separates file-level matrix classification from finding-level rule matching and scenario analysis.

### Unit of Testing
One controlled test case is defined as one file with reviewed ground-truth expectations and recorded scanner outputs.

### Detection Matching vs Metadata Verification
Target detection matching is evaluated strictly by `ruleId` and location coordinates under the configured policy. Category and severity metadata do NOT decide whether a detection match occurred:
- A detection match requires identical `ruleId` and coordinates matching within tolerance.
- Category and severity are compared separately in metadata concordance checks (recording whether the rule's metadata agrees with the target expectation).
- Manual description verification checks whether the finding's reported description/message identifies the expected weakness.

### Completion Tracking
Every scan attempt is classified into one of four states:
1. `completed`: Successful AST parse and complete visitor traversal without errors.
2. `partial`: Execution was interrupted by rule-level runtime exceptions.
3. `failed`: Fatal parser errors or unhandled scanner engine exceptions occurred.
4. `unattempted`: A manifest file was omitted from the scan run.

Only scans with a `completed` status and `hasError = false` enter the controlled evaluation matrix. Partial or failed runs are reported in completion metrics but are excluded from detection ratios to prevent distorted performance numbers.

### Controlled Confusion Matrix
The denominator N represents the count of completed eligible controlled scans (N <= 108). If any controlled file scan is partial or failed, N decreases.
Outcomes are classified as:
- True Positive (TP): A vulnerable file with one or more in-scope vulnerability alerts.
- True Negative (TN): A clean file with zero in-scope vulnerability alerts.
- False Positive (FP): A clean file with one or more in-scope vulnerability alerts.
- False Negative (FN): A vulnerable file with zero in-scope vulnerability alerts.

Formulas:
- Accuracy = (TP + TN) / N
- Precision = TP / (TP + FP)
- Recall (Sensitivity) = TP / (TP + FN)
- Specificity = TN / (TN + FP)
- False Positive Rate (FPR) = FP / (FP + TN)
- False Negative Rate (FNR) = FN / (FN + TP)

If any denominator is zero, the evaluator outputs `N/A`.

### Expected-Rule Recall and Finding Adjudication
Expected-rule recall measures whether specific vulnerability targets were detected:
- Expected-Rule Recall = Matched Expected Rules / Total Expected Vulnerabilities

Finding precision assesses the validity of reported alerts:
- Target-Match Fraction = Matched Findings / Total Actual Findings
- Adjudicated Precision = (Automated Matched TP + Reviewed Unmatched TP) / (Automated Matched TP + Reviewed Unmatched TP + Reviewed Unmatched FP [+ Duplicates if COUNT_AS_FP])

Any finding that does not match a documented target requires manual ground-truth review. The evaluator keeps adjudicated precision as `N/A` until human reviewers assign a disposition of `TRUE_POSITIVE` or `FALSE_POSITIVE`. Automated target matches are distinguished from human approvals. Duplicate alerts at the same line coordinate are excluded from inflating match counts.

### Research Stage Boundary (Development vs Formal AU Laboratory Results)
All metrics and confusion-matrix values produced during Phase 05 development (including local test observations yielding TP=45, TN=53, FP=1, FN=9, 90.74% accuracy, and 85.00% expected-rule recall) represent local pre-freeze development observations only. These local observations verify evaluator mechanics and test-suite integrity. They must not be presented as Phase 07 AU laboratory results, which require physical data collection on Arellano University laboratory computers following the formal multi-run protocol.

---

## 5. Proposed Laboratory Testing Protocol

This section outlines the student group's proposed testing protocol for formal evaluation runs at Arellano University. These procedures represent proposed research protocols pending formal group and PC adoption.

### Hardware and Software Environment (Proposed)
- Workstations: Dedicated AU laboratory personal computers (final processor, RAM, and operating system specifications will be recorded on site).
- Runtime Environments: Node.js (current LTS), modern Chromium browser for web testing, and VS Code for the extension interface.
- Local Storage: Test files stored on local solid-state drives to eliminate external network latency.
- Cache Management: Browser cache and temporary extension storage will be cleared prior to test runs.

### Proposed Execution Protocol
1. Environmental Check: Verify installed tool versions, Node runtime, operating system, and dataset file SHA-256 hashes on each participating workstation.
2. Setup and Compatibility Pilot: Conduct a dedicated setup and compatibility pilot on each participating AU PC prior to formal measurement. The pilot verifies interface loading, scanner execution, export collection, and screenshot workflows. The pilot is not a formal measured run; its purpose is solely to identify and resolve configuration, path, or permission issues before formal data collection begins.
3. Proposed Warm-Up Run: An initial pass over 10 sample files is proposed to warm up runtime compilation caches and engine initialization. Timings from this warm-up pass are recorded separately and strictly excluded from final timing averages.
4. Proposed Repeated Iterations: Three consecutive scan passes across all 116 files are proposed for both scanner engines (web application in the recorded browser and extension in actual VS Code), with timings averaged across iterations.
5. Timing Start and Stop Boundary: Formal timing starts at scan invocation after the input file or folder is ready in memory and ends when the completed scan and vulnerability report are available. Manual file selection and upload time (such as navigating file dialogs, selecting items, or drag-and-drop movement) is strictly excluded from formal scan-duration timing. The scanner engines do not isolate separate AST parse duration from rule execution duration; therefore, separate parse timings are not claimed. Local Node development timings are explicitly distinguished from AU physical laboratory performance.
6. File-Size Measurement Protocol: Workload size is recorded using three measures: raw file size in bytes on disk (via filesystem stat), newline-delimited line counts, and total character counts.
7. Memory Observation Technique: Process memory consumption will be observed at regular intervals (start, midpoint, end of run) using Node.js `process.memoryUsage()` for the engine and browser/VS Code task managers for the user interfaces.
8. Evidence Retention Requirements: Formal evaluation runs require complete archival of evidence to support verification. The retained evidence package must include:
   - Raw scanner output and exported reports (JSON and CSV exports from both web and extension interfaces);
   - Evaluator output files, confusion matrices, and adjudication records;
   - Detailed timing records for each iteration, warm-up pass, and per-file duration;
   - Complete workstation environment records (PC identifier, CPU, RAM, OS, browser build, VS Code version, Node runtime, date, and operator);
   - Photographic or screenshot evidence supporting recorded runs, UI states, and diagnostic summaries (screenshots support recorded runs rather than replacing underlying count records);
   - Error and completion logs, documenting any parse errors, rule runtime exceptions, partial scans, or failed scans;
   - Exact version and integrity identifiers (scanner build or commit hash, dataset manifest SHA-256 digest, and evaluator commit SHA).

---

## 6. Survey Methodology and Statistical Tools

User acceptance testing evaluates the practical usability and effectiveness of JSentinel based on the ISO/IEC 25010 software quality model.

### Sourcing and Baseline Paper Reference
The survey instrument and methodology are sourced directly from the existing approved research paper snapshot: `documents/MD/Final-Grp13-IT225-Chapters123-Aug25-2026.md` (dated August 25, 2026), Section 1 (Evaluation Tool, Table 6) and Section 2 (The 4-Point Likert Scale, Table 7).

### Respondents and Sampling
The evaluation involves 50 purposively selected respondents:
- 40 User Respondents: Computer science and information technology students learning programming and writing JavaScript code for coursework or personal projects.
- 10 Technical Experts: Computer professionals with exposure in programming, software quality assurance, or information security.

### Evaluation Procedure
1. System Demonstration: Participants view a standardized video demonstration detailing system installation, AST scanning, and vulnerability reports.
2. Hands-On Interaction: Respondents are provided optional direct access to test sample files using the web dashboard and VS Code extension.
3. Questionnaire Administration: Participants complete a structured evaluation form distributed through Google Forms.

### Evaluation Criteria (Table 6 in August 25 Paper)
The questionnaire contains 10 items covering 5 ISO/IEC 25010 criteria:
1. Functional Suitability (2 items: accurate detection of vulnerabilities, correct classification of issues).
2. Performance Efficiency (2 items: acceptable response time, multi-file handling without slowdown).
3. Usability (2 items: interface navigation, clear presentation of scan results).
4. Security (2 items: standalone operation, local data storage without external transmission).
5. Reliability (2 items: consistent scan results, graceful error recovery without crashing).

### Likert Scale and Interpretation (Table 7 in August 25 Paper)
The study employs a 4-point Likert Scale:
- 4: 3.01 - 4.00 (Strongly Agree)
- 3: 2.01 - 3.00 (Agree)
- 2: 1.01 - 2.00 (Disagree)
- 1: 0.99 - 1.00 (Strongly Disagree)

### Statistical Tools
Data analysis employs three statistical techniques:
1. Frequency Distribution: Raw count of responses per rating level.
2. Percentage Distribution: Percentage of responses across categories (`P = (f / n) * 100`).
3. Weighted Mean: Calculation of central tendency per item and criterion (`x̄ = Σ(f * w) / n`).

Calculations strictly distinguish between respondent counts (n = 40 or n = 10) and total response counts across questions (e.g., 400 or 100). Further alignment with the ISO classmate's calculations remains pending group review.

---

## 7. Document Governance and Next Steps

This draft represents the proposed method for Phase 05. It locks down the sample count at 116, establishes fail-closed completion tracking, separates controlled classification from finding adjudication, and specifies the proposed lab testing protocol.

Unfulfilled promises or speculative features (such as dynamic taint tracing, automated code rewriting, or server-side framework analysis) are excluded from the scope. Static AST visitor analysis remains the sole technical mechanism under evaluation.

Following this checkpoint:
1. The student group reviews the proposed draft method and formally adopts the candidate test package.
2. The agreed Chapter III technical method will be transferred into the shared Google Doc during Pass A, prior to Phase 07 laboratory testing.
3. Physical laboratory testing will be conducted at Arellano University following the agreed protocol.
4. Pass B (Phase 08 Batch B) will reconcile completed test results across Chapters I through V.
