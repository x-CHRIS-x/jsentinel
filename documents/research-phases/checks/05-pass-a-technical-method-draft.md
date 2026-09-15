# Pass A: Chapter III Technical Method Checkpoint Draft

Date: September 15, 2026  
Phase: Phase 05 Batch C  
Author: John Chris P. Ledama  
Status: Proposed Draft Checkpoint (Pending Group Review and Freeze Adoption)  
Reference Base Commit: `0a76a2f61dea576a0155153a8e0bad6a4d42fdbb`  
Evaluator State Commit: `5239da9`  
Dataset Manifest Version: `1.0.0` (116 files)  

---

## 1. Overview and Scope

This document provides the Pass A technical method checkpoint for Chapter III (Research Methodology). It addresses the dataset distribution, ground-truth definitions, evaluation metrics, laboratory testing protocol, and survey procedures before formal laboratory runs take place.

Following the project guidelines, no direct modifications are made to the live paper or shared Google Doc. This document serves as an agreed draft checkpoint for group review. Once the group reviews and adopts this method, the text will be transferred into the shared Google Doc during Pass B.

---

## 2. Benchmark Dataset and Distribution (Table 1)

The benchmark evaluation dataset contains 116 JavaScript and JSX files. It consists of 108 controlled test files (54 matched pairs of vulnerable and corrected implementations) and 8 composite simulated browser scenarios.

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

Every file is counted exactly once in Table 1. Each controlled pair isolates a specific client-side vulnerability alongside a safe remediation. The safe counterpart applies valid browser mitigations such as strict origin checks, parameter allowlists, DOM sanitization, or cryptographic APIs.

The advisory module, `knownVulns.js`, implements rule `OWASP-A06-001`. It flags third-party library imports for component-review advisories rather than confirmed static vulnerabilities. Because the controlled matrix measures binary vulnerability detection, `knownVulns.js` contains zero controlled vulnerability pairs in the confusion matrix. Its diagnostic signaling is evaluated separately in automated tests and within the composite scenarios.

The 8 simulated scenario files represent realistic multi-flaw client workloads. These files include administrative dashboards, payment modules, chat interfaces, and API integrations. They evaluate how the scanner handles composite structures containing multiple flaws and third-party imports. These scenarios are evaluated separately from the 108 controlled unit files.

---

## 3. Ground-Truth Provenance and Detection Scope

The ground-truth expectations for all 116 files were established independently of the scanner engines. Flaw descriptions, line coordinates, and safe partner assumptions are documented in `test-samples/dataset-manifest.json`.

The initial dataset curation and coordinate mapping were completed using AI-assisted review (Gemini 3.8 Flash High). Formal manual human adjudication of ground-truth findings remains pending group review. The evaluation system marks all unreviewed findings as `PENDING` to prevent false claims of human sign-off.

The scanner engines implement 24 active detection rules across 7 OWASP Top 10 categories:
- A01 (Broken Access Control): 2 rules
- A02 (Cryptographic Failures): 7 rules
- A03 (Injection): 8 rules
- A05 (Security Misconfiguration): 2 rules
- A06 (Vulnerable and Outdated Components): 1 advisory rule
- A07 (Identification and Authentication Failures): 1 rule
- A08 (Software and Data Integrity Failures): 3 rules

Five historical rules were retired during Phase 01: `OWASP-A05-002` (server CORS wildcard), `OWASP-A05-004` (server Helmet headers), two `OWASP-A06-001` sub-branches, and `OWASP-A10-001` (server SSRF). These checks inspected server-side HTTP headers or network boundaries outside browser client code.

Rule distribution across categories reflects common client-side weaknesses rather than an equal quota per rule. Categories like A02 and A03 contain more test samples because dynamic code execution and insecure client storage are common browser security defects.

---

## 4. Technical Evaluation Protocol and Metrics

The evaluation framework separates file-level matrix classification from finding-level rule matching and scenario analysis.

### Unit of Testing
One controlled test case is defined as one file with reviewed ground-truth expectations and recorded scanner outputs. The evaluator matches expected targets against scanner alerts using exact line coordinates (line tolerance 0 under default policy), matching rule identifiers, and corresponding vulnerability categories.

### Completion Tracking
Every scan attempt is classified into one of four states:
1. `completed`: Successful AST parse and complete visitor traversal without errors.
2. `partial`: Execution was interrupted by rule-level runtime exceptions.
3. `failed`: Fatal parser errors or unhandled scanner engine exceptions occurred.
4. `unattempted`: A manifest file was omitted from the scan run.

Only scans with a `completed` status and `hasError = false` enter the controlled evaluation matrix. Partial or failed runs are reported in completion metrics but are excluded from detection ratios to prevent distorted performance numbers.

### Controlled Confusion Matrix
For completed controlled files (N = 108), results are classified into four standard outcomes:
- True Positive (TP): A vulnerable file with one or more in-scope vulnerability alerts.
- True Negative (TN): A clean file with zero in-scope vulnerability alerts.
- False Positive (FP): A clean file with one or more in-scope vulnerability alerts.
- False Negative (FN): A vulnerable file with zero in-scope vulnerability alerts.

The evaluation metrics are computed as follows:
- Accuracy = (TP + TN) / (TP + TN + FP + FN)
- Precision = TP / (TP + FP)
- Recall (Sensitivity) = TP / (TP + FN)
- Specificity = TN / (TN + FP)
- False Positive Rate (FPR) = FP / (FP + TN)
- False Negative Rate (FNR) = FN / (FN + TP)

If any denominator is zero, the evaluator outputs `N/A` rather than calculating invalid ratios.

### Expected-Rule Recall and Finding Adjudication
Expected-rule recall measures whether specific vulnerability targets were detected:
- Expected-Rule Recall = Matched Expected Rules / Total Expected Vulnerabilities

Finding precision assesses the validity of reported alerts:
- Target-Match Fraction = Matched Findings / Total Actual Findings
- Adjudicated Precision = Reviewed TP / (Reviewed TP + Reviewed FP)

Any finding that does not match a documented target requires manual ground-truth review. The evaluator keeps adjudicated precision as `N/A` until a human reviewer assigns a disposition of `TRUE_POSITIVE` or `FALSE_POSITIVE`. Duplicate alerts at the same line coordinate are excluded from inflating match counts.

---

## 5. AU Laboratory Testing Protocol

Formal evaluation runs will be conducted in the computer laboratories of Arellano University. This protocol outlines the procedure for testing both the web interface and the VS Code extension.

### Hardware and Software Configuration
- Workstation: Dedicated laboratory personal computer (final CPU, RAM, and OS specifications will be recorded on site).
- Runtime Environments: Node.js (current LTS), modern Chromium-based browser for the web application, and VS Code for the extension interface.
- Local Isolation: All test files will be stored on local solid-state drives to eliminate network latency during static analysis.

### Execution Procedure
1. Environmental Verification: Confirm installed tool versions, clear system cache, and verify dataset file hashes.
2. Warm-Up Execution: Run an initial pass over 10 sample files to warm up runtime compilation caches. Timings from this warm-up pass are recorded separately and discarded from final timing averages.
3. Repeated Test Iterations: Execute three consecutive scan passes across all 116 files for both scanner engines.
4. Data Recording: Record scan completion status, detected issues, AST parsing duration, and rule execution time for each file.
5. Memory Monitoring: Observe process memory consumption via Node.js `process.memoryUsage()` and browser task managers at regular intervals (start, midpoint, and completion).

The local benchmark runner timings obtained during development reflect Node.js execution. They do not establish physical browser DOM or VS Code extension execution speeds. Formal timing figures belong in Chapter IV after physical laboratory execution.

---

## 6. Survey Methodology and Statistical Tools

User acceptance testing evaluates the practical usability and effectiveness of JSentinel based on the ISO/IEC 25010 software quality model.

### Respondents and Sampling
The evaluation includes 50 purposively selected respondents divided into two groups:
- 40 General Users: Computer science and information technology students who interact with the web scanning dashboard.
- 10 Technical Experts: IT faculty members, software engineers, and cybersecurity practitioners who evaluate both the web application and the VS Code extension.

### Evaluation Procedure
1. System Demonstration: Participants watch a standardized video demonstration explaining the installation, AST scanning process, and vulnerability reports.
2. Hands-On Interaction: Respondents are given optional direct access to test sample files using the web dashboard and VS Code extension.
3. Questionnaire Administration: Participants complete a structured evaluation form with 10 questions covering 5 ISO quality criteria:
   - Functional Suitability (2 items)
   - Reliability (2 items)
   - Usability (2 items)
   - Performance Efficiency (2 items)
   - Maintainability (2 items)

### Statistical Analysis
Survey responses use a 5-point Likert scale (5 = Strongly Agree, 4 = Agree, 3 = Neutral, 2 = Disagree, 1 = Strongly Disagree). Data will be summarized using three statistical measures:
1. Frequency Distribution: Counting respondent selections for each rating level.
2. Percentage Distribution: Calculating the proportion of responses across rating categories.
3. Weighted Mean: Computing the central tendency for each item and criterion using standard verbal interpretation ranges:
   - 4.21 to 5.00: Strongly Agree / Very High
   - 3.41 to 4.20: Agree / High
   - 2.61 to 3.40: Neutral / Moderate
   - 1.81 to 2.60: Disagree / Low
   - 1.00 to 1.80: Strongly Disagree / Very Low

Calculations clearly distinguish between respondent counts (N = 40 or N = 10) and total response counts across multiple questions.

---

## 7. Document Governance and Next Steps

This draft represents the method agreed upon for Phase 05. It locks down the sample count at 116, establishes fail-closed completion tracking, separates controlled classification from finding adjudication, and specifies the lab testing protocol.

Unfulfilled promises or speculative features (such as dynamic taint tracing, automated code fixing, or server-side framework analysis) are excluded from the scope. Static AST visitor analysis remains the sole technical mechanism under evaluation.

Following this checkpoint:
1. The student group reviews the draft method and formally adopts the frozen test package.
2. Physical laboratory testing will be conducted at Arellano University following the protocol defined in Section 5.
3. Live Google Doc updates will be executed during Pass B (Phase 08 Batch B), ensuring full alignment across Chapters I through V.
