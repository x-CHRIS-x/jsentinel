import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

// self-contained Code Remediation Guide Dictionary for Section 6
const pdfCodeFixGuide = {
  'OWASP-A1-001': {
    bad: 'eval("const user = " + userInput);',
    good: 'const user = JSON.parse(userInput); // Parse structural data safely'
  },
  'OWASP-A1-002': {
    bad: 'setTimeout("executeCallback()", 1000);',
    good: 'setTimeout(executeCallback, 1000); // Pass function reference directly'
  },
  'OWASP-A1-003': {
    bad: 'const execute = new Function("x", "return " + userInput);',
    good: 'const execute = (x) => { return safeCallback(userInput, x); }; // Avoid dynamic code construction'
  },
  'OWASP-A1-004': {
    bad: 'element.innerHTML = `<p>${userInput}</p>`;',
    good: 'element.textContent = userInput; // Automatically sanitizes content to plaintext'
  },
  'OWASP-A1-005': {
    bad: 'element.innerHTML = retrieveData(userInput);',
    good: 'element.textContent = retrieveData(userInput); // Prevent execution of nested script tags'
  },
  'OWASP-A2-001': {
    bad: 'const password = "admin_credential_key_123";',
    good: 'const password = process.env.DATABASE_PASSWORD; // Retrieve credentials from environment context'
  },
  'OWASP-A2-002': {
    bad: 'localStorage.setItem("authToken", jsonWebToken);',
    good: 'document.cookie = "authToken=" + jsonWebToken + "; Secure; HttpOnly; SameSite=Strict;";'
  },
  'OWASP-A2-003': {
    bad: 'document.cookie = "session=" + sessionId;',
    good: 'document.cookie = "session=" + sessionId + "; Secure; HttpOnly; SameSite=Strict;";'
  },
  'OWASP-A2-004': {
    bad: 'const securityToken = Math.random().toString();',
    good: 'const securityToken = window.crypto.getRandomValues(new Uint32Array(1))[0].toString(); // Cryptographically secure random'
  },
  'OWASP-A2-005': {
    bad: 'fetch("http://api.internal.service/authenticate");',
    good: 'fetch("https://api.internal.service/authenticate"); // Enforce encrypted HTTPS connections'
  },
  'OWASP-A3-001': {
    bad: 'const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";',
    good: 'const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY_ID; // Store secrets in secure server context'
  },
  'OWASP-A3-002': {
    bad: 'const apiKey = "sec_key_xyz123456789abc";',
    good: 'const apiKey = process.env.APP_SECRET_API_KEY; // Never expose authorization keys in source code'
  },
  'OWASP-A3-003': {
    bad: 'const authUrl = "/login?password=" + userPassword;',
    good: 'const response = await axios.post("/login", { password: userPassword }); // Pass sensitive credentials in post body'
  },
  'OWASP-A5-001': {
    bad: 'window.location.href = redirectTargetUrl;',
    good: 'if (trustedDomainWhitelist.includes(redirectTargetUrl)) {\n  window.location.href = redirectTargetUrl;\n} // Validate redirect target domain client side'
  },
  'OWASP-A5-002': {
    bad: 'if (userData.role === "admin") { renderDashboard(); }',
    good: '// Access control check must be enforced and validated on the backend API layer\nif (session.isAuthenticated) { renderDashboard(); }'
  },
  'OWASP-A6-001': {
    bad: 'console.log("User password payload: ", userPassword);',
    good: 'console.log("User login lifecycle triggered."); // Log non-sensitive transaction indicators only'
  },
  'OWASP-A6-002': {
    bad: 'response.setHeader("Access-Control-Allow-Origin", "*");',
    good: 'response.setHeader("Access-Control-Allow-Origin", "https://trusted.production.domain"); // Enforce restrictive CORS origins'
  },
  'OWASP-A6-003': {
    bad: 'console.log("Full request context logged: ", requestContext);',
    good: 'console.log("Request context received for path: ", requestContext.path);'
  },
  'OWASP-A6-004': {
    bad: 'const app = express();\napp.listen(3000);',
    good: 'const app = express();\nconst helmet = require("helmet");\napp.use(helmet()); // Enforce helmet secure response headers'
  },
  'OWASP-A7-001': {
    bad: 'targetDiv.innerHTML = untrustedHTMLString;',
    good: 'targetDiv.textContent = untrustedHTMLString; // Avoid DOM parsing of dynamic strings'
  },
  'OWASP-A7-002': {
    bad: 'document.write(userInputString);',
    good: 'const textNode = document.createTextNode(userInputString);\ndocument.body.appendChild(textNode);'
  },
  'OWASP-A7-003': {
    bad: '<div dangerouslySetInnerHTML={{ __html: dynamicMarkup }} />',
    good: '<div>{dynamicMarkup}</div> // Rely on React default rendering auto sanitization'
  },
  'OWASP-A8-001': {
    bad: 'const payload = JSON.parse(untrustedJSONInput);',
    good: 'const payload = secureSchemaParse(untrustedJSONInput); // Validate schema layout post deserialization'
  },
  'OWASP-A8-002': {
    bad: 'targetObject.__proto__.polluted = true;',
    good: 'const targetObject = Object.create(null); // Instantiate prototype-less objects'
  },
  'OWASP-A8-003': {
    bad: 'Object.assign(baseObject, JSON.parse(userInputPayload));',
    good: 'const sanitized = filterKeys(JSON.parse(userInputPayload));\nObject.assign(baseObject, sanitized); // Filter input keys to prevent injection'
  },
  'OWASP-A9-001': {
    bad: 'import lodash from "lodash"; // CVE-2019-10744 prototype pollution',
    good: 'import lodash from "lodash-es"; // Utilize updated or patched utility libraries'
  },
  'OWASP-A10-001': {
    bad: 'axios.get(dynamicRequestUrl);',
    good: 'if (isValidInternalEndpoint(dynamicRequestUrl)) {\n  axios.get(dynamicRequestUrl);\n} // Restrict connection targets to authenticated APIs'
  },
  'OWASP-A3-ENTROPY': {
    bad: 'const secretValue = "a8f3d6c1b9e0f2a4c5d8e7f9b0a1c2d3e4f5"; // Raw high entropy string',
    good: 'const secretValue = process.env.API_KEY; // Relocate raw strings to local environment configs'
  }
};

// Check height bounds and append new pages dynamically
const checkHeightAndPageBreak = (doc, neededHeight, currentY) => {
  if (currentY + neededHeight > 265) {
    doc.addPage();
    return 20; // Standard top margin
  }
  return currentY;
};

/**
 * Generates a professional academic PDF security report containing the 10 core sections.
 * All details run client-side in third-person, contraction-free formatting.
 * 
 * @param {Array} results - Active files analysis results list.
 * @param {Object} stats - Computed compliance and penalty statistics.
 * @param {Array} history - Logged prior scanning records.
 * @param {Array} activity - Developer action audit registry items.
 * @param {Array} fpFlags - Marked false positive key indicators.
 * @param {Object} fpAnnotations - Justification rationale override texts.
 */
export const generatePDFReport = (results, stats, history = [], activity = [], fpFlags = [], fpAnnotations = {}) => {
  const doc = new jsPDF();
  const timestamp = new Date().toLocaleString();
  
  // Custom Academic branding palettes matching JSentinel dark red theme
  const brand = {
    maroon: [185, 28, 28], // Dark Maroon Red
    slate: [51, 65, 85],   // Slate Gray Header
    charcoal: [15, 23, 42], // Deep Charcoal Font
    gray: [100, 116, 139],  // Secondary Slate Gray
    emerald: [16, 185, 129], // Emerald Green Band
    amber: [245, 158, 11],  // Amber Orange Band
    rose: [239, 68, 68]     // Crimson Rose Band
  };

  // Setup Cover Header Panel on first page
  doc.setFillColor(...brand.maroon);
  doc.rect(0, 0, 210, 42, 'F');
  
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.text('JSENTINEL STATIC SECURITY REPORT', 14, 18);
  
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text(`AUDIT GENERATION TIMESTAMP: ${timestamp.toUpperCase()}`, 14, 28);
  doc.text('BROWSER-BASED STATIC SOURCE CODE ANALYSIS ENGINE', 14, 34);

  let y = 55;

  // ==========================================
  // SECTION 1: EXECUTIVE SUMMARY & SECURITY SCORE
  // ==========================================
  doc.setTextColor(...brand.charcoal);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('1. EXECUTIVE SUMMARY & SECURITY SCORE REPORT', 14, y);
  y += 6;

  // Calculated Compliance Rating Band
  const score = stats.securityScore;
  let bandText = "COMPLIANT (EXCELLENT STATUS)";
  let bandColor = brand.emerald;
  
  if (score < 50) {
    bandText = "NON-COMPLIANT (HIGH RISK BREACH PROTOCOL)";
    bandColor = brand.rose;
  } else if (score < 80) {
    bandText = "WARNING STATUS (MITIGATION STRONGLY SUGGESTED)";
    bandColor = brand.amber;
  }

  doc.setFillColor(...bandColor);
  doc.rect(14, y, 182, 14, 'F');
  
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text(`PROJECT SECURITY SCORE RATING: ${score.toFixed(1)}%  -  ${bandText}`, 18, y + 9);
  
  y += 20;
  doc.setTextColor(...brand.charcoal);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  
  const scoreExplanation = "This score is computed client side using a CVSS v3.1 inspired mathematical model. The base line rating starts at 100.0 points. Deductions are dynamically applied based on unmitigated active breaches detected in scanned files: Critical severity issues incur a 20.0 point penalty, High severity issues incur 10.0 points, Medium severity issues incur 5.0 points, and Low severity issues incur 1.0 point. Exempted false positive overrides immediately restore score metrics in real time.";
  const splitExplanation = doc.splitTextToSize(scoreExplanation, 182);
  doc.text(splitExplanation, 14, y);
  y += (splitExplanation.length * 4) + 6;

  // ==========================================
  // SECTION 2: VULNERABILITY SCAN DETAILS
  // ==========================================
  y = checkHeightAndPageBreak(doc, 45, y);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('2. VULNERABILITY SCAN DETAILS', 14, y);
  y += 5;

  autoTable(doc, {
    startY: y,
    head: [['Metric Parameter Flag', 'Scanned Resource Valuation Status']],
    body: [
      ['Scope of Project Scope Name', results.length > 0 ? (history[0]?.projectName || 'Uploaded Workspace') : 'N/A'],
      ['Total Source Files Scanned', `${results.length} JavaScript/TypeScript resource files`],
      ['Total Vulnerability Breaches Detected', `${stats.totalIssues} items flagged in AST nodes`],
      ['Active Vulnerability Breaches Remaining', `${stats.activeIssuesCount} issues affecting rating compliance`],
      ['Flagged False Positive Override Exceptions', `${fpFlags.length} issues excluded from score model`],
      ['Scanning Engine Code Parser Status', 'Complete - Babel Standalone Engine (Active Mode)']
    ],
    theme: 'striped',
    styles: { fontSize: 8, cellPadding: 3.5 },
    headStyles: { fillColor: brand.slate, fontStyle: 'bold' },
    columnStyles: { 0: { fontStyle: 'bold', cellWidth: 90 } }
  });
  y = doc.lastAutoTable.finalY + 12;

  // ==========================================
  // SECTION 3: SEVERITY CLASSIFICATION BREAKDOWN
  // ==========================================
  y = checkHeightAndPageBreak(doc, 50, y);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('3. SEVERITY CLASSIFICATION BREAKDOWN REPORT', 14, y);
  y += 5;

  autoTable(doc, {
    startY: y,
    head: [['Severity Band', 'Active Breaches', 'Weight Deduction', 'Standard CVSS v3.1 Representative Vector']],
    body: [
      ['CRITICAL', `${stats.criticalIssues} active`, '20.0 points', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'],
      ['HIGH', `${stats.highIssues} active`, '10.0 points', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'],
      ['MEDIUM', `${stats.mediumIssues} active`, '5.0 points', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'],
      ['LOW', `${stats.lowIssues} active`, '1.0 point', 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N']
    ],
    theme: 'grid',
    styles: { fontSize: 8, cellPadding: 4 },
    headStyles: { fillColor: brand.slate, fontStyle: 'bold' },
    columnStyles: { 0: { fontStyle: 'bold' }, 1: { fontStyle: 'bold' } }
  });
  y = doc.lastAutoTable.finalY + 12;

  // ==========================================
  // SECTION 4: FILE-LEVEL ANALYSIS MATRIX
  // ==========================================
  y = checkHeightAndPageBreak(doc, 60, y);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('4. FILE-LEVEL ANALYSIS MATRIX REPORT', 14, y);
  y += 5;

  const matrixBody = results.map(res => {
    let filePenalty = 0;
    let activeIssues = 0;
    
    if (res.issues) {
      res.issues.forEach(issue => {
        const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
        if (fpFlags.includes(fpKey)) return;
        
        activeIssues++;
        if (issue.severity === 'CRITICAL') filePenalty += 20.0;
        else if (issue.severity === 'HIGH') filePenalty += 10.0;
        else if (issue.severity === 'MEDIUM') filePenalty += 5.0;
        else if (issue.severity === 'LOW') filePenalty += 1.0;
      });
    }

    const fileScore = Math.max(0, 100 - filePenalty);
    const shortName = res.fileName.split('/').pop();

    return [
      shortName,
      res.fileName,
      res.issues ? res.issues.length : 0,
      activeIssues,
      `${fileScore.toFixed(1)}%`
    ];
  });

  autoTable(doc, {
    startY: y,
    head: [['Resource File', 'Full Relative Workspace Path', 'Raw Flags', 'Active Flags', 'Calculated File Score']],
    body: matrixBody,
    theme: 'striped',
    styles: { fontSize: 8, cellPadding: 3.5 },
    headStyles: { fillColor: brand.slate, fontStyle: 'bold' },
    columnStyles: { 0: { fontStyle: 'bold', cellWidth: 40 }, 4: { fontStyle: 'bold', halign: 'right' } }
  });
  y = doc.lastAutoTable.finalY + 12;

  // ==========================================
  // SECTION 5: DETAILED ISSUE FINDINGS
  // ==========================================
  y = checkHeightAndPageBreak(doc, 60, y);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('5. DETAILED VULNERABILITY FINDINGS REPORT', 14, y);
  y += 5;

  const activeIssuesList = [];
  const triggeredRuleIds = new Set();

  results.forEach(res => {
    if (res.issues) {
      res.issues.forEach(issue => {
        const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
        if (fpFlags.includes(fpKey)) return;

        activeIssuesList.push({
          file: res.fileName.split('/').pop(),
          line: issue.line,
          id: issue.id,
          severity: issue.severity,
          message: issue.message,
          confidence: issue.confidence || 'MEDIUM'
        });

        triggeredRuleIds.add(issue.id);
      });
    }
  });

  if (activeIssuesList.length === 0) {
    doc.setFontSize(9);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(...brand.gray);
    doc.text('No active unmitigated security vulnerabilities are logged in this scanning session.', 14, y);
    y += 10;
  } else {
    const findingsBody = activeIssuesList.map(issue => [
      issue.severity,
      issue.id,
      `Line ${issue.line}`,
      issue.file,
      issue.confidence,
      issue.message
    ]);

    autoTable(doc, {
      startY: y,
      head: [['Severity', 'Rule ID', 'Location', 'Resource', 'Confidence', 'Breach Description']],
      body: findingsBody,
      theme: 'grid',
      styles: { fontSize: 7.5, cellPadding: 3.5 },
      headStyles: { fillColor: brand.slate, fontStyle: 'bold' },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 0) {
          const sev = data.cell.raw;
          if (sev === 'CRITICAL') data.cell.styles.textColor = brand.maroon;
          else if (sev === 'HIGH') data.cell.styles.textColor = [194, 65, 12];
          else if (sev === 'MEDIUM') data.cell.styles.textColor = [180, 83, 9];
          data.cell.styles.fontStyle = 'bold';
        }
      },
      columnStyles: { 0: { cellWidth: 20 }, 1: { cellWidth: 25 }, 2: { cellWidth: 15 }, 4: { fontStyle: 'bold', cellWidth: 20 } }
    });
    y = doc.lastAutoTable.finalY + 12;
  }

  // ==========================================
  // SECTION 6: RECOMMENDED CODE REMEDIATION GUIDES
  // ==========================================
  y = checkHeightAndPageBreak(doc, 60, y);
  doc.setTextColor(...brand.charcoal);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('6. RECOMMENDED CODE REMEDIATION GUIDES', 14, y);
  y += 5;

  if (triggeredRuleIds.size === 0) {
    doc.setFontSize(9);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(...brand.gray);
    doc.text('No remediation guidelines are required. The active codebase does not trigger unmitigated rules.', 14, y);
    y += 10;
  } else {
    triggeredRuleIds.forEach(ruleId => {
      const guide = pdfCodeFixGuide[ruleId];
      if (!guide) return;

      y = checkHeightAndPageBreak(doc, 48, y);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...brand.maroon);
      doc.text(`REMEDIATION TEMPLATE FOR RULE ID: ${ruleId}`, 14, y);
      y += 4;

      doc.setFontSize(8);
      doc.setTextColor(...brand.charcoal);
      
      // Bad code block
      doc.setFillColor(254, 242, 242);
      doc.rect(14, y, 182, 16, 'F');
      doc.setFont('courier', 'normal');
      doc.text('VULNERABLE CODE EXPOSED:', 18, y + 5);
      doc.text(guide.bad, 18, y + 11);
      
      y += 18;

      // Good code block
      doc.setFillColor(240, 253, 250);
      doc.rect(14, y, 182, 16, 'F');
      doc.setFont('courier', 'bold');
      doc.text('SECURE REMEDIATION CONTEXT:', 18, y + 5);
      doc.text(guide.good, 18, y + 11);
      
      y += 22;
      doc.setFont('helvetica', 'normal');
    });
    doc.setTextColor(...brand.charcoal);
  }

  // ==========================================
  // SECTION 7: OWASP CATEGORY VULNERABILITY PROFILE
  // ==========================================
  y = checkHeightAndPageBreak(doc, 60, y);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('7. OWASP CATEGORY VULNERABILITY PROFILE', 14, y);
  y += 5;

  // Pre-calculate OWASP count distributions client side
  const owaspData = {
    'A1:2021-Injection': 0,
    'A2:2021-Broken Authentication': 0,
    'A3:2021-Sensitive Data Exposure': 0,
    'A5:2021-Broken Access Control': 0,
    'A6:2021-Security Misconfiguration': 0,
    'A7:2021-Cross-Site Scripting (XSS)': 0,
    'A8:2021-Software and Data Integrity Failures': 0,
    'A9:2021-Vulnerable and Outdated Components': 0,
    'A10:2021-Server-Side Request Forgery': 0
  };

  results.forEach(res => {
    if (res.issues) {
      res.issues.forEach(issue => {
        const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
        if (fpFlags.includes(fpKey)) return;

        if (issue.id.startsWith('OWASP-A1')) owaspData['A1:2021-Injection']++;
        else if (issue.id.startsWith('OWASP-A2')) owaspData['A2:2021-Broken Authentication']++;
        else if (issue.id.startsWith('OWASP-A3')) owaspData['A3:2021-Sensitive Data Exposure']++;
        else if (issue.id.startsWith('OWASP-A5')) owaspData['A5:2021-Broken Access Control']++;
        else if (issue.id.startsWith('OWASP-A6')) owaspData['A6:2021-Security Misconfiguration']++;
        else if (issue.id.startsWith('OWASP-A7')) owaspData['A7:2021-Cross-Site Scripting (XSS)']++;
        else if (issue.id.startsWith('OWASP-A8')) owaspData['A8:2021-Software and Data Integrity Failures']++;
        else if (issue.id.startsWith('OWASP-A9')) owaspData['A9:2021-Vulnerable and Outdated Components']++;
        else if (issue.id.startsWith('OWASP-A10')) owaspData['A10:2021-Server-Side Request Forgery']++;
      });
    }
  });

  const owaspBody = Object.entries(owaspData).map(([name, count]) => {
    return [name, `${count} active breaches`, count > 0 ? 'Exposed status' : 'Secure compliance'];
  });

  autoTable(doc, {
    startY: y,
    head: [['OWASP Core Category Profile Description', 'Breach Frequency Metric', 'Compliance Status']],
    body: owaspBody,
    theme: 'striped',
    styles: { fontSize: 8, cellPadding: 3.5 },
    headStyles: { fillColor: brand.slate, fontStyle: 'bold' }
  });
  y = doc.lastAutoTable.finalY + 12;

  // ==========================================
  // SECTION 8: HISTORICAL COMPARISON ANALYSIS
  // ==========================================
  y = checkHeightAndPageBreak(doc, 60, y);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('8. HISTORICAL COMPARISON ANALYSIS REPORT', 14, y);
  y += 5;

  if (history.length <= 1) {
    doc.setFontSize(9);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(...brand.gray);
    doc.text('Baseline execution: no prior historical scanning sessions are logged in this sandbox registry.', 14, y);
    y += 10;
    doc.setTextColor(...brand.charcoal);
  } else {
    // Show up to the last 5 scans in history log
    const historyBody = history.slice(0, 5).map(record => [
      record.timestamp,
      record.projectName,
      `${record.filesCount} resources`,
      `${record.stats.activeIssuesCount} issues`,
      `${record.stats.securityScore.toFixed(1)}%`
    ]);

    autoTable(doc, {
      startY: y,
      head: [['Scanning Date Stamp', 'Project Folder Context', 'Workspace Files', 'Unmitigated Issues', 'Project Security Score']],
      body: historyBody,
      theme: 'grid',
      styles: { fontSize: 8, cellPadding: 4 },
      headStyles: { fillColor: brand.slate, fontStyle: 'bold' },
      columnStyles: { 4: { fontStyle: 'bold', halign: 'right' } }
    });
    y = doc.lastAutoTable.finalY + 12;
  }

  // ==========================================
  // SECTION 9: FALSE POSITIVE ANNOTATIONS LOG
  // ==========================================
  y = checkHeightAndPageBreak(doc, 60, y);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('9. FALSE POSITIVE ANNOTATIONS LOG', 14, y);
  y += 5;

  if (fpFlags.length === 0) {
    doc.setFontSize(9);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(...brand.gray);
    doc.text('No false positive override annotations have been logged. All breaches remain active.', 14, y);
    y += 10;
    doc.setTextColor(...brand.charcoal);
  } else {
    const fpBody = fpFlags.map(key => {
      const [fileName, ruleId, line] = key.split(':');
      const annotation = fpAnnotations[key];
      return [
        fileName.split('/').pop(),
        ruleId,
        `Line ${line}`,
        annotation && annotation.reason ? annotation.reason : 'No justification entered'
      ];
    });

    autoTable(doc, {
      startY: y,
      head: [['Exempted Source File', 'Flagged Rule ID', 'Location', 'Developer Rationale & Override Justification']],
      body: fpBody,
      theme: 'striped',
      styles: { fontSize: 7.5, cellPadding: 3.5 },
      headStyles: { fillColor: brand.slate, fontStyle: 'bold' }
    });
    y = doc.lastAutoTable.finalY + 12;
  }

  // ==========================================
  // SECTION 10: DEVELOPER AUDIT AND ACTIVITY LOG
  // ==========================================
  y = checkHeightAndPageBreak(doc, 60, y);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('10. DEVELOPER AUDIT AND ACTIVITY LOG', 14, y);
  y += 5;

  if (activity.length === 0) {
    doc.setFontSize(9);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(...brand.gray);
    doc.text('No transaction events recorded in the secure audit sandbox registry.', 14, y);
    y += 10;
    doc.setTextColor(...brand.charcoal);
  } else {
    // Show up to the last 12 events to preserve document bounds cleanly
    const auditBody = activity.slice(0, 12).map(log => [
      log.timestamp,
      log.action,
      log.verificationHash || 'JSEC-PENDING'
    ]);

    autoTable(doc, {
      startY: y,
      head: [['Audit Timestamp', 'Transaction Action Description', 'Security Verification Hash Signature']],
      body: auditBody,
      theme: 'grid',
      styles: { fontSize: 7.5, cellPadding: 3.5 },
      headStyles: { fillColor: brand.slate, fontStyle: 'bold' },
      columnStyles: { 2: { fontStyle: 'bold', fontName: 'courier', cellWidth: 40 } }
    });
    y = doc.lastAutoTable.finalY + 12;
  }

  // Footer Setup on each page
  const totalPages = doc.internal.getNumberOfPages();
  for (let pageNum = 1; pageNum <= totalPages; pageNum++) {
    doc.setPage(pageNum);
    doc.setFontSize(7.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...brand.gray);
    
    // Page count indicator
    doc.text(`CONFIDENTIAL SECURITY AUDIT REPORT  -  PAGE ${pageNum} OF ${totalPages}`, 14, 287);
    doc.text('GENERATED ELECTRONICALLY VIA JSENTINEL ENGINE', 142, 287);
  }

  // Save the generated document using date tokens
  const docDate = new Date().toISOString().split('T')[0];
  doc.save(`JSENTINEL-SECURITY-AUDIT-REPORT-${docDate}.pdf`);
};
