import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { getGuidance, GUIDANCE_DISCLAIMER } from '../data/guidanceCatalog';

// Safely parse fpKey with full support for Windows drive letters and colons in file paths
const parseFpKey = (key) => {
  if (!key) return { fileName: '', ruleId: '', line: '', col: '' };
  const lastColon = key.lastIndexOf(':');
  if (lastColon === -1) return { fileName: key, ruleId: '', line: '', col: '' };
  const col = key.substring(lastColon + 1);
  const remainder1 = key.substring(0, lastColon);
  const secondLastColon = remainder1.lastIndexOf(':');
  if (secondLastColon === -1) return { fileName: remainder1, ruleId: '', line: col, col: '' };
  const line = remainder1.substring(secondLastColon + 1);
  const remainder2 = remainder1.substring(0, secondLastColon);
  const thirdLastColon = remainder2.lastIndexOf(':');
  if (thirdLastColon === -1) return { fileName: remainder2, ruleId: line, line: col, col: '' };
  const ruleId = remainder2.substring(thirdLastColon + 1);
  const fileName = remainder2.substring(0, thirdLastColon);
  return { fileName, ruleId, line, col };
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
    const shortName = res.fileName.replace(/\\/g, '/').split('/').pop();

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
  const triggeredGuidanceMap = new Map();

  results.forEach(res => {
    if (res.issues) {
      res.issues.forEach(issue => {
        const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
        if (fpFlags.includes(fpKey)) return;

        activeIssuesList.push({
          file: res.fileName.replace(/\\/g, '/').split('/').pop(),
          line: issue.line,
          id: issue.id,
          guidanceId: issue.guidanceId || issue.id,
          severity: issue.severity,
          message: issue.message
        });

        const gId = issue.guidanceId || issue.id;
        if (!triggeredGuidanceMap.has(gId)) {
          triggeredGuidanceMap.set(gId, getGuidance(issue));
        }
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
      issue.message
    ]);

    autoTable(doc, {
      startY: y,
      head: [['Severity', 'Rule ID', 'Location', 'Resource', 'Breach Description']],
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
      columnStyles: { 0: { cellWidth: 20 }, 1: { cellWidth: 25 }, 2: { cellWidth: 15 }, 3: { cellWidth: 35 } }
    });
    y = doc.lastAutoTable.finalY + 12;
  }

  // ==========================================
  // SECTION 6: SECURITY REMEDIATION GUIDANCE
  // ==========================================
  y = checkHeightAndPageBreak(doc, 60, y);
  doc.setTextColor(...brand.charcoal);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('6. SECURITY REMEDIATION GUIDANCE', 14, y);
  y += 6;

  if (triggeredGuidanceMap.size === 0) {
    doc.setFontSize(9);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(...brand.gray);
    doc.text('No remediation guidelines are required. The active codebase does not trigger unmitigated rules.', 14, y);
    y += 10;
  } else {
    triggeredGuidanceMap.forEach((record) => {
      if (!record) return;

      y = checkHeightAndPageBreak(doc, 55, y);

      // Header Banner / Title
      doc.setFontSize(9.5);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...brand.maroon);
      const guidanceId = record?.guidanceId || 'GENERAL';
      const recordTitle = (record?.title || 'Security Recommendation').toUpperCase();
      const headerTitle = `REMEDIATION GUIDANCE: ${guidanceId} - ${recordTitle}`;
      doc.text(headerTitle, 14, y);
      y += 4.5;

      // Metadata: Category and Scope
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...brand.gray);
      const categoryStr = record?.category || 'General Security';
      const scopeStr = (record?.scope || 'cross-boundary').toUpperCase();
      doc.text(`Category: ${categoryStr} | Scope: ${scopeStr}`, 14, y);
      y += 5.5;

      // Recommended Action
      y = checkHeightAndPageBreak(doc, 20, y);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...brand.charcoal);
      doc.text('RECOMMENDED ACTION:', 14, y);
      y += 3.5;
      doc.setFont('helvetica', 'normal');
      const actionText = record?.recommendedAction || record?.shortAction || 'Review the flagged code against project security requirements.';
      const actionLines = doc.splitTextToSize(actionText, 182);
      doc.text(actionLines, 14, y);
      y += (actionLines.length * 3.8) + 3;

      // Why review this / Risk Context
      y = checkHeightAndPageBreak(doc, 25, y);
      doc.setFont('helvetica', 'bold');
      doc.text('WHY REVIEW THIS (SECURITY RISK):', 14, y);
      y += 3.5;
      doc.setFont('helvetica', 'normal');
      const riskText = record?.risk || 'Static analysis flagged an unclassified code pattern that may warrant security review.';
      const riskLines = doc.splitTextToSize(riskText, 182);
      doc.text(riskLines, 14, y);
      y += (riskLines.length * 3.8) + 3;

      // Static Analysis Limitations (cannotInfer)
      y = checkHeightAndPageBreak(doc, 25, y);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...brand.maroon);
      doc.text('STATIC ANALYSIS LIMITATIONS (WHAT JSENTINEL CANNOT DETERMINE):', 14, y);
      y += 3.5;
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...brand.charcoal);
      const cannotInferText = record?.cannotInfer || 'JSentinel cannot determine application intent, runtime context, or environmental security controls.';
      const cannotInferLines = doc.splitTextToSize(cannotInferText, 182);
      doc.text(cannotInferLines, 14, y);
      y += (cannotInferLines.length * 3.8) + 3;

      // Remediation Approaches
      if (record.approaches && record.approaches.length > 0) {
        y = checkHeightAndPageBreak(doc, 25, y);
        doc.setFont('helvetica', 'bold');
        doc.text('REMEDIATION APPROACHES:', 14, y);
        y += 3.5;
        doc.setFont('helvetica', 'normal');
        record.approaches.forEach(appr => {
          const apprText = typeof appr === 'string' ? appr : `${appr.title}: ${appr.description}`;
          const apprLines = doc.splitTextToSize(`• ${apprText}`, 178);
          y = checkHeightAndPageBreak(doc, (apprLines.length * 3.8) + 2, y);
          doc.text(apprLines, 16, y);
          y += (apprLines.length * 3.8) + 1.5;
        });
        y += 1.5;
      }

      // Verification Procedures
      if (record.verifySteps && record.verifySteps.length > 0) {
        y = checkHeightAndPageBreak(doc, 20, y);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...brand.charcoal);
        doc.text('VERIFICATION PROCEDURES:', 14, y);
        y += 3.5;
        doc.setFont('helvetica', 'normal');
        record.verifySteps.forEach(step => {
          const stepLines = doc.splitTextToSize(`[ ] ${step}`, 178);
          y = checkHeightAndPageBreak(doc, (stepLines.length * 3.8) + 2, y);
          doc.text(stepLines, 16, y);
          y += (stepLines.length * 3.8) + 1.5;
        });
        y += 1.5;
      }

      // Authoritative References (if present)
      if (record.references && record.references.length > 0) {
        y = checkHeightAndPageBreak(doc, 15, y);
        doc.setFontSize(7.5);
        doc.setFont('helvetica', 'bold');
        doc.text('AUTHORITATIVE REFERENCES:', 14, y);
        y += 3.5;
        doc.setFont('helvetica', 'normal');
        record.references.forEach(ref => {
          const refLines = doc.splitTextToSize(`- ${ref.title}: ${ref.url}`, 178);
          y = checkHeightAndPageBreak(doc, (refLines.length * 3.5) + 2, y);
          doc.text(refLines, 16, y);
          y += (refLines.length * 3.5) + 1.2;
        });
        y += 1.5;
      }

      // Mandatory Educational Disclaimer
      y = checkHeightAndPageBreak(doc, 14, y);
      doc.setFont('helvetica', 'italic');
      doc.setFontSize(7);
      doc.setTextColor(...brand.gray);
      const discLines = doc.splitTextToSize(GUIDANCE_DISCLAIMER, 182);
      doc.text(discLines, 14, y);
      y += (discLines.length * 3.2) + 6;
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...brand.charcoal);
    });
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
    'A01:2021-Broken Access Control': 0,
    'A02:2021-Cryptographic Failures': 0,
    'A03:2021-Injection': 0,
    'A05:2021-Security Misconfiguration': 0,
    'A06:2021-Vulnerable and Outdated Components': 0,
    'A07:2021-Identification and Authentication Failures': 0,
    'A08:2021-Software and Data Integrity Failures': 0,
    'A10:2021-Server-Side Request Forgery (SSRF)': 0
  };

  results.forEach(res => {
    if (res.issues) {
      res.issues.forEach(issue => {
        const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
        if (fpFlags.includes(fpKey)) return;

        const match = issue.id.match(/^OWASP-(A\d+)/);
        const catCode = match ? match[1] : '';
        if (catCode === 'A01') owaspData['A01:2021-Broken Access Control']++;
        else if (catCode === 'A02') owaspData['A02:2021-Cryptographic Failures']++;
        else if (catCode === 'A03') owaspData['A03:2021-Injection']++;
        else if (catCode === 'A05') owaspData['A05:2021-Security Misconfiguration']++;
        else if (catCode === 'A06') owaspData['A06:2021-Vulnerable and Outdated Components']++;
        else if (catCode === 'A07') owaspData['A07:2021-Identification and Authentication Failures']++;
        else if (catCode === 'A08') owaspData['A08:2021-Software and Data Integrity Failures']++;
        else if (catCode === 'A10') owaspData['A10:2021-Server-Side Request Forgery (SSRF)']++;
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
      const { fileName, ruleId, line } = parseFpKey(key);
      const annotation = fpAnnotations[key];
      const shortName = fileName.replace(/\\/g, '/').split('/').pop();
      return [
        shortName || fileName,
        ruleId,
        line ? `Line ${line}` : 'N/A',
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
