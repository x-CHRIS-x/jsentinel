/**
 * JSentinel Security Scan Exporter
 * 
 * Generates a clean, developer-friendly flat JSON export of security scan results.
 */

export const generateJSONReport = (results, stats, owaspCategories, fpFlags) => {
  // Extract project name from first file path
  let projectName = "JSentinel Scan";
  const firstResult = results.find(r => r.fileName);
  if (firstResult) {
    const parts = firstResult.fileName.replace(/\\/g, '/').split('/');
    if (parts.length > 1) {
      projectName = parts[0];
    }
  }

  // Map issues to flat structure including file name
  const flatIssues = [];
  results.forEach(res => {
    if (res.issues) {
      res.issues.forEach(issue => {
        const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
        const isFP = fpFlags.includes(fpKey);

        flatIssues.push({
          fileName: res.fileName,
          id: issue.id,
          severity: issue.severity,
          line: issue.line,
          column: issue.column,
          message: issue.message,
          suggestion: issue.suggestion,
          cvssBaseScore: issue.cvssBaseScore || null,
          cvssVector: issue.cvssVector || '',
          isFalsePositive: isFP
        });
      });
    }
  });

  // Map files matrix
  const fileSummary = results.map(res => {
    let filePenalty = 0;
    let issuesCount = 0;
    let activeCount = 0;

    if (res.issues) {
      issuesCount = res.issues.length;
      res.issues.forEach(issue => {
        const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
        if (fpFlags.includes(fpKey)) return;
        activeCount++;
        
        if (issue.severity === 'CRITICAL') filePenalty += 20.0;
        else if (issue.severity === 'HIGH') filePenalty += 10.0;
        else if (issue.severity === 'MEDIUM') filePenalty += 5.0;
        else if (issue.severity === 'LOW') filePenalty += 1.0;
      });
    }

    return {
      fileName: res.fileName,
      success: res.success,
      hasError: res.hasError,
      issuesCount,
      activeIssuesCount: activeCount,
      score: Math.max(0, 100 - filePenalty)
    };
  });

  const report = {
    meta: {
      projectName,
      scannedAt: new Date().toISOString(),
      scannerEngine: "JSentinel Core v1.0.0"
    },
    summary: {
      totalIssues: stats.totalIssues,
      activeIssuesCount: stats.activeIssuesCount,
      criticalIssues: stats.criticalIssues,
      highIssues: stats.highIssues,
      mediumIssues: stats.mediumIssues,
      lowIssues: stats.lowIssues,
      securityScore: stats.securityScore
    },
    owaspProfile: owaspCategories.map(cat => ({
      category: cat.name.split(':')[0],
      name: cat.name,
      count: cat.count,
      severity: cat.severity
    })),
    files: fileSummary,
    issues: flatIssues
  };

  // Convert to JSON and trigger browser download
  const jsonString = JSON.stringify(report, null, 2);
  const blob = new Blob([jsonString], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  
  // Format file name
  const formattedProjName = projectName.toLowerCase().replace(/[^a-z0-9]/g, '_');
  link.download = `jsentinel_security_report_${formattedProjName}.json`;
  
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};
