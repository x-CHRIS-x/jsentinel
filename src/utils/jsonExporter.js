import { calculateStats, isAdvisory, getScanVersions, getOwaspCategories } from './findingPolicy.js';
/**
 * JSentinel Security Scan Exporter
 * 
 * Generates a clean, developer-friendly JSON report object and handles browser export.
 * Decouples pure data formatting (formatJSONReport) from browser DOM download (generateJSONReport).
 */

import { getGuidance, FALLBACK_GUIDANCE, GUIDANCE_DISCLAIMER } from '../data/guidanceCatalog.js';

/**
 * Pure data formatting function that converts scan results into a structured report object.
 * 
 * @param {Array} results - Scanner results per file.
 * @param {Object} stats - Aggregated scan statistics.
 * @param {Array} owaspCategories - OWASP category statistics.
 * @param {Array} [fpFlags=[]] - List of false-positive finding keys.
 * @returns {Object} Structured report object.
 */
export const formatJSONReport = (results = [], stats = {}, owaspCategories = [], fpFlags = []) => {
  // Retain legacy positional arguments for caller compatibility. Report metrics are
  // intentionally recomputed below so stale caller summaries cannot classify advisories.
  void stats;
  void owaspCategories;
  const safeResults = Array.isArray(results) ? results : [];
  const safeFpFlags = Array.isArray(fpFlags) ? fpFlags : [];
  // Recompute from findings so stale caller totals cannot include advisories.
  const safeStats = calculateStats(safeResults, safeFpFlags);
  const safeOwasp = getOwaspCategories(safeResults, safeFpFlags);

  // Extract project name from first file path
  let projectName = "JSentinel Scan";
  const firstResult = safeResults.find(r => r && r.fileName);
  if (firstResult) {
    const parts = firstResult.fileName.replace(/\\/g, '/').split('/');
    if (parts.length > 1) {
      projectName = parts[0];
    }
  }

  // Map issues to flat structure including file name, guidanceId, and sourceLine
  const flatIssues = [];
  safeResults.forEach(res => {
    if (res && res.issues) {
      res.issues.forEach(issue => {
        const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
        const isFP = safeFpFlags.includes(fpKey);
        const guidance = getGuidance(issue);

        flatIssues.push({
          fileName: res.fileName,
          id: issue.id,
          guidanceId: issue.guidanceId || issue.id,
          severity: issue.severity,
          findingType: issue.findingType || 'vulnerability-pattern',
          eligibleForVulnerabilityMetrics: !isAdvisory(issue),
          line: issue.line,
          column: issue.column,
          sourceLine: issue.sourceLine || '',
          message: issue.message,
          suggestion: guidance === FALLBACK_GUIDANCE ? (issue.suggestion || '') : guidance.recommendedAction,
          cvssBaseScore: issue.cvssBaseScore || null,
          cvssVector: issue.cvssVector || '',
          isFalsePositive: isFP
        });
      });
    }
  });

  // Map files matrix
  const fileSummary = safeResults.map(res => {
    let filePenalty = 0;
    let issuesCount = 0;
    let activeCount = 0;

    if (res && res.issues) {
      issuesCount = res.issues.filter(issue => !isAdvisory(issue)).length;
      res.issues.forEach(issue => {
        const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
        if (safeFpFlags.includes(fpKey) || isAdvisory(issue)) return;
        activeCount++;
        
        if (issue.severity === 'CRITICAL') filePenalty += 20.0;
        else if (issue.severity === 'HIGH') filePenalty += 10.0;
        else if (issue.severity === 'MEDIUM') filePenalty += 5.0;
        else if (issue.severity === 'LOW') filePenalty += 1.0;
      });
    }

    return {
      fileName: res ? res.fileName : '',
      success: res ? res.success : false,
      hasError: res ? res.hasError : false,
      scannerVersion: res?.scannerVersion || 'Legacy / version not recorded',
      advisoryCount: calculateStats([res]).advisoryCount,
      issuesCount,
      activeIssuesCount: activeCount,
      score: Math.max(0, 100 - filePenalty)
    };
  });

  return {
    meta: {
      projectName,
      scannedAt: new Date().toISOString(),
      scannerEngine: getScanVersions(safeResults).join(', ') || 'No scan results',
      scannerVersions: getScanVersions(safeResults),
      exportFormatVersion: 2,
      disclaimer: GUIDANCE_DISCLAIMER
    },
    summary: {
      advisoryCount: safeStats.advisoryCount,
      activeAdvisoryCount: safeStats.activeAdvisoryCount,
      totalIssues: safeStats.totalIssues ?? 0,
      activeIssuesCount: safeStats.activeIssuesCount ?? 0,
      criticalIssues: safeStats.criticalIssues ?? 0,
      highIssues: safeStats.highIssues ?? 0,
      mediumIssues: safeStats.mediumIssues ?? 0,
      lowIssues: safeStats.lowIssues ?? 0,
      securityScore: safeStats.securityScore ?? 100
    },
    owaspProfile: safeOwasp.map(cat => ({
      category: cat && cat.name ? cat.name.split(':')[0] : '',
      name: (cat && cat.name) || '',
      count: (cat && cat.count) || 0,
      advisoryCount: cat.advisoryCount || 0,
      severity: (cat && cat.severity) || 'LOW'
    })),
    files: fileSummary,
    issues: flatIssues
  };
};

/**
 * Formats the report and triggers a browser file download.
 * 
 * @param {Array} results - Scanner results per file.
 * @param {Object} stats - Aggregated scan statistics.
 * @param {Array} owaspCategories - OWASP category statistics.
 * @param {Array} [fpFlags=[]] - List of false-positive finding keys.
 */
export const generateJSONReport = (results, stats, owaspCategories, fpFlags = []) => {
  const report = formatJSONReport(results, stats, owaspCategories, fpFlags);

  // Convert to JSON and trigger browser download
  const jsonString = JSON.stringify(report, null, 2);
  const blob = new Blob([jsonString], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  
  // Format file name
  const formattedProjName = report.meta.projectName.toLowerCase().replace(/[^a-z0-9]/g, '_');
  link.download = `jsentinel_security_report_${formattedProjName}.json`;
  
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};
