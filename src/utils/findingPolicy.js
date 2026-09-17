// New advisories use an explicit marker. Legacy A06 records retain their original meaning.
const SCANNER_VERSION = 'JSentinel browser-scope v2';
const isAdvisory = issue => issue?.findingType === 'advisory';
const calculateStats = (results = [], fpFlags = []) => {
  const stats = { totalIssues: 0, activeIssuesCount: 0, advisoryCount: 0, activeAdvisoryCount: 0,
    criticalIssues: 0, highIssues: 0, mediumIssues: 0, lowIssues: 0, securityScore: 100 };
  const weights = { CRITICAL: 20, HIGH: 10, MEDIUM: 5, LOW: 1 };
  let penalty = 0;
  results.forEach(res => (res?.issues || []).forEach(issue => {
    const exempt = fpFlags.includes(`${res.fileName}:${issue.id}:${issue.line}:${issue.column}`);
    if (isAdvisory(issue)) {
      stats.advisoryCount++;
      if (!exempt) stats.activeAdvisoryCount++;
      return;
    }
    stats.totalIssues++;
    if (exempt) return;
    stats.activeIssuesCount++;
    const key = `${issue.severity?.toLowerCase()}Issues`;
    if (key in stats) stats[key]++;
    penalty += weights[issue.severity] || 0;
  }));
  stats.securityScore = Math.max(0, 100 - penalty);
  return stats;
};
const getScanVersions = results => [...new Set(results.map(res => res?.scannerVersion || 'Legacy / version not recorded'))];
const getOwaspCategories = (results = [], fpFlags = []) => {
  const names = { A01: 'Broken Access Control', A02: 'Cryptographic Failures', A03: 'Injection',
    A05: 'Security Misconfiguration', A06: 'Vulnerable and Outdated Components',
    A07: 'Identification and Authentication Failures', A08: 'Software and Data Integrity Failures' };
  if (results.some(res => (res?.issues || []).some(issue => issue.id?.startsWith('OWASP-A10-')))) {
    names.A10 = 'Server-Side Request Forgery (SSRF) (historical)';
  }
  const levels = { A01: 'HIGH', A02: 'CRITICAL', A03: 'HIGH', A05: 'MEDIUM', A06: 'INFORMATIONAL', A07: 'HIGH', A08: 'MEDIUM', A10: 'HIGH' };
  return Object.entries(names).map(([code, name]) => {
    let count = 0, advisoryCount = 0;
    results.forEach(res => (res?.issues || []).forEach(issue => {
      if (!issue.id?.startsWith(`OWASP-${code}-`) || fpFlags.includes(`${res.fileName}:${issue.id}:${issue.line}:${issue.column}`)) return;
      if (isAdvisory(issue)) advisoryCount++; else count++;
    }));
    return { name: `${code}:2021-${name}`, count, advisoryCount, severity: code === 'A06' && count ? 'MEDIUM' : levels[code] };
  });
};

export { SCANNER_VERSION, isAdvisory, calculateStats, getScanVersions, getOwaspCategories };
