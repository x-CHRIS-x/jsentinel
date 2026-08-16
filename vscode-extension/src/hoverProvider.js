/**
 * JSentinel Rich Hover Provider
 * 
 * Displays beautifully formatted Markdown hover cards when the user hovers
 * over lines flagged with security vulnerabilities. Instead of cramming
 * everything into a single diagnostic message string, this provider renders
 * structured, readable cards with clear visual hierarchy.
 * 
 * Each card includes:
 *   - Severity badge with emoji indicator
 *   - OWASP category identification
 *   - Confidence level indicator
 *   - CVSS v3.1 base score and vector
 *   - What the vulnerability is and why it is dangerous
 *   - How to fix it
 *   - Link to OWASP documentation
 */

const vscode = require('vscode');

// ──────────────────────────────────────────────
// OWASP Category Metadata
// Maps rule ID prefixes to human-readable names
// ──────────────────────────────────────────────
const owaspCategories = {
  'A1':  { name: 'Injection', icon: '💉', url: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'A2':  { name: 'Broken Authentication', icon: '🔓', url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/' },
  'A3':  { name: 'Sensitive Data Exposure', icon: '🔍', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'A5':  { name: 'Broken Access Control', icon: '🚪', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
  'A6':  { name: 'Security Misconfiguration', icon: '⚙️', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  'A7':  { name: 'Cross-Site Scripting (XSS)', icon: '🌐', url: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'A8':  { name: 'Software & Data Integrity', icon: '🔗', url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  'A9':  { name: 'Vulnerable Components', icon: '📦', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  'A10': { name: 'Server-Side Request Forgery', icon: '🌍', url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/' },
};

// ──────────────────────────────────────────────
// Severity display configuration
// ──────────────────────────────────────────────
const severityConfig = {
  'CRITICAL': { emoji: '🔴', label: 'CRITICAL', color: 'Red' },
  'HIGH':     { emoji: '🟠', label: 'HIGH',     color: 'Orange' },
  'MEDIUM':   { emoji: '🟡', label: 'MEDIUM',   color: 'Yellow' },
  'LOW':      { emoji: '🔵', label: 'LOW',      color: 'Blue' },
};

// ──────────────────────────────────────────────
// Confidence level display
// ──────────────────────────────────────────────
const confidenceConfig = {
  'HIGH':   { emoji: '🟢', description: 'Almost certainly a real vulnerability' },
  'MEDIUM': { emoji: '🟡', description: 'Likely real, but context matters' },
  'LOW':    { emoji: '⚪', description: 'Informational: verify manually' },
};

// ──────────────────────────────────────────────
// Risk explanations per rule ID
// Explains WHY this pattern is dangerous
// ──────────────────────────────────────────────
const riskExplanations = {
  'OWASP-A1-001': 'eval() executes arbitrary strings as JavaScript code. An attacker who controls the input can run any code in the application context, leading to full compromise.',
  'OWASP-A1-002': 'When setTimeout/setInterval receives a string, it acts like eval(), parsing and executing the string as code. This opens the same arbitrary code execution risks.',
  'OWASP-A1-003': 'The Function constructor creates a new function from a string argument, identical in risk to eval(). Attackers can inject executable code through the string parameter.',
  'OWASP-A1-004': 'Assigning a template literal with variables to innerHTML allows attackers to inject malicious HTML/JavaScript if they control any of the interpolated values.',
  'OWASP-A1-005': 'Setting innerHTML to a function\'s return value is dangerous if the function processes any user input. The returned HTML could contain injected script tags.',
  'OWASP-A2-001': 'Hardcoded passwords in source code are exposed to anyone with repository access. They cannot be rotated without a code change and deployment.',
  'OWASP-A2-002': 'localStorage is accessible to any JavaScript on the page. If an XSS vulnerability exists, an attacker\'s script can steal all stored tokens instantly.',
  'OWASP-A2-003': 'Cookies without HttpOnly flag can be read by JavaScript (enabling XSS theft). Without Secure flag, they transmit over unencrypted HTTP connections.',
  'OWASP-A2-004': 'Math.random() produces predictable pseudo-random numbers. An attacker can predict future values and forge tokens, OTPs, or session identifiers.',
  'OWASP-A2-005': 'HTTP transmits data as plaintext. Anyone on the network path (WiFi, ISP, proxy) can read or modify the traffic, including credentials and session tokens.',
  'OWASP-A3-001': 'Hardcoded secrets (JWT tokens, AWS keys, IPs) in source code are permanently exposed in version control history, even if later removed.',
  'OWASP-A3-002': 'API keys and secrets hardcoded in variables can be extracted from client-side bundles, version control, or build artifacts by anyone with access.',
  'OWASP-A3-003': 'Credentials in URL query strings are logged in browser history, server logs, proxy logs, and the Referer header, creating multiple exposure vectors.',
  'OWASP-A5-001': 'Setting location.href to a user-controlled variable lets attackers craft URLs that redirect victims to phishing sites or malicious pages.',
  'OWASP-A5-002': 'Client-side role checks can be trivially bypassed using browser DevTools. An attacker can modify variables or skip conditions to access restricted features.',
  'OWASP-A6-001': 'Console.log statements with sensitive variables persist in production browser consoles. Any user or attacker can open DevTools and read the logged secrets.',
  'OWASP-A6-002': 'A wildcard CORS policy allows any website to make authenticated requests to your API, enabling cross-site data theft from any malicious page.',
  'OWASP-A6-003': 'Logging entire request, user, or session objects to the console may expose passwords, tokens, personal data, and internal system details.',
  'OWASP-A6-004': 'Express without helmet middleware leaves the application missing critical security headers (CSP, X-Frame-Options, HSTS, etc.), increasing attack surface.',
  'OWASP-A7-001': 'Direct innerHTML assignment interprets the string as HTML markup. If any part of the string comes from user input, it can execute arbitrary scripts.',
  'OWASP-A7-002': 'document.write() injects raw HTML into the page during parsing. It has no sanitization and can completely overwrite page content with malicious code.',
  'OWASP-A7-003': 'React\'s dangerouslySetInnerHTML bypasses React\'s built-in XSS protection. If the HTML content is user-controlled, scripts will execute in the browser.',
  'OWASP-A8-001': 'JSON.parse() on untrusted input can produce unexpected object shapes. Without validation, downstream code may behave unpredictably or insecurely.',
  'OWASP-A8-002': 'Modifying __proto__ or constructor.prototype changes the behavior of all objects sharing that prototype, enabling denial of service or code execution.',
  'OWASP-A8-003': 'Object.assign() merges all properties from the source. If the source is user-controlled, attackers can inject __proto__ or other dangerous properties.',
  'OWASP-A9-001': 'This library has known CVEs or common misuse patterns. Using outdated or misconfigured versions can introduce exploitable vulnerabilities into your application.',
  'OWASP-A10-001': 'When fetch/axios URLs are user-controlled, attackers can make your server request internal resources (databases, admin panels, cloud metadata endpoints).'
};

/**
 * Extracts the OWASP category prefix from a rule ID.
 * e.g., 'OWASP-A1-001' → 'A1', 'OWASP-A10-001' → 'A10'
 */
const getCategoryPrefix = (ruleId) => {
  if (!ruleId) return null;
  const match = ruleId.match(/OWASP-(A\d+)/);
  return match ? match[1] : null;
};

/**
 * Formats a CVSS base score into a human-readable severity band.
 */
const formatCvssScore = (score) => {
  if (score >= 9.0) return `\`${score}\`: Critical`;
  if (score >= 7.0) return `\`${score}\`: High`;
  if (score >= 4.0) return `\`${score}\`: Medium`;
  if (score >= 0.1) return `\`${score}\`: Low`;
  return `\`${score}\``;
};

/**
 * Builds a single rich Markdown hover card for one issue.
 */
const buildHoverCard = (issue) => {
  const severity = severityConfig[issue.severity] || severityConfig['MEDIUM'];
  const confidence = confidenceConfig[issue.confidence] || confidenceConfig['MEDIUM'];
  const categoryPrefix = getCategoryPrefix(issue.id);
  const category = categoryPrefix ? owaspCategories[categoryPrefix] : null;
  const riskExplanation = riskExplanations[issue.id] || '';

  const lines = [];

  // ── Header: Severity + Rule ID ──
  lines.push(`## ${severity.emoji} ${severity.label}: \`${issue.id}\``);
  lines.push('');

  // ── OWASP Category ──
  if (category) {
    lines.push(`${category.icon} **OWASP Category:** [${category.name}](${category.url})`);
    lines.push('');
  }

  // ── Divider ──
  lines.push('---');
  lines.push('');

  // ── What was detected ──
  lines.push(`### 🔎 What was detected`);
  lines.push('');
  lines.push(issue.message);
  lines.push('');

  // ── Why this is dangerous ──
  if (riskExplanation) {
    lines.push(`### ⚠️ Why this is dangerous`);
    lines.push('');
    lines.push(riskExplanation);
    lines.push('');
  }

  // ── How to fix it ──
  if (issue.suggestion) {
    lines.push(`### 💡 How to fix`);
    lines.push('');
    lines.push(issue.suggestion);
    lines.push('');
  }

  // ── Divider ──
  lines.push('---');
  lines.push('');

  // ── Metrics row ──
  const metricsRow = [];

  // Confidence
  metricsRow.push(`${confidence.emoji} **Confidence:** ${issue.confidence}: *${confidence.description}*`);

  // CVSS Score
  if (issue.cvssBaseScore !== undefined) {
    metricsRow.push(`📊 **CVSS Score:** ${formatCvssScore(issue.cvssBaseScore)}`);
  }

  // CVSS Vector
  if (issue.cvssVector) {
    metricsRow.push(`🧮 **Vector:** \`${issue.cvssVector}\``);
  }

  lines.push(metricsRow.join('  \n'));
  lines.push('');

  return lines.join('\n');
};

/**
 * Creates the JSentinel Hover Provider.
 * 
 * @param {Map<string, Array>} issuesMap - A Map keyed by file URI string,
 *   where each value is an array of scanner issue objects for that file.
 * @returns {vscode.HoverProvider}
 */
const createHoverProvider = (issuesMap, getFpFlags = () => []) => {
  return {
    provideHover(document, position) {
      const fileKey = document.uri.toString();
      const fileIssues = issuesMap.get(fileKey);

      if (!fileIssues || fileIssues.length === 0) {
        return null;
      }

      // Find all issues on this line (1-indexed in scanner, position.line is 0-indexed)
      const hoveredLine = position.line + 1;
      const fpFlags = getFpFlags();
      const lineIssues = fileIssues.filter(issue => {
        if (issue.line !== hoveredLine) return false;
        const fpKey = `${document.fileName}:${issue.id}:${issue.line}:${issue.column}`;
        return !fpFlags.includes(fpKey);
      });

      if (lineIssues.length === 0) {
        return null;
      }

      // Build combined hover content for all issues on this line
      const cards = lineIssues.map(buildHoverCard);
      
      // If multiple issues on same line, separate with a thick divider
      const combinedMarkdown = cards.join('\n---\n---\n\n');

      const markdownContent = new vscode.MarkdownString(combinedMarkdown);
      markdownContent.isTrusted = true;
      markdownContent.supportHtml = false;

      // Return hover spanning the entire line for easy trigger area
      const lineText = document.lineAt(position.line).text;
      const startCol = lineText.search(/\S/);
      const range = new vscode.Range(
        new vscode.Position(position.line, startCol >= 0 ? startCol : 0),
        new vscode.Position(position.line, lineText.length)
      );

      return new vscode.Hover(markdownContent, range);
    }
  };
};

module.exports = { createHoverProvider };
