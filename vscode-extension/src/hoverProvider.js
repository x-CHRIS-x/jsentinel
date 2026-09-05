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
const { getGuidance, GUIDANCE_DISCLAIMER } = require('./data/guidanceCatalog');

// ──────────────────────────────────────────────
// OWASP Category Metadata
// Maps rule ID prefixes to human-readable names
// ──────────────────────────────────────────────
const owaspCategories = {
  'A01': { name: 'A01:2021-Broken Access Control', icon: '🚪', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
  'A02': { name: 'A02:2021-Cryptographic Failures', icon: '🔒', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'A03': { name: 'A03:2021-Injection', icon: '💉', url: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'A05': { name: 'A05:2021-Security Misconfiguration', icon: '⚙️', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  'A06': { name: 'A06:2021-Vulnerable and Outdated Components', icon: '📦', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  'A07': { name: 'A07:2021-Identification and Authentication Failures', icon: '🔓', url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/' },
  'A08': { name: 'A08:2021-Software and Data Integrity Failures', icon: '🔗', url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  'A10': { name: 'A10:2021-Server-Side Request Forgery (SSRF)', icon: '🌍', url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/' },
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

/**
 * Extracts the OWASP category prefix from a rule ID.
 * e.g., 'OWASP-A01-001' → 'A01', 'OWASP-A10-001' → 'A10'
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
  const guidance = getGuidance(issue);
  const scopeLabel = guidance.scope === 'browser' ? 'Browser Scope' : guidance.scope === 'server' ? 'Server Scope' : 'Cross-Boundary Scope';
  const contextNote = guidance.scope === 'cross-boundary' ? ' | **Context:** `Requires project context`' : '';

  const lines = [];

  // ── Header: Severity + Rule ID + Title ──
  lines.push(`## ${severity.emoji} ${severity.label}: \`${issue.id}\` - ${guidance.title}`);
  lines.push('');

  // ── OWASP Category & Scope ──
  if (category) {
    lines.push(`${category.icon} **OWASP Category:** [${category.name}](${category.url}) | **Scope:** \`${scopeLabel}\`${contextNote}`);
    lines.push('');
  }

  // ── Divider ──
  lines.push('---');
  lines.push('');

  // ── Suggested Next Step (Visual Priority) ──
  lines.push('### 💡 Suggested Next Step');
  lines.push('');
  lines.push(`**${guidance.shortAction || guidance.recommendedAction}**`);
  lines.push('');
  if (issue.sourceLine) {
    lines.push(`**Detected code (Line ${issue.line}):**`);
    lines.push('```javascript');
    lines.push(issue.sourceLine);
    lines.push('```');
  } else {
    lines.push(`*Detected (Line ${issue.line}):* ${issue.message}`);
  }
  lines.push('');

  // ── Why This Was Flagged ──
  lines.push('### 🔎 Why This Was Flagged');
  lines.push('');
  lines.push(guidance.risk);
  lines.push('');

  // ── Choose an Approach ──
  if (guidance.approaches && Array.isArray(guidance.approaches) && guidance.approaches.length > 0) {
    lines.push('### 🛠️ Choose an Approach');
    lines.push('');
    guidance.approaches.forEach(appr => {
      if (typeof appr === 'string') {
        const colonIdx = appr.indexOf(':');
        if (colonIdx !== -1) {
          const title = appr.slice(0, colonIdx);
          const desc = appr.slice(colonIdx + 1).trim();
          lines.push(`- **${title}:** ${desc}`);
        } else {
          lines.push(`- ${appr}`);
        }
      } else if (typeof appr === 'object' && appr !== null) {
        lines.push(`- **${appr.title}:** ${appr.description}`);
      }
    });
    lines.push('');
  }

  // ── How to Test ──
  if (guidance.verifySteps && Array.isArray(guidance.verifySteps) && guidance.verifySteps.length > 0) {
    lines.push('### 🧪 How to Test');
    lines.push('');
    guidance.verifySteps.forEach(step => {
      lines.push(`- [ ] ${step}`);
    });
    lines.push('');
  }

  // ── Example Structure ──
  lines.push('### 📋 Example Structure');
  lines.push('');
  lines.push(`**Why there isn't one exact fix:** ${guidance.cannotInfer}`);
  lines.push('');
  const patternText = guidance.illustrativePattern || '// Conceptual pattern: consult architectural guidelines and project security standards for safe implementation.';
  lines.push('**Illustrative pattern: adapt this to your project**');
  lines.push('```javascript');
  lines.push(patternText);
  lines.push('```');
  lines.push('');

  // ── Mandatory Educational Disclaimer ──
  lines.push('---');
  lines.push('');
  lines.push(`*${GUIDANCE_DISCLAIMER}*`);
  lines.push('');

  // ── Metrics Footer ──
  lines.push('---');
  lines.push('');
  const metricsRow = [];
  metricsRow.push(`${confidence.emoji} **Confidence:** ${issue.confidence}: *${confidence.description}*`);
  if (issue.cvssBaseScore !== undefined) {
    metricsRow.push(`📊 **CVSS Score:** ${formatCvssScore(issue.cvssBaseScore)}`);
  }
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
