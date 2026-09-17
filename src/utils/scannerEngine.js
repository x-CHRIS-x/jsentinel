import { SCANNER_VERSION } from './findingPolicy.js';
import * as Babel from '@babel/standalone';

/**
 * Main scanning engine that coordinates file parsing and rule execution.
 * 
 * @param {File} file - Browser File object.
 * @param {Array} rules - Array of security rule objects.
 * @returns {Promise<Object>} - Results including AST and any vulnerabilities.
 */
export const scanFile = async (file, rules) => {
  let hasError = false;
  try {
    const code = await file.text();
    const issues = [];

    // Run rules via @babel/standalone parser
    for (const rule of rules) {
      try {
        Babel.transform(code, {
          filename: file.name,
          ast: false,
          code: false,
          highlightCode: false,
          parserOpts: {
            errorRecovery: true // Allows partial scans of broken files
          },
          presets: [
            file.name.endsWith('.ts') || file.name.endsWith('.tsx') ? 'typescript' : null,
            ['react', { runtime: 'automatic' }]
          ].filter(Boolean),
          plugins: [
            () => ({
              visitor: rule.visitor(issues)
            })
          ]
        });
      } catch (ruleError) {
        console.error(`Error running rule ${rule.name} on ${file.name}:`, ruleError);
        hasError = true;
      }
    }

    // Attach guidanceId and extracted sourceLine
    const codeLines = code.split(/\r?\n/);
    issues.forEach(issue => {
      if (!issue.guidanceId) {
        issue.guidanceId = issue.id;
      }
      const lineNum = typeof issue.line === 'number' ? issue.line : parseInt(issue.line, 10);
      if (!Number.isNaN(lineNum) && lineNum >= 1 && lineNum <= codeLines.length) {
        issue.sourceLine = codeLines[lineNum - 1].trim();
      } else {
        issue.sourceLine = '';
      }
    });

    const deduplicatedIssues = deduplicateOverlappingHtmlIssues(issues);

    return {
      scannerVersion: SCANNER_VERSION,
      fileName: file.webkitRelativePath || file.name,
      issues: deduplicatedIssues,
      rawCode: code,
      success: true,
      hasError, // Track if any rule execution failed
    };
  } catch (error) {
    console.error("Scanner Error:", error);
    return {
      scannerVersion: SCANNER_VERSION,
      fileName: file.webkitRelativePath || file.name,
      error: error.message,
      success: false,
      hasError: true
    };
  }
};

const HTML_INJECTION_RULE_PRIORITY = {
  'OWASP-A03-004': 1,
  'OWASP-A03-005': 2,
  'OWASP-A03-006': 3
};

/**
 * Deduplicates overlapping HTML findings representing the same assignment.
 * When multiple HTML injection rules fire on the same assignment expression,
 * priority is:
 *   1. OWASP-A03-004 (template-specific)
 *   2. OWASP-A03-005 (function-result)
 *   3. OWASP-A03-006 (general innerHTML detection)
 *
 * Distinct assignments (including separate assignments on the same line)
 * and unrelated vulnerabilities at the same location survive.
 *
 * @param {Array} issues - Array of detected issue objects.
 * @returns {Array} - Deduplicated issues array preserving survivor metadata and order.
 */
export const deduplicateOverlappingHtmlIssues = (issues = []) => {
  if (!Array.isArray(issues) || issues.length <= 1) {
    return issues || [];
  }

  const chosenHtmlIssuesByLoc = new Map();

  for (const issue of issues) {
    const priority = HTML_INJECTION_RULE_PRIORITY[issue?.id];
    if (!priority) continue;

    const locKey = `${issue.line ?? 'unknown'}:${issue.column ?? 'unknown'}`;
    const existing = chosenHtmlIssuesByLoc.get(locKey);

    if (!existing || priority < existing.priority) {
      chosenHtmlIssuesByLoc.set(locKey, { issue, priority });
    }
  }

  if (chosenHtmlIssuesByLoc.size === 0) {
    return issues;
  }

  const remainingChosen = new Set(
    Array.from(chosenHtmlIssuesByLoc.values()).map(entry => entry.issue)
  );

  return issues.filter(issue => {
    if (!HTML_INJECTION_RULE_PRIORITY[issue?.id]) {
      return true;
    }
    if (remainingChosen.has(issue)) {
      remainingChosen.delete(issue);
      return true;
    }
    return false;
  });
};
