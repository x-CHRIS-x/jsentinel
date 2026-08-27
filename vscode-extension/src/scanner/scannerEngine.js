/**
 * JSentinel Scanner Engine: Node.js / VS Code Extension Port
 * 
 * This is the VS Code extension version of the scanner engine.
 * Uses @babel/parser + @babel/traverse directly instead of @babel/standalone
 * (which is browser-only).
 * 
 * The rule visitor pattern is identical to the browser version: each rule
 * exports a visitor(issues) function that returns Babel visitor node handlers.
 */

const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

/**
 * Scans a code string using all provided security rules.
 * 
 * @param {string} code - Raw source code text.
 * @param {string} fileName - File name (used for TS/JSX detection).
 * @param {Array} rules - Array of security rule objects.
 * @returns {Object} - Results including issues found.
 */
const scanCode = (code, fileName, rules) => {
  let hasError = false;
  const issues = [];

  // Determine parser plugins based on file extension
  const plugins = ['jsx', 'classProperties', 'optionalChaining', 'nullishCoalescingOperator'];
  if (fileName.endsWith('.ts') || fileName.endsWith('.tsx')) {
    plugins.push('typescript');
  }

  // Parse the code into an AST
  let ast;
  try {
    ast = parser.parse(code, {
      sourceType: 'module',
      errorRecovery: true,
      plugins
    });
  } catch (parseError) {
    console.error(`Parse error in ${fileName}:`, parseError.message);
    return {
      fileName,
      issues: [],
      success: false,
      hasError: true,
      error: parseError.message
    };
  }

  // Run each security rule against the AST
  for (const rule of rules) {
    try {
      const visitorHandlers = rule.visitor(issues);
      traverse(ast, visitorHandlers);
    } catch (ruleError) {
      console.error(`Error running rule ${rule.name} on ${fileName}:`, ruleError.message);
      hasError = true;
    }
  }

  // Attach guidanceId and extracted sourceLine
  const codeLines = code.split(/\r?\n/);
  issues.forEach(issue => {
    if (!issue.guidanceId) {
      issue.guidanceId = issue.id;
    }
    if (typeof issue.line === 'number' && issue.line >= 1 && issue.line <= codeLines.length) {
      issue.sourceLine = codeLines[issue.line - 1].trim();
    } else {
      issue.sourceLine = '';
    }
  });

  // Assign confidence levels (same logic as browser version)
  assignConfidenceLevels(issues);

  return {
    fileName,
    issues,
    success: true,
    hasError
  };
};

/**
 * Assigns confidence levels to each detected issue.
 * Mirrors the browser version's post-processing logic exactly.
 */
const assignConfidenceLevels = (issues) => {
  const highConfidenceRules = [
    'OWASP-A02-002', 'OWASP-A05-002', 'OWASP-A03-007', 'OWASP-A08-002'
  ];

  const mediumConfidenceRules = [
    'OWASP-A03-001', 'OWASP-A03-002', 'OWASP-A03-003', 'OWASP-A03-004',
    'OWASP-A03-005', 'OWASP-A07-001', 'OWASP-A02-003', 'OWASP-A02-004',
    'OWASP-A02-007', 'OWASP-A01-001', 'OWASP-A01-002', 'OWASP-A05-001',
    'OWASP-A05-003', 'OWASP-A03-006', 'OWASP-A03-008', 'OWASP-A08-003',
    'OWASP-A10-001'
  ];

  const lowConfidenceRules = [
    'OWASP-A08-001', 'OWASP-A06-001', 'OWASP-A05-004'
  ];

  issues.forEach(issue => {
    if (issue.confidence) return;

    let confidence = 'MEDIUM';
    const messageLower = issue.message?.toLowerCase() || '';
    const ruleId = issue.id;

    if (highConfidenceRules.includes(ruleId)) {
      confidence = 'HIGH';
    } else if (mediumConfidenceRules.includes(ruleId)) {
      confidence = 'MEDIUM';
    } else if (lowConfidenceRules.includes(ruleId)) {
      confidence = 'LOW';
    } else if (ruleId === 'OWASP-A02-001' || ruleId === 'OWASP-A02-006') {
      const matchesStrongIndicator =
        messageLower.includes('password') || messageLower.includes('secret');
      confidence = matchesStrongIndicator ? 'HIGH' : 'MEDIUM';
    } else if (ruleId === 'OWASP-A02-005') {
      if (messageLower.includes('jwt') || messageLower.includes('aws')) {
        confidence = 'HIGH';
      } else {
        confidence = 'MEDIUM';
      }
    }

    issue.confidence = confidence;
  });
};

module.exports = { scanCode };
