/**
 * A1 - Injection Rules
 * Targets: eval(), dynamic setTimeout, dynamic setInterval
 */
export const injectionRules = [
  {
    name: "eval-detection",
    id: "OWASP-A1-001",
    severity: "CRITICAL",
    message: "Use of eval() detected. This allows execution of arbitrary strings and is highly vulnerable to injection attacks.",
    owasp: "A1:2021-Broken Access Control (Injection)",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S:  'C',
      C:  'H',
      I:  'H',
      A:  'H',
      baseScore: 10.0,
      baseSeverity: 'CRITICAL',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
    },
    visitor: (issues) => {
      const cvssBaseScore = 10.0;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';
      return {
        CallExpression(path) {
          if (path.node && path.node.callee && path.node.callee.name === 'eval') {
            issues.push({
              id: "OWASP-A1-001",
              severity: "CRITICAL",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: "Dangerous use of eval()",
              suggestion: "Use JSON.parse() or access object properties directly instead of eval().",
              cvssBaseScore,
              cvssVector
            });
          }
        }
      };
    }
  },
  {
    name: "dynamic-timer",
    id: "OWASP-A1-002",
    severity: "MEDIUM",
    message: "setTimeout/setInterval with string arguments detected. This functions similarly to eval() and can lead to code injection.",
    owasp: "A1:2021-Injection",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'R',
      S:  'C',
      C:  'L',
      I:  'L',
      A:  'N',
      baseScore: 6.1,
      baseSeverity: 'MEDIUM',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 6.1;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
      return {
        CallExpression(path) {
          const calleeName = path.node.callee?.name;
          if (!calleeName) return; // Guard against MemberExpressions like window.setTimeout

          if (calleeName === 'setTimeout' || calleeName === 'setInterval') {
            const firstArg = path.node.arguments[0];
            // Check if first argument is a StringLiteral or TemplateLiteral (not a function/arrow)
            if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'TemplateLiteral')) {
              issues.push({
                id: "OWASP-A1-002",
                severity: "MEDIUM",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: `Dangerous use of string in ${calleeName}`,
                suggestion: "Pass a function or arrow function as the first argument instead of a string.",
                cvssBaseScore,
                cvssVector
              });
            }
          }
        }
      };
    }
  }
];
