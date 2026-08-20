/**
 * A03 - Injection Rules
 * Targets: eval(), dynamic setTimeout/setInterval, new Function(), innerHTML dynamic assignments
 */
export const injectionRules = [
  {
    name: "eval-detection",
    id: "OWASP-A03-001",
    severity: "CRITICAL",
    message: "Use of eval() detected. This allows execution of arbitrary strings and is highly vulnerable to injection attacks.",
    owasp: "A03:2021-Injection",
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
              id: "OWASP-A03-001",
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
    id: "OWASP-A03-002",
    severity: "HIGH",
    message: "setTimeout/setInterval with string arguments detected. This functions similarly to eval() and can lead to code injection.",
    owasp: "A03:2021-Injection",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'R',
      S:  'U',
      C:  'H',
      I:  'H',
      A:  'H',
      baseScore: 8.8,
      baseSeverity: 'HIGH',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'
    },
    visitor: (issues) => {
      const cvssBaseScore = 8.8;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H';
      return {
        CallExpression(path) {
          const calleeName = path.node.callee?.name;
          if (!calleeName) return;

          if (calleeName === 'setTimeout' || calleeName === 'setInterval') {
            const firstArg = path.node.arguments[0];
            if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
              issues.push({
                id: "OWASP-A03-002",
                severity: "HIGH",
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
  },
  {
    name: "unsafe-function-constructor",
    id: "OWASP-A03-003",
    severity: "CRITICAL",
    message: "new Function() with a string argument detected. This acts similarly to eval() and poses a severe code execution risk.",
    owasp: "A03:2021-Injection",
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
        NewExpression(path) {
          const callee = path.node.callee;
          if (callee && callee.type === 'Identifier' && callee.name === 'Function') {
            const firstArg = path.node.arguments[0];
            if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'TemplateLiteral')) {
              issues.push({
                id: "OWASP-A03-003",
                severity: "CRITICAL",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: "Unsafe use of Function constructor",
                suggestion: "Avoid dynamic code execution. Pass standard functions or structured modules instead of strings.",
                cvssBaseScore,
                cvssVector
              });
            }
          }
        }
      };
    }
  },
  {
    name: "innerhtml-template-literal",
    id: "OWASP-A03-004",
    severity: "HIGH",
    message: "innerHTML assigned via a template literal containing a variable. This is highly vulnerable to Cross-Site Scripting (XSS) and HTML injection.",
    owasp: "A03:2021-Injection",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'R',
      S:  'U',
      C:  'H',
      I:  'H',
      A:  'H',
      baseScore: 8.8,
      baseSeverity: 'HIGH',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'
    },
    visitor: (issues) => {
      const cvssBaseScore = 8.8;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H';
      return {
        AssignmentExpression(path) {
          const left = path.node.left;
          if (left && left.type === 'MemberExpression' && left.property && left.property.name === 'innerHTML') {
            const right = path.node.right;
            if (right && right.type === 'TemplateLiteral') {
              // Ensure the template literal contains at least one variable/expression inside
              if (right.expressions && right.expressions.length > 0) {
                issues.push({
                  id: "OWASP-A03-004",
                  severity: "HIGH",
                  line: path.node.loc?.start?.line || 'unknown',
                  column: path.node.loc?.start?.column || 'unknown',
                  message: "Unsafe innerHTML assignment using dynamic template literal",
                  suggestion: "Use DOM manipulation methods such as document.createElement() and textContent, or apply a sanitization library.",
                  cvssBaseScore,
                  cvssVector
                });
              }
            }
          }
        }
      };
    }
  },
  {
    name: "innerhtml-function-call",
    id: "OWASP-A03-005",
    severity: "HIGH",
    message: "Result of a function call assigned directly to innerHTML. If the function returns unsanitized user input, it creates an injection vulnerability.",
    owasp: "A03:2021-Injection",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'R',
      S:  'U',
      C:  'H',
      I:  'H',
      A:  'H',
      baseScore: 8.8,
      baseSeverity: 'HIGH',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'
    },
    visitor: (issues) => {
      const cvssBaseScore = 8.8;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H';
      return {
        AssignmentExpression(path) {
          const left = path.node.left;
          if (left && left.type === 'MemberExpression' && left.property && left.property.name === 'innerHTML') {
            const right = path.node.right;
            if (right && right.type === 'CallExpression') {
              issues.push({
                id: "OWASP-A03-005",
                severity: "HIGH",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: "Unsafe innerHTML assignment using function return value",
                suggestion: "Ensure the returned string is properly sanitized before assignment, or use textContent instead of innerHTML.",
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
