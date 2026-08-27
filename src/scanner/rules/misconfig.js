/**
 * A05 - Security Misconfiguration Rules
 * Targets: console.log of secrets/sensitive variables, permissive CORS, logging sensitive objects, Express without helmet
 */
export const misconfigRules = [
  {
    name: "console-log-secrets",
    id: "OWASP-A05-001",
    severity: "MEDIUM",
    message: "Logging sensitive variables to the console can expose secrets in production environments.",
    owasp: "A05:2021-Security Misconfiguration",
    cvss: {
      AV: 'L',
      AC: 'L',
      PR: 'L',
      UI: 'N',
      S:  'U',
      C:  'H',
      I:  'N',
      A:  'N',
      baseScore: 5.5,
      baseSeverity: 'MEDIUM',
      vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 5.5;
      const cvssVector = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N';
      // Recursively search an expression tree for sensitive Identifier names
      const findSensitiveIdentifiers = (node) => {
        if (!node) return [];
        if (node.type === 'Identifier') {
          const name = node.name.toLowerCase();
          if (name.includes('password') || name.includes('token') || name.includes('secret') || name.includes('key')) {
            return [node.name];
          }
          return [];
        }
        if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression') {
          return [...findSensitiveIdentifiers(node.left), ...findSensitiveIdentifiers(node.right)];
        }
        if (node.type === 'TemplateLiteral' && node.expressions) {
          return node.expressions.flatMap(findSensitiveIdentifiers);
        }
        return [];
      };
      return {
        CallExpression(path) {
          const callee = path.node.callee;
          if (callee.type === 'MemberExpression' && callee.object.name === 'console') {
            path.node.arguments.forEach(arg => {
              const sensitiveNames = findSensitiveIdentifiers(arg);
              sensitiveNames.forEach(name => {
                issues.push({
                  id: "OWASP-A05-001",
                  guidanceId: "OWASP-A05-001",
                  severity: "MEDIUM",
                  line: path.node.loc?.start?.line || 'unknown',
                  column: path.node.loc?.start?.column || 'unknown',
                  message: `Sensitive variable '${name}' logged to console`,
                  suggestion: "Remove or redact sensitive values before logging.",
                  cvssBaseScore,
                  cvssVector
                });
              });
            });
          }
        }
      };
    }
  },
  {
    name: "cors-wildcard",
    id: "OWASP-A05-002",
    severity: "MEDIUM",
    message: "Permissive CORS policy detected (Access-Control-Allow-Origin: *).",
    owasp: "A05:2021-Security Misconfiguration",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'R',
      S:  'U',
      C:  'H',
      I:  'N',
      A:  'N',
      baseScore: 6.5,
      baseSeverity: 'MEDIUM',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 6.5;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N';
      return {
        CallExpression(path) {
          const callee = path.node.callee;
          if (callee.type === 'MemberExpression' && (callee.property.name === 'setHeader' || callee.property.name === 'header')) {
            const args = path.node.arguments;
            if (args.length === 2 && args[0].type === 'StringLiteral' && args[1].type === 'StringLiteral') {
              if (args[0].value.toLowerCase() === 'access-control-allow-origin' && args[1].value === '*') {
                issues.push({
                  id: "OWASP-A05-002",
                  guidanceId: "OWASP-A05-002",
                  severity: "MEDIUM",
                  line: path.node.loc?.start?.line || 'unknown',
                  column: path.node.loc?.start?.column || 'unknown',
                  message: "Wildcard (*) used in Access-Control-Allow-Origin header",
                  suggestion: "Configure server CORS for the actual trusted origins and credential policy.",
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
    name: "console-log-objects",
    id: "OWASP-A05-003",
    severity: "MEDIUM",
    message: "Logging potentially sensitive objects to the console can expose session details, configurations, or credentials in production environments.",
    owasp: "A05:2021-Security Misconfiguration",
    cvss: {
      AV: 'L',
      AC: 'L',
      PR: 'L',
      UI: 'N',
      S:  'U',
      C:  'H',
      I:  'N',
      A:  'N',
      baseScore: 5.5,
      baseSeverity: 'MEDIUM',
      vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 5.5;
      const cvssVector = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N';
      const sensitiveObjects = ['req', 'user', 'session', 'credentials', 'config'];
      return {
        CallExpression(path) {
          const callee = path.node.callee;
          if (callee.type === 'MemberExpression' && callee.object.name === 'console') {
            path.node.arguments.forEach(arg => {
              if (arg.type === 'Identifier') {
                if (sensitiveObjects.includes(arg.name.toLowerCase())) {
                  issues.push({
                    id: "OWASP-A05-003",
                    guidanceId: "OWASP-A05-003",
                    severity: "MEDIUM",
                    line: path.node.loc?.start?.line || 'unknown',
                    column: path.node.loc?.start?.column || 'unknown',
                    message: `Sensitive object variable '${arg.name}' logged to console`,
                    suggestion: "Log an allowlisted, non-sensitive subset rather than whole request/session objects.",
                    cvssBaseScore,
                    cvssVector
                  });
                }
              }
            });
          }
        }
      };
    }
  },
  {
    name: "missing-helmet-middleware",
    id: "OWASP-A05-004",
    severity: "LOW",
    message: "Express application detected without helmet middleware integration. Use helmet to set secure HTTP headers.",
    owasp: "A05:2021-Security Misconfiguration",
    cvss: {
      AV: 'L',
      AC: 'L',
      PR: 'L',
      UI: 'N',
      S:  'U',
      C:  'L',
      I:  'N',
      A:  'N',
      baseScore: 3.3,
      baseSeverity: 'LOW',
      vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 3.3;
      const cvssVector = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N';
      let hasExpress = false;
      let hasHelmet = false;
      let expressNode = null;

      return {
        ImportDeclaration(path) {
          if (path.node.source.value === 'express') {
            hasExpress = true;
            expressNode = path.node;
          }
          if (path.node.source.value === 'helmet') {
            hasHelmet = true;
          }
        },
        CallExpression(path) {
          if (path.node.callee.name === 'require') {
            const arg = path.node.arguments[0];
            if (arg && arg.type === 'StringLiteral') {
              if (arg.value === 'express') {
                hasExpress = true;
                expressNode = path.node;
              }
              if (arg.value === 'helmet') {
                hasHelmet = true;
              }
            }
          }
        },
        Program: {
          exit() {
            if (hasExpress && !hasHelmet) {
              issues.push({
                id: "OWASP-A05-004",
                guidanceId: "OWASP-A05-004",
                severity: "LOW",
                line: expressNode?.loc?.start?.line || 1,
                column: expressNode?.loc?.start?.column || 0,
                message: "Express framework imported without protective helmet middleware",
                suggestion: "Review server response-header policy and apply the appropriate Express/server hardening.",
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
