/**
 * A05 - Security Misconfiguration Rules
 * Targets: console.log of secrets/sensitive variables, logging sensitive objects
 *
 * Active browser checks: OWASP-A05-001, OWASP-A05-003
 *
 * RETIRED FROM ACTIVE BROWSER SCANNING (Phase 01):
 *   OWASP-A05-002 (cors-wildcard) — res.setHeader('Access-Control-Allow-Origin', '*')
 *     is an Express server-side response header call. Browsers do not set CORS
 *     response headers; only servers do. This check is meaningless in browser JS.
 *   OWASP-A05-004 (missing-helmet-middleware) — Express and helmet are Node.js
 *     server packages. Browser-side JavaScript cannot import or run them.
 *     Flagging their absence in browser code is a server-side concern.
 *
 * Rule IDs and guidance entries are retained for historical result resolution.
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
  }
];
