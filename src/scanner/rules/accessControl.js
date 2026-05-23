/**
 * A5 - Broken Access Control Rules
 * Targets: Open redirects, client-side role checks guarding conditional logic
 */
export const accessControlRules = [
  {
    name: "open-redirect",
    id: "OWASP-A5-001",
    severity: "HIGH",
    message: "Potential open redirect vulnerability. Assigning window.location or calling location.replace() with dynamic variables can let attackers redirect users to malicious websites.",
    owasp: "A5:2021-Broken Access Control",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'R',
      S:  'C',
      C:  'L',
      I:  'L',
      A:  'N',
      baseScore: 7.4,
      baseSeverity: 'HIGH',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 7.4;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
      return {
        AssignmentExpression(path) {
          const left = path.node.left;
          if (left && left.type === 'MemberExpression') {
            const isLocationHref = 
              (left.object.name === 'location' && left.property.name === 'href') ||
              (left.object.type === 'MemberExpression' && 
               left.object.object.name === 'window' && 
               left.object.property.name === 'location' && 
               left.property.name === 'href');

            if (isLocationHref) {
              const right = path.node.right;
              if (right && (right.type === 'Identifier' || right.type === 'TemplateLiteral' || right.type === 'CallExpression')) {
                issues.push({
                  id: "OWASP-A5-001",
                  severity: "HIGH",
                  line: path.node.loc?.start?.line || 'unknown',
                  column: path.node.loc?.start?.column || 'unknown',
                  message: "Unsafe location redirection using dynamic value",
                  suggestion: "Validate dynamic redirect targets against a whitelist of trusted domains, or avoid dynamic redirections entirely.",
                  cvssBaseScore,
                  cvssVector
                });
              }
            }
          }
        },
        CallExpression(path) {
          const callee = path.node.callee;
          if (callee && callee.type === 'MemberExpression') {
            const isReplace = callee.property.name === 'replace';
            const isLocationObject = 
              callee.object.name === 'location' || 
              (callee.object.type === 'MemberExpression' && 
               callee.object.object.name === 'window' && 
               callee.object.property.name === 'location');

            if (isReplace && isLocationObject) {
              const arg = path.node.arguments[0];
              if (arg && (arg.type === 'Identifier' || arg.type === 'TemplateLiteral' || arg.type === 'CallExpression')) {
                issues.push({
                  id: "OWASP-A5-001",
                  severity: "HIGH",
                  line: path.node.loc?.start?.line || 'unknown',
                  column: path.node.loc?.start?.column || 'unknown',
                  message: "Unsafe location.replace() using dynamic value",
                  suggestion: "Validate dynamic redirect targets against a whitelist of trusted domains, or avoid dynamic redirections entirely.",
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
    name: "client-side-role-check",
    id: "OWASP-A5-002",
    severity: "MEDIUM",
    message: "Client-side role or authorization check detected. Restricting features in the client browser only can be bypassed. Ensure security checks are enforced on the backend server.",
    owasp: "A5:2021-Broken Access Control",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S:  'U',
      C:  'L',
      I:  'N',
      A:  'N',
      baseScore: 5.3,
      baseSeverity: 'MEDIUM',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 5.3;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N';

      const isSensitiveProperty = (name) => {
        if (!name) return false;
        const lower = name.toLowerCase();
        return lower === 'role' || lower === 'isadmin' || lower === 'isauthenticated' || lower === 'admin';
      };

      const checkExpression = (node) => {
        if (!node) return false;
        if (node.type === 'MemberExpression') {
          return isSensitiveProperty(node.property.name);
        }
        if (node.type === 'BinaryExpression') {
          return checkExpression(node.left) || checkExpression(node.right);
        }
        if (node.type === 'LogicalExpression') {
          return checkExpression(node.left) || checkExpression(node.right);
        }
        if (node.type === 'UnaryExpression' && node.operator === '!') {
          return checkExpression(node.argument);
        }
        return false;
      };

      return {
        IfStatement(path) {
          const test = path.node.test;
          if (test && checkExpression(test)) {
            issues.push({
              id: "OWASP-A5-002",
              severity: "MEDIUM",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: "Client-side role or authorization check in condition statement",
              suggestion: "Never rely purely on client-side state for access control. Enforce all role-based authorization checks on a secure server.",
              cvssBaseScore,
              cvssVector
            });
          }
        }
      };
    }
  }
];
