/**
 * A2 - Broken Authentication Rules
 * Targets: Hardcoded passwords, localStorage tokens, unsecure cookies
 */
export const authRules = [
  {
    name: "hardcoded-password",
    id: "OWASP-A2-001",
    severity: "CRITICAL",
    message: "Hardcoded password detected. Credentials should never be hardcoded in the source code.",
    owasp: "A2:2021-Cryptographic Failures / Broken Auth",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S:  'U',
      C:  'H',
      I:  'H',
      A:  'H',
      baseScore: 9.8,
      baseSeverity: 'CRITICAL',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    },
    visitor: (issues) => {
      const cvssBaseScore = 9.8;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
      return {
        VariableDeclarator(path) {
          const idName = path.node.id.name?.toLowerCase();
          if (idName && (idName.includes('password') || idName.includes('passwd') || idName.includes('pwd'))) {
            if (path.node.init && path.node.init.type === 'StringLiteral') {
              issues.push({
                id: "OWASP-A2-001",
                severity: "CRITICAL",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: `Hardcoded password found in variable '${path.node.id.name}'`,
                suggestion: "Use environment variables or a secure secret management system instead of hardcoding credentials.",
                cvssBaseScore,
                cvssVector
              });
            }
          }
        },
        AssignmentExpression(path) {
          const leftName = path.node.left.name?.toLowerCase() || path.node.left.property?.name?.toLowerCase();
          if (leftName && (leftName.includes('password') || leftName.includes('passwd') || leftName.includes('pwd'))) {
            if (path.node.right && path.node.right.type === 'StringLiteral') {
              issues.push({
                id: "OWASP-A2-001",
                severity: "CRITICAL",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: `Hardcoded password assigned to '${leftName}'`,
                suggestion: "Use environment variables or a secure secret management system instead of hardcoding credentials.",
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
    name: "localstorage-token",
    id: "OWASP-A2-002",
    severity: "HIGH",
    message: "Storing sensitive tokens in localStorage exposes them to XSS attacks.",
    owasp: "A2:2021-Broken Authentication",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'R',
      S:  'C',
      C:  'H',
      I:  'L',
      A:  'N',
      baseScore: 8.2,
      baseSeverity: 'HIGH',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 8.2;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N';
      return {
        CallExpression(path) {
          const callee = path.node.callee;
          if (callee.type === 'MemberExpression' && callee.object.name === 'localStorage' && callee.property.name === 'setItem') {
            const firstArg = path.node.arguments[0];
            if (firstArg && firstArg.type === 'StringLiteral') {
              const keyName = firstArg.value.toLowerCase();
              if (keyName.includes('token') || keyName.includes('auth') || keyName.includes('jwt')) {
                issues.push({
                  id: "OWASP-A2-002",
                  severity: "HIGH",
                  line: path.node.loc?.start?.line || 'unknown',
                  column: path.node.loc?.start?.column || 'unknown',
                  message: `Sensitive token stored in localStorage (key: '${firstArg.value}')`,
                  suggestion: "Store authentication tokens in HttpOnly cookies to prevent theft via XSS.",
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
    name: "insecure-cookie",
    id: "OWASP-A2-003",
    severity: "MEDIUM",
    message: "Direct manipulation of document.cookie detected. Ensure cookies are set with HttpOnly and Secure flags.",
    owasp: "A2:2021-Broken Authentication",
    cvss: {
      AV: 'N',
      AC: 'H',
      PR: 'N',
      UI: 'R',
      S:  'U',
      C:  'L',
      I:  'L',
      A:  'N',
      baseScore: 4.2,
      baseSeverity: 'MEDIUM',
      vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 4.2;
      const cvssVector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N';
      return {
        AssignmentExpression(path) {
          if (path.node.left.type === 'MemberExpression' && path.node.left.object.name === 'document' && path.node.left.property.name === 'cookie') {
            const right = path.node.right;
            if (right.type === 'StringLiteral') {
              const cookieVal = right.value.toLowerCase();
              if (!cookieVal.includes('httponly') || !cookieVal.includes('secure')) {
                 issues.push({
                  id: "OWASP-A2-003",
                  severity: "MEDIUM",
                  line: path.node.loc?.start?.line || 'unknown',
                  column: path.node.loc?.start?.column || 'unknown',
                  message: "Insecure cookie assignment (missing HttpOnly/Secure flags)",
                  suggestion: "Always append '; HttpOnly; Secure' when manually setting cookies containing sensitive session data.",
                  cvssBaseScore,
                  cvssVector
                });
              }
            } else if (right.type === 'TemplateLiteral') {
              issues.push({
                id: "OWASP-A2-003",
                severity: "MEDIUM",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: "Cookie set via template literal — verify HttpOnly and Secure flags are present",
                suggestion: "Ensure template literals used for cookies include '; HttpOnly; Secure' for sensitive data.",
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
