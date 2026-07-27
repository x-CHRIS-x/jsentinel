/**
 * A2 - Broken Authentication Rules
 * Targets: Hardcoded passwords, localStorage tokens, insecure cookies, Math.random() secrets, http:// URLs
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
                suggestion: "Ensure cookies include '; HttpOnly; Secure' for sensitive data.",
                cvssBaseScore,
                cvssVector
              });
            } else if (right.type === 'BinaryExpression') {
              const collectStrings = (node) => {
                if (!node) return '';
                if (node.type === 'StringLiteral') return node.value;
                if (node.type === 'BinaryExpression') return collectStrings(node.left) + collectStrings(node.right);
                return '';
              };
              const fullCookieStr = collectStrings(right).toLowerCase();
              if (!fullCookieStr.includes('httponly') || !fullCookieStr.includes('secure')) {
                issues.push({
                  id: "OWASP-A2-003",
                  severity: "MEDIUM",
                  line: path.node.loc?.start?.line || 'unknown',
                  column: path.node.loc?.start?.column || 'unknown',
                  message: "Cookie set via dynamic concatenation — missing HttpOnly or Secure flags",
                  suggestion: "Ensure cookies include '; HttpOnly; Secure' for sensitive data.",
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
    name: "insecure-random",
    id: "OWASP-A2-004",
    severity: "HIGH",
    message: "Math.random() used to generate a security-sensitive value. This pseudo-random number generator is not cryptographically secure.",
    owasp: "A2:2021-Broken Authentication",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S:  'U',
      C:  'H',
      I:  'N',
      A:  'N',
      baseScore: 7.5,
      baseSeverity: 'HIGH',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 7.5;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';
      const hasMathRandom = (node) => {
        if (!node) return false;
        if (node.type === 'CallExpression') {
          const callee = node.callee;
          if (callee.type === 'MemberExpression' && callee.object.name === 'Math' && callee.property.name === 'random') {
            return true;
          }
          return hasMathRandom(callee) || node.arguments.some(hasMathRandom);
        }
        if (node.type === 'MemberExpression') {
          return hasMathRandom(node.object) || hasMathRandom(node.property);
        }
        if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression') {
          return hasMathRandom(node.left) || hasMathRandom(node.right);
        }
        return false;
      };
      return {
        VariableDeclarator(path) {
          const varName = path.node.id.name?.toLowerCase();
          if (varName && (varName.includes('token') || varName.includes('otp') || varName.includes('secret') || varName.includes('salt') || varName.includes('key'))) {
            const init = path.node.init;
            if (init && hasMathRandom(init)) {
              issues.push({
                id: "OWASP-A2-004",
                severity: "HIGH",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: `Insecure pseudo-random number generator used for sensitive variable '${path.node.id.name}'`,
                suggestion: "Use window.crypto.getRandomValues() or the Web Crypto API to generate cryptographically secure random values.",
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
    name: "plaintext-http-url",
    id: "OWASP-A2-005",
    severity: "MEDIUM",
    message: "Hardcoded http:// URL detected. Plaintext connections can transmit sensitive information without encryption.",
    owasp: "A2:2021-Broken Authentication",
    cvss: {
      AV: 'N',
      AC: 'H',
      PR: 'N',
      UI: 'N',
      S:  'U',
      C:  'H',
      I:  'N',
      A:  'N',
      baseScore: 5.9,
      baseSeverity: 'MEDIUM',
      vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 5.9;
      const cvssVector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N';
      return {
        StringLiteral(path) {
          const val = path.node.value;
          if (val && typeof val === 'string' && val.startsWith('http://')) {
            // Check if it is assigned to a variable or passed as an argument
            const parent = path.parent;
            let isVulnerable = false;
            
            if (parent && (parent.type === 'VariableDeclarator' || parent.type === 'AssignmentExpression')) {
              isVulnerable = true;
            } else if (parent && parent.type === 'CallExpression') {
              const callee = parent.callee;
              const calleeName = callee.name || callee.property?.name;
              if (calleeName === 'fetch' || calleeName === 'axios' || calleeName === 'get' || calleeName === 'post') {
                isVulnerable = true;
              }
            }

            if (isVulnerable) {
              issues.push({
                id: "OWASP-A2-005",
                severity: "MEDIUM",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: `Insecure plaintext connection URL hardcoded: '${val}'`,
                suggestion: "Use HTTPS connection URLs to secure transmissions and protect data integrity.",
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
