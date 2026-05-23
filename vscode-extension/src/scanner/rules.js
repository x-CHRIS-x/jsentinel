/**
 * JSentinel Detection Rules — Consolidated for VS Code Extension
 * 
 * All 27 security detection rules across 9 OWASP categories, ported to CommonJS.
 * Each rule follows the same visitor pattern as the browser version:
 *   rule.visitor(issues) → returns Babel visitor handlers
 * 
 * Categories covered:
 *   A1 - Injection (5 rules)
 *   A2 - Broken Authentication (5 rules)
 *   A3 - Sensitive Data Exposure (3 rules)
 *   A5 - Broken Access Control (2 rules)
 *   A6 - Security Misconfiguration (4 rules)
 *   A7 - Cross-Site Scripting (3 rules)
 *   A8 - Software and Data Integrity (3 rules)
 *   A9 - Vulnerable and Outdated Components (1 rule)
 *   A10 - Server-Side Request Forgery (1 rule)
 */

// ============================================================
// A1 - Injection Rules
// ============================================================
const injectionRules = [
  {
    name: "eval-detection",
    id: "OWASP-A1-001",
    severity: "CRITICAL",
    visitor: (issues) => ({
      CallExpression(path) {
        if (path.node && path.node.callee && path.node.callee.name === 'eval') {
          issues.push({
            id: "OWASP-A1-001", severity: "CRITICAL",
            line: path.node.loc?.start?.line || 1,
            column: path.node.loc?.start?.column || 0,
            message: "Dangerous use of eval()",
            suggestion: "Use JSON.parse() or access object properties directly instead of eval().",
            cvssBaseScore: 10.0, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
          });
        }
      }
    })
  },
  {
    name: "dynamic-timer",
    id: "OWASP-A1-002",
    severity: "HIGH",
    visitor: (issues) => ({
      CallExpression(path) {
        const calleeName = path.node.callee?.name;
        if (!calleeName) return;
        if (calleeName === 'setTimeout' || calleeName === 'setInterval') {
          const firstArg = path.node.arguments[0];
          if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'TemplateLiteral')) {
            issues.push({
              id: "OWASP-A1-002", severity: "HIGH",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: `Dangerous use of string in ${calleeName}`,
              suggestion: "Pass a function or arrow function as the first argument instead of a string.",
              cvssBaseScore: 8.8, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N'
            });
          }
        }
      }
    })
  },
  {
    name: "unsafe-function-constructor",
    id: "OWASP-A1-003",
    severity: "CRITICAL",
    visitor: (issues) => ({
      NewExpression(path) {
        const callee = path.node.callee;
        if (callee && callee.type === 'Identifier' && callee.name === 'Function') {
          const firstArg = path.node.arguments[0];
          if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'TemplateLiteral')) {
            issues.push({
              id: "OWASP-A1-003", severity: "CRITICAL",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "Unsafe use of Function constructor",
              suggestion: "Avoid dynamic code execution. Pass standard functions or structured modules instead of strings.",
              cvssBaseScore: 10.0, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
            });
          }
        }
      }
    })
  },
  {
    name: "innerhtml-template-literal",
    id: "OWASP-A1-004",
    severity: "HIGH",
    visitor: (issues) => ({
      AssignmentExpression(path) {
        const left = path.node.left;
        if (left && left.type === 'MemberExpression' && left.property && left.property.name === 'innerHTML') {
          const right = path.node.right;
          if (right && right.type === 'TemplateLiteral' && right.expressions && right.expressions.length > 0) {
            issues.push({
              id: "OWASP-A1-004", severity: "HIGH",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "Unsafe innerHTML assignment using dynamic template literal",
              suggestion: "Use DOM manipulation methods such as document.createElement() and textContent, or apply a sanitization library.",
              cvssBaseScore: 8.8, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N'
            });
          }
        }
      }
    })
  },
  {
    name: "innerhtml-function-call",
    id: "OWASP-A1-005",
    severity: "HIGH",
    visitor: (issues) => ({
      AssignmentExpression(path) {
        const left = path.node.left;
        if (left && left.type === 'MemberExpression' && left.property && left.property.name === 'innerHTML') {
          const right = path.node.right;
          if (right && right.type === 'CallExpression') {
            issues.push({
              id: "OWASP-A1-005", severity: "HIGH",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "Unsafe innerHTML assignment using function return value",
              suggestion: "Ensure the returned string is properly sanitized before assignment, or use textContent instead of innerHTML.",
              cvssBaseScore: 8.8, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N'
            });
          }
        }
      }
    })
  }
];

// ============================================================
// A2 - Broken Authentication Rules
// ============================================================
const authRules = [
  {
    name: "hardcoded-password",
    id: "OWASP-A2-001",
    severity: "CRITICAL",
    visitor: (issues) => ({
      VariableDeclarator(path) {
        const idName = path.node.id.name?.toLowerCase();
        if (idName && (idName.includes('password') || idName.includes('passwd') || idName.includes('pwd'))) {
          if (path.node.init && path.node.init.type === 'StringLiteral') {
            issues.push({
              id: "OWASP-A2-001", severity: "CRITICAL",
              line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
              message: `Hardcoded password found in variable '${path.node.id.name}'`,
              suggestion: "Use environment variables or a secure secret management system instead of hardcoding credentials.",
              cvssBaseScore: 9.8, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            });
          }
        }
      },
      AssignmentExpression(path) {
        const leftName = path.node.left.name?.toLowerCase() || path.node.left.property?.name?.toLowerCase();
        if (leftName && (leftName.includes('password') || leftName.includes('passwd') || leftName.includes('pwd'))) {
          if (path.node.right && path.node.right.type === 'StringLiteral') {
            issues.push({
              id: "OWASP-A2-001", severity: "CRITICAL",
              line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
              message: `Hardcoded password assigned to '${leftName}'`,
              suggestion: "Use environment variables or a secure secret management system instead of hardcoding credentials.",
              cvssBaseScore: 9.8, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            });
          }
        }
      }
    })
  },
  {
    name: "localstorage-token",
    id: "OWASP-A2-002",
    severity: "HIGH",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        if (callee.type === 'MemberExpression' && callee.object.name === 'localStorage' && callee.property.name === 'setItem') {
          const firstArg = path.node.arguments[0];
          if (firstArg && firstArg.type === 'StringLiteral') {
            const keyName = firstArg.value.toLowerCase();
            if (keyName.includes('token') || keyName.includes('auth') || keyName.includes('jwt')) {
              issues.push({
                id: "OWASP-A2-002", severity: "HIGH",
                line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
                message: `Sensitive token stored in localStorage (key: '${firstArg.value}')`,
                suggestion: "Store authentication tokens in HttpOnly cookies to prevent theft via XSS.",
                cvssBaseScore: 8.2, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N'
              });
            }
          }
        }
      }
    })
  },
  {
    name: "insecure-cookie",
    id: "OWASP-A2-003",
    severity: "MEDIUM",
    visitor: (issues) => ({
      AssignmentExpression(path) {
        if (path.node.left.type === 'MemberExpression' && path.node.left.object.name === 'document' && path.node.left.property.name === 'cookie') {
          const right = path.node.right;
          if (right.type === 'StringLiteral') {
            const cookieVal = right.value.toLowerCase();
            if (!cookieVal.includes('httponly') || !cookieVal.includes('secure')) {
              issues.push({
                id: "OWASP-A2-003", severity: "MEDIUM",
                line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
                message: "Insecure cookie assignment (missing HttpOnly/Secure flags)",
                suggestion: "Always append '; HttpOnly; Secure' when manually setting cookies containing sensitive session data.",
                cvssBaseScore: 4.2, cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N'
              });
            }
          } else if (right.type === 'TemplateLiteral') {
            issues.push({
              id: "OWASP-A2-003", severity: "MEDIUM",
              line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
              message: "Cookie set via template literal — verify HttpOnly and Secure flags are present",
              suggestion: "Ensure template literals used for cookies include '; HttpOnly; Secure' for sensitive data.",
              cvssBaseScore: 4.2, cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N'
            });
          }
        }
      }
    })
  },
  {
    name: "insecure-random",
    id: "OWASP-A2-004",
    severity: "HIGH",
    visitor: (issues) => ({
      VariableDeclarator(path) {
        const varName = path.node.id.name?.toLowerCase();
        if (varName && (varName.includes('token') || varName.includes('otp') || varName.includes('secret') || varName.includes('salt') || varName.includes('key'))) {
          const init = path.node.init;
          if (init && init.type === 'CallExpression') {
            const callee = init.callee;
            if (callee.type === 'MemberExpression' && callee.object.name === 'Math' && callee.property.name === 'random') {
              issues.push({
                id: "OWASP-A2-004", severity: "HIGH",
                line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
                message: `Insecure pseudo-random number generator used for sensitive variable '${path.node.id.name}'`,
                suggestion: "Use window.crypto.getRandomValues() or the Web Crypto API to generate cryptographically secure random values.",
                cvssBaseScore: 7.5, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
              });
            }
          }
        }
      }
    })
  },
  {
    name: "plaintext-http-url",
    id: "OWASP-A2-005",
    severity: "MEDIUM",
    visitor: (issues) => ({
      StringLiteral(path) {
        const val = path.node.value;
        if (val && typeof val === 'string' && val.startsWith('http://')) {
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
              id: "OWASP-A2-005", severity: "MEDIUM",
              line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
              message: `Insecure plaintext connection URL hardcoded: '${val}'`,
              suggestion: "Use HTTPS connection URLs to secure transmissions and protect data integrity.",
              cvssBaseScore: 5.9, cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
            });
          }
        }
      }
    })
  }
];

// ============================================================
// A3 - Sensitive Data Exposure Rules
// ============================================================
const sensitiveDataRules = [
  {
    name: "hardcoded-secret-patterns",
    id: "OWASP-A3-001",
    severity: "CRITICAL",
    visitor: (issues) => ({
      StringLiteral(path) {
        const val = path.node.value;
        if (!val) return;
        const jwtPattern = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
        const awsKeyPattern = /(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|AQCA|AMZA|AWA|A2A)[A-Z0-9]{16}/;
        const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
        let type = null;
        if (val.startsWith('eyJ') && jwtPattern.test(val)) type = "JWT Token";
        else if (awsKeyPattern.test(val)) type = "AWS Access Key";
        else if (ipPattern.test(val) && val !== '127.0.0.1' && val !== '0.0.0.0') type = "IP Address";
        if (type) {
          issues.push({
            id: "OWASP-A3-001",
            severity: type === "IP Address" ? "MEDIUM" : "CRITICAL",
            line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
            message: `Hardcoded ${type} detected in string.`,
            suggestion: `Never hardcode ${type}s. Use environment variables (e.g., process.env or import.meta.env).`,
            cvssBaseScore: type === "IP Address" ? 5.3 : 9.1,
            cvssVector: type === "IP Address" ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' : 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
          });
        }
      }
    })
  },
  {
    name: "hardcoded-api-key",
    id: "OWASP-A3-002",
    severity: "CRITICAL",
    visitor: (issues) => ({
      VariableDeclarator(path) {
        const varName = path.node.id.name?.toLowerCase();
        if (varName && (varName.includes('key') || varName.includes('secret') || varName.includes('token') || varName.includes('api'))) {
          const init = path.node.init;
          if (init && init.type === 'StringLiteral' && init.value.length > 8) {
            const val = init.value.toLowerCase();
            if (val.includes('placeholder') || val.includes('dummy') || val.includes('test') || val.includes('example')) return;
            issues.push({
              id: "OWASP-A3-002", severity: "CRITICAL",
              line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
              message: `Hardcoded API key or secret found in variable '${path.node.id.name}'`,
              suggestion: "Retrieve keys and secrets dynamically from a secure backend or environment storage instead of hardcoding.",
              cvssBaseScore: 9.1, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
            });
          }
        }
      }
    })
  },
  {
    name: "sensitive-query-string",
    id: "OWASP-A3-003",
    severity: "MEDIUM",
    visitor: (issues) => ({
      StringLiteral(path) {
        const val = path.node.value;
        if (val && typeof val === 'string') {
          const lowerVal = val.toLowerCase();
          if (lowerVal.includes('?password=') || lowerVal.includes('&password=') ||
              lowerVal.includes('?token=') || lowerVal.includes('&token=') ||
              lowerVal.includes('?key=') || lowerVal.includes('&key=') ||
              lowerVal.includes('?secret=') || lowerVal.includes('&secret=')) {
            issues.push({
              id: "OWASP-A3-003", severity: "MEDIUM",
              line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
              message: "Sensitive credentials embedded in URL query string",
              suggestion: "Pass sensitive credentials inside HTTP request bodies or headers instead of query parameters.",
              cvssBaseScore: 5.3, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
            });
          }
        }
      }
    })
  }
];

// ============================================================
// A5 - Broken Access Control Rules
// ============================================================
const accessControlRules = [
  {
    name: "open-redirect",
    id: "OWASP-A5-001",
    severity: "HIGH",
    visitor: (issues) => ({
      AssignmentExpression(path) {
        const left = path.node.left;
        if (left && left.type === 'MemberExpression') {
          const isLocationHref =
            (left.object.name === 'location' && left.property.name === 'href') ||
            (left.object.type === 'MemberExpression' && left.object.object.name === 'window' && left.object.property.name === 'location' && left.property.name === 'href');
          if (isLocationHref) {
            const right = path.node.right;
            if (right && (right.type === 'Identifier' || right.type === 'TemplateLiteral' || right.type === 'CallExpression')) {
              issues.push({
                id: "OWASP-A5-001", severity: "HIGH",
                line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
                message: "Unsafe location redirection using dynamic value",
                suggestion: "Validate dynamic redirect targets against a whitelist of trusted domains.",
                cvssBaseScore: 7.4, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'
              });
            }
          }
        }
      },
      CallExpression(path) {
        const callee = path.node.callee;
        if (callee && callee.type === 'MemberExpression') {
          const isReplace = callee.property.name === 'replace';
          const isLocationObject = callee.object.name === 'location' ||
            (callee.object.type === 'MemberExpression' && callee.object.object.name === 'window' && callee.object.property.name === 'location');
          if (isReplace && isLocationObject) {
            const arg = path.node.arguments[0];
            if (arg && (arg.type === 'Identifier' || arg.type === 'TemplateLiteral' || arg.type === 'CallExpression')) {
              issues.push({
                id: "OWASP-A5-001", severity: "HIGH",
                line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
                message: "Unsafe location.replace() using dynamic value",
                suggestion: "Validate dynamic redirect targets against a whitelist of trusted domains.",
                cvssBaseScore: 7.4, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'
              });
            }
          }
        }
      }
    })
  },
  {
    name: "client-side-role-check",
    id: "OWASP-A5-002",
    severity: "MEDIUM",
    visitor: (issues) => {
      const isSensitiveProperty = (name) => {
        if (!name) return false;
        const lower = name.toLowerCase();
        return lower === 'role' || lower === 'isadmin' || lower === 'isauthenticated' || lower === 'admin';
      };
      const checkExpression = (node) => {
        if (!node) return false;
        if (node.type === 'MemberExpression') return isSensitiveProperty(node.property.name);
        if (node.type === 'BinaryExpression') return checkExpression(node.left) || checkExpression(node.right);
        if (node.type === 'LogicalExpression') return checkExpression(node.left) || checkExpression(node.right);
        if (node.type === 'UnaryExpression' && node.operator === '!') return checkExpression(node.argument);
        return false;
      };
      return {
        IfStatement(path) {
          const test = path.node.test;
          if (test && checkExpression(test)) {
            issues.push({
              id: "OWASP-A5-002", severity: "MEDIUM",
              line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
              message: "Client-side role or authorization check in condition statement",
              suggestion: "Never rely purely on client-side state for access control. Enforce all role-based authorization checks on a secure server.",
              cvssBaseScore: 5.3, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
            });
          }
        }
      };
    }
  }
];

// ============================================================
// A6 - Security Misconfiguration Rules
// ============================================================
const misconfigRules = [
  {
    name: "console-log-secrets",
    id: "OWASP-A6-001",
    severity: "MEDIUM",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        if (callee.type === 'MemberExpression' && callee.object.name === 'console') {
          path.node.arguments.forEach(arg => {
            if (arg.type === 'Identifier') {
              const argName = arg.name.toLowerCase();
              if (argName.includes('password') || argName.includes('token') || argName.includes('secret') || argName.includes('key')) {
                issues.push({
                  id: "OWASP-A6-001", severity: "MEDIUM",
                  line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
                  message: `Sensitive variable '${arg.name}' logged to console`,
                  suggestion: "Remove console.log statements containing sensitive data before deploying to production.",
                  cvssBaseScore: 5.5, cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
                });
              }
            }
          });
        }
      }
    })
  },
  {
    name: "cors-wildcard",
    id: "OWASP-A6-002",
    severity: "MEDIUM",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        if (callee.type === 'MemberExpression' && (callee.property.name === 'setHeader' || callee.property.name === 'header')) {
          const args = path.node.arguments;
          if (args.length === 2 && args[0].type === 'StringLiteral' && args[1].type === 'StringLiteral') {
            if (args[0].value.toLowerCase() === 'access-control-allow-origin' && args[1].value === '*') {
              issues.push({
                id: "OWASP-A6-002", severity: "MEDIUM",
                line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
                message: "Wildcard (*) used in Access-Control-Allow-Origin header",
                suggestion: "Specify exact trusted domains instead of using a wildcard.",
                cvssBaseScore: 6.5, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N'
              });
            }
          }
        }
      }
    })
  },
  {
    name: "console-log-objects",
    id: "OWASP-A6-003",
    severity: "MEDIUM",
    visitor: (issues) => {
      const sensitiveObjects = ['req', 'user', 'session', 'credentials', 'config'];
      return {
        CallExpression(path) {
          const callee = path.node.callee;
          if (callee.type === 'MemberExpression' && callee.object.name === 'console') {
            path.node.arguments.forEach(arg => {
              if (arg.type === 'Identifier' && sensitiveObjects.includes(arg.name.toLowerCase())) {
                issues.push({
                  id: "OWASP-A6-003", severity: "MEDIUM",
                  line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
                  message: `Sensitive object variable '${arg.name}' logged to console`,
                  suggestion: "Avoid logging complete request, session, or credential objects. Log only specific non-sensitive attributes.",
                  cvssBaseScore: 5.5, cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
                });
              }
            });
          }
        }
      };
    }
  },
  {
    name: "missing-helmet-middleware",
    id: "OWASP-A6-004",
    severity: "LOW",
    visitor: (issues) => {
      let hasExpress = false;
      let hasHelmet = false;
      let expressNode = null;
      return {
        ImportDeclaration(path) {
          if (path.node.source.value === 'express') { hasExpress = true; expressNode = path.node; }
          if (path.node.source.value === 'helmet') { hasHelmet = true; }
        },
        CallExpression(path) {
          if (path.node.callee.name === 'require') {
            const arg = path.node.arguments[0];
            if (arg && arg.type === 'StringLiteral') {
              if (arg.value === 'express') { hasExpress = true; expressNode = path.node; }
              if (arg.value === 'helmet') { hasHelmet = true; }
            }
          }
        },
        Program: {
          exit() {
            if (hasExpress && !hasHelmet) {
              issues.push({
                id: "OWASP-A6-004", severity: "LOW",
                line: expressNode?.loc?.start?.line || 1, column: expressNode?.loc?.start?.column || 0,
                message: "Express framework imported without protective helmet middleware",
                suggestion: "Install helmet (npm install helmet) and integrate it using app.use(helmet()).",
                cvssBaseScore: 3.3, cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'
              });
            }
          }
        }
      };
    }
  }
];

// ============================================================
// A7 - Cross-Site Scripting (XSS) Rules
// ============================================================
const xssRules = [
  {
    name: "inner-html-detection",
    id: "OWASP-A7-001",
    severity: "HIGH",
    visitor: (issues) => ({
      AssignmentExpression(path) {
        if (path.node.left && path.node.left.property && path.node.left.property.name === 'innerHTML') {
          issues.push({
            id: "OWASP-A7-001", severity: "HIGH",
            line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
            message: "Dangerous use of innerHTML",
            suggestion: "Use .textContent or .innerText to set text, or use a sanitization library like DOMPurify.",
            cvssBaseScore: 8.2, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N'
          });
        }
      }
    })
  },
  {
    name: "document-write-detection",
    id: "OWASP-A7-002",
    severity: "CRITICAL",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        if (callee.type === 'MemberExpression' && callee.object.name === 'document' && callee.property.name === 'write') {
          issues.push({
            id: "OWASP-A7-002", severity: "CRITICAL",
            line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
            message: "Dangerous use of document.write()",
            suggestion: "Use DOM manipulation methods like document.createElement() and appendChild() instead.",
            cvssBaseScore: 9.3, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N'
          });
        }
      }
    })
  },
  {
    name: "dangerously-set-inner-html-detection",
    id: "OWASP-A7-003",
    severity: "HIGH",
    visitor: (issues) => ({
      JSXAttribute(path) {
        if (path.node.name && path.node.name.name === 'dangerouslySetInnerHTML') {
          issues.push({
            id: "OWASP-A7-003", severity: "HIGH",
            line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
            message: "Dangerous use of dangerouslySetInnerHTML",
            suggestion: "Avoid setting raw HTML from user input. Use safer alternatives or a sanitization library.",
            cvssBaseScore: 8.2, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N'
          });
        }
      }
    })
  }
];

// ============================================================
// A8 - Software and Data Integrity Rules
// ============================================================
const deserializationRules = [
  {
    name: "unsafe-json-parse",
    id: "OWASP-A8-001",
    severity: "LOW",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        if (callee.type === 'MemberExpression' && callee.object.name === 'JSON' && callee.property.name === 'parse') {
          issues.push({
            id: "OWASP-A8-001", severity: "LOW",
            line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
            message: "JSON.parse() usage detected",
            suggestion: "If the input comes from an untrusted user, validate the structure of the resulting object immediately.",
            cvssBaseScore: 3.7, cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N'
          });
        }
      }
    })
  },
  {
    name: "prototype-pollution",
    id: "OWASP-A8-002",
    severity: "HIGH",
    visitor: (issues) => ({
      AssignmentExpression(path) {
        const left = path.node.left;
        if (!left) return;
        let isPollution = false;
        if (left.type === 'MemberExpression') {
          if (left.property && left.property.name === '__proto__') isPollution = true;
          if (left.object && left.object.type === 'MemberExpression') {
            if (left.object.property && left.object.property.name === 'constructor' && left.property && left.property.name === 'prototype') {
              isPollution = true;
            }
          }
        }
        if (isPollution) {
          issues.push({
            id: "OWASP-A8-002", severity: "HIGH",
            line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
            message: "Potential prototype pollution assignment detected",
            suggestion: "Avoid direct modification of __proto__ or constructor.prototype. Use Map objects, or use Object.create(null).",
            cvssBaseScore: 7.5, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
          });
        }
      }
    })
  },
  {
    name: "unsafe-object-assign",
    id: "OWASP-A8-003",
    severity: "MEDIUM",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        if (callee.type === 'MemberExpression' && callee.object.name === 'Object' && callee.property.name === 'assign') {
          const args = path.node.arguments;
          if (args.length >= 2 && args[0].type === 'ObjectExpression' && args[1].type === 'Identifier') {
            issues.push({
              id: "OWASP-A8-003", severity: "MEDIUM",
              line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
              message: "Unsafe use of Object.assign() with dynamic source argument",
              suggestion: "Validate and sanitize dynamic input arguments, or use a strict schema validator before merging objects.",
              cvssBaseScore: 5.3, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
            });
          }
        }
      }
    })
  }
];

// ============================================================
// A9 - Vulnerable and Outdated Components
// ============================================================
const knownVulnsRules = [
  {
    name: "risky-library-import",
    id: "OWASP-A9-001",
    severity: "MEDIUM",
    visitor: (issues) => {
      const riskyLibs = ['serialize-javascript', 'markdown-it', 'js-yaml', 'node-fetch', 'lodash', 'axios', 'jsonwebtoken', 'express', 'mongoose', 'vm2'];
      return {
        ImportDeclaration(path) {
          const moduleName = path.node.source.value;
          if (riskyLibs.includes(moduleName)) {
            issues.push({
              id: "OWASP-A9-001", severity: "MEDIUM",
              line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
              message: `Risky library imported: '${moduleName}'`,
              suggestion: "Ensure this library is kept strictly up-to-date and its inputs are heavily sanitized.",
              cvssBaseScore: 4.8, cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N'
            });
          }
        },
        CallExpression(path) {
          if (path.node.callee.name === 'require') {
            const arg = path.node.arguments[0];
            if (arg && arg.type === 'StringLiteral' && riskyLibs.includes(arg.value)) {
              issues.push({
                id: "OWASP-A9-001", severity: "MEDIUM",
                line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
                message: `Risky library required: '${arg.value}'`,
                suggestion: "Ensure this library is kept strictly up-to-date and its inputs are heavily sanitized.",
                cvssBaseScore: 4.8, cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N'
              });
            }
          }
        }
      };
    }
  }
];

// ============================================================
// A10 - Server-Side Request Forgery
// ============================================================
const ssrfRules = [
  {
    name: "ssrf-detection",
    id: "OWASP-A10-001",
    severity: "HIGH",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        if (!callee) return;
        let isHttpClientCall = false;
        let firstArg = null;
        if (callee.type === 'Identifier' && callee.name === 'fetch') {
          isHttpClientCall = true;
          firstArg = path.node.arguments[0];
        } else if (callee.type === 'MemberExpression') {
          const objName = callee.object.name;
          const propName = callee.property.name;
          if (objName === 'axios' && (propName === 'get' || propName === 'post')) {
            isHttpClientCall = true;
            firstArg = path.node.arguments[0];
          }
        }
        if (isHttpClientCall && firstArg) {
          let isUnsafe = false;
          if (firstArg.type === 'Identifier') isUnsafe = true;
          else if (firstArg.type === 'TemplateLiteral' && firstArg.expressions && firstArg.expressions.length > 0) isUnsafe = true;
          else if (firstArg.type === 'CallExpression') isUnsafe = true;
          if (isUnsafe) {
            issues.push({
              id: "OWASP-A10-001", severity: "HIGH",
              line: path.node.loc?.start?.line || 1, column: path.node.loc?.start?.column || 0,
              message: "Dynamic request target passed to HTTP client (SSRF risk)",
              suggestion: "Do not allow user-supplied input to directly construct connection URLs. Use a strict request whitelist.",
              cvssBaseScore: 8.6, cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'
            });
          }
        }
      }
    })
  }
];

// ============================================================
// Export all rules as a single flat array
// ============================================================
const allRules = [
  ...injectionRules,
  ...authRules,
  ...sensitiveDataRules,
  ...accessControlRules,
  ...misconfigRules,
  ...xssRules,
  ...deserializationRules,
  ...knownVulnsRules,
  ...ssrfRules
];

module.exports = { allRules };
