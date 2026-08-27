/**
 * JSentinel Detection Rules - Consolidated for VS Code Extension
 * 
 * All 27 security detection rules across 8 OWASP Top 10:2021 categories, ported to CommonJS.
 * Each rule follows the same visitor pattern as the browser version:
 *   rule.visitor(issues) → returns Babel visitor handlers
 * 
 * Categories covered:
 *   A01 - Broken Access Control (2 rules)
 *   A02 - Cryptographic Failures (7 rules)
 *   A03 - Injection (8 rules)
 *   A05 - Security Misconfiguration (4 rules)
 *   A06 - Vulnerable and Outdated Components (1 rule)
 *   A07 - Identification and Authentication Failures (1 rule)
 *   A08 - Software and Data Integrity Failures (3 rules)
 *   A10 - Server-Side Request Forgery (1 rule)
 */

function isValidated(path, varName) {
  if (!varName) return false;
  let currentPath = path;
  while (currentPath) {
    if (currentPath.isIfStatement && currentPath.isIfStatement()) {
      const test = currentPath.node.test;
      
      const checkTestNode = (node) => {
        if (!node) return false;
        
        // Match methods like includes, indexOf, test, validate, or check
        if (node.type === 'CallExpression') {
          const callee = node.callee;
          const hasVarArg = node.arguments.some(arg => arg.type === 'Identifier' && arg.name === varName);
          if (hasVarArg) {
            let funcName = '';
            if (callee.type === 'Identifier') {
              funcName = callee.name;
            } else if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') {
              funcName = callee.property.name;
            }
            const lowerFunc = funcName.toLowerCase();
            if (lowerFunc.includes('include') || lowerFunc.includes('indexof') || lowerFunc.includes('test') || lowerFunc.includes('validate') || lowerFunc.includes('check')) {
              return true;
            }
          }
        }
        
        if (node.type === 'BinaryExpression') {
          return checkTestNode(node.left) || checkTestNode(node.right);
        }
        if (node.type === 'LogicalExpression') {
          return checkTestNode(node.left) || checkTestNode(node.right);
        }
        if (node.type === 'UnaryExpression') {
          return checkTestNode(node.argument);
        }
        return false;
      };
      
      if (checkTestNode(test)) {
        return true;
      }
    }
    // Stop traversal if we leave the current function
    if (currentPath.isFunction && currentPath.isFunction()) {
      break;
    }
    currentPath = currentPath.parentPath;
  }
  return false;
}

// ============================================================
// A03 - Injection Rules
// ============================================================
const injectionRules = [
  {
    name: "eval-detection",
    id: "OWASP-A03-001",
    severity: "CRITICAL",
    visitor: (issues) => ({
      CallExpression(path) {
        if (path.node && path.node.callee && path.node.callee.name === 'eval') {
          issues.push({
            id: "OWASP-A03-001",
            guidanceId: "OWASP-A03-001",
            severity: "CRITICAL",
            line: path.node.loc?.start?.line || 1,
            column: path.node.loc?.start?.column || 0,
            message: "Dangerous use of eval()",
            suggestion: "Remove dynamic evaluation and choose a parser or fixed behavior that matches the intended input format.",
            cvssBaseScore: 10.0,
            cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
          });
        }
      }
    })
  },
  {
    name: "dynamic-timer",
    id: "OWASP-A03-002",
    severity: "HIGH",
    visitor: (issues) => ({
      CallExpression(path) {
        const calleeName = path.node.callee?.name;
        if (!calleeName) return;
        if (calleeName === 'setTimeout' || calleeName === 'setInterval') {
          const firstArg = path.node.arguments[0];
          if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'TemplateLiteral' || firstArg.type === 'BinaryExpression')) {
            issues.push({
              id: "OWASP-A03-002",
              guidanceId: "OWASP-A03-002",
              severity: "HIGH",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: `Dangerous use of string in ${calleeName}`,
              suggestion: "Replace runtime code strings with a function or closure that preserves intended arguments and timing.",
              cvssBaseScore: 8.8,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'
            });
          }
        }
      }
    })
  },
  {
    name: "unsafe-function-constructor",
    id: "OWASP-A03-003",
    severity: "CRITICAL",
    visitor: (issues) => ({
      NewExpression(path) {
        const callee = path.node.callee;
        if (callee && callee.type === 'Identifier' && callee.name === 'Function') {
          const firstArg = path.node.arguments[0];
          if (firstArg && (firstArg.type === 'StringLiteral' || firstArg.type === 'TemplateLiteral')) {
            issues.push({
              id: "OWASP-A03-003",
              guidanceId: "OWASP-A03-003",
              severity: "CRITICAL",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "Unsafe use of Function constructor",
              suggestion: "Redesign dynamic code execution into fixed functions, a restricted interpreter, or structured input.",
              cvssBaseScore: 10.0,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
            });
          }
        }
      }
    })
  },
  {
    name: "innerhtml-template-literal",
    id: "OWASP-A03-004",
    severity: "HIGH",
    visitor: (issues) => ({
      AssignmentExpression(path) {
        const left = path.node.left;
        if (left && left.type === 'MemberExpression' && left.property && left.property.name === 'innerHTML') {
          const right = path.node.right;
          if (right && right.type === 'TemplateLiteral' && right.expressions && right.expressions.length > 0) {
            issues.push({
              id: "OWASP-A03-004",
              guidanceId: "OWASP-A03-004",
              severity: "HIGH",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "Unsafe innerHTML assignment using dynamic template literal",
              suggestion: "Use DOM/text rendering when markup is unnecessary; otherwise sanitize under a defined HTML policy.",
              cvssBaseScore: 8.8,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'
            });
          }
        }
      }
    })
  },
  {
    name: "innerhtml-function-call",
    id: "OWASP-A03-005",
    severity: "HIGH",
    visitor: (issues) => ({
      AssignmentExpression(path) {
        const left = path.node.left;
        if (left && left.type === 'MemberExpression' && left.property && left.property.name === 'innerHTML') {
          const right = path.node.right;
          if (right && right.type === 'CallExpression') {
            issues.push({
              id: "OWASP-A03-005",
              guidanceId: "OWASP-A03-005",
              severity: "HIGH",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "Unsafe innerHTML assignment using function return value",
              suggestion: "Trace the returned data and use safe rendering or context-appropriate sanitization.",
              cvssBaseScore: 8.8,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'
            });
          }
        }
      }
    })
  }
];

// ============================================================
// A02 / A07 - Cryptographic Failures & Auth Rules
// ============================================================
const authRules = [
  {
    name: "hardcoded-password",
    id: "OWASP-A02-001",
    severity: "CRITICAL",
    visitor: (issues) => ({
      VariableDeclarator(path) {
        const idName = path.node.id.name?.toLowerCase();
        if (idName && (idName.includes('password') || idName.includes('passwd') || idName.includes('pwd'))) {
          if (path.node.init && path.node.init.type === 'StringLiteral') {
            issues.push({
              id: "OWASP-A02-001",
              guidanceId: "OWASP-A02-001",
              severity: "CRITICAL",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: `Hardcoded password found in variable '${path.node.id.name}'`,
              suggestion: "Revoke or rotate exposed credentials and move real secrets to a server-side secret store.",
              cvssBaseScore: 9.8,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            });
          }
        }
      },
      AssignmentExpression(path) {
        const leftName = path.node.left.name?.toLowerCase() || path.node.left.property?.name?.toLowerCase();
        if (leftName && (leftName.includes('password') || leftName.includes('passwd') || leftName.includes('pwd'))) {
          if (path.node.right && path.node.right.type === 'StringLiteral') {
            issues.push({
              id: "OWASP-A02-001",
              guidanceId: "OWASP-A02-001",
              severity: "CRITICAL",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: `Hardcoded password assigned to '${leftName}'`,
              suggestion: "Revoke or rotate exposed credentials and move real secrets to a server-side secret store.",
              cvssBaseScore: 9.8,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            });
          }
        }
      }
    })
  },
  {
    name: "localstorage-token",
    id: "OWASP-A07-001",
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
                id: "OWASP-A07-001",
                guidanceId: "OWASP-A07-001",
                severity: "HIGH",
                line: path.node.loc?.start?.line || 1,
                column: path.node.loc?.start?.column || 0,
                message: `Sensitive token stored in localStorage (key: '${firstArg.value}')`,
                suggestion: "Design the authentication flow so scripts cannot read long-lived credentials where possible.",
                cvssBaseScore: 8.2,
                cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N'
              });
            }
          }
        }
      }
    })
  },
  {
    name: "insecure-cookie",
    id: "OWASP-A02-002",
    severity: "MEDIUM",
    visitor: (issues) => ({
      AssignmentExpression(path) {
        if (path.node.left.type === 'MemberExpression' && path.node.left.object.name === 'document' && path.node.left.property.name === 'cookie') {
          const right = path.node.right;
          if (right.type === 'StringLiteral') {
            const cookieVal = right.value.toLowerCase();
            if (!cookieVal.includes('httponly') || !cookieVal.includes('secure')) {
              issues.push({
                id: "OWASP-A02-002",
                guidanceId: "OWASP-A02-002",
                severity: "MEDIUM",
                line: path.node.loc?.start?.line || 1,
                column: path.node.loc?.start?.column || 0,
                message: "Insecure cookie assignment (missing HttpOnly/Secure flags)",
                suggestion: "Have the server issue the session cookie with the appropriate secure attributes.",
                cvssBaseScore: 4.2,
                cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N'
              });
            }
          } else if (right.type === 'TemplateLiteral') {
            issues.push({
              id: "OWASP-A02-002",
              guidanceId: "OWASP-A02-002",
              severity: "MEDIUM",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "Cookie set via template literal: verify HttpOnly and Secure flags are present",
              suggestion: "Have the server issue the session cookie with the appropriate secure attributes.",
              cvssBaseScore: 4.2,
              cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N'
            });
          } else if (right.type === 'BinaryExpression') {
            // Check if the concatenation chain contains both HttpOnly and Secure flags
            const collectStrings = (node) => {
              if (!node) return '';
              if (node.type === 'StringLiteral') return node.value;
              if (node.type === 'BinaryExpression') return collectStrings(node.left) + collectStrings(node.right);
              return '';
            };
            const fullCookieStr = collectStrings(right).toLowerCase();
            if (!fullCookieStr.includes('httponly') || !fullCookieStr.includes('secure')) {
              issues.push({
                id: "OWASP-A02-002",
                guidanceId: "OWASP-A02-002",
                severity: "MEDIUM",
                line: path.node.loc?.start?.line || 1,
                column: path.node.loc?.start?.column || 0,
                message: "Cookie set via dynamic concatenation: missing HttpOnly or Secure flags",
                suggestion: "Have the server issue the session cookie with the appropriate secure attributes.",
                cvssBaseScore: 4.2,
                cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N'
              });
            }
          }
        }
      }
    })
  },
  {
    name: "insecure-random",
    id: "OWASP-A02-003",
    severity: "HIGH",
    visitor: (issues) => {
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
                id: "OWASP-A02-003",
                guidanceId: "OWASP-A02-003",
                severity: "HIGH",
                line: path.node.loc?.start?.line || 1,
                column: path.node.loc?.start?.column || 0,
                message: `Insecure pseudo-random number generator used for sensitive variable '${path.node.id.name}'`,
                suggestion: "Use a cryptographically strong generator appropriate to the token's security purpose.",
                cvssBaseScore: 7.5,
                cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
              });
            }
          }
        }
      };
    }
  },
  {
    name: "plaintext-http-url",
    id: "OWASP-A02-004",
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
              id: "OWASP-A02-004",
              guidanceId: "OWASP-A02-004",
              severity: "MEDIUM",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: `Insecure plaintext connection URL hardcoded: '${val}'`,
              suggestion: "Migrate only to a TLS endpoint that the service actually supports.",
              cvssBaseScore: 5.9,
              cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
            });
          }
        }
      }
    })
  }
];
// ============================================================
// A02 - Sensitive Data Exposure Rules
// ============================================================
const sensitiveDataRules = [
  {
    name: "hardcoded-secret-patterns",
    id: "OWASP-A02-005",
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
          const isNetworkAddress = type === "IP Address";
          const guidanceId = isNetworkAddress ? "OWASP-A02-005:network-address" : "OWASP-A02-005:credential";
          const cvssBaseScore = isNetworkAddress ? 5.3 : 9.1;
          const cvssVector = isNetworkAddress
            ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
            : 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N';
          const suggestion = isNetworkAddress
            ? "Review whether the endpoint address is sensitive configuration before changing it."
            : "Revoke, rotate, and move genuine secrets out of source and client bundles.";

          issues.push({
            id: "OWASP-A02-005",
            guidanceId,
            severity: isNetworkAddress ? "MEDIUM" : "CRITICAL",
            line: path.node.loc?.start?.line || 1,
            column: path.node.loc?.start?.column || 0,
            message: `Hardcoded ${type} detected in string.`,
            suggestion,
            cvssBaseScore,
            cvssVector
          });
        }
      }
    })
  },
  {
    name: "hardcoded-api-key",
    id: "OWASP-A02-006",
    severity: "CRITICAL",
    visitor: (issues) => ({
      VariableDeclarator(path) {
        const varName = path.node.id.name?.toLowerCase();
        if (varName && (varName.includes('key') || varName.includes('secret') || varName.includes('token') || varName.includes('api'))) {
          const init = path.node.init;
          if (init && init.type === 'StringLiteral' && init.value.length > 8) {
            const val = init.value.toLowerCase();
            if (val.includes('placeholder') || val.includes('dummy') || val.includes('test') || val.includes('example')) return;
            if (val.startsWith('http://') || val.startsWith('https://')) return; // Ignore URLs to prevent false positives
            issues.push({
              id: "OWASP-A02-006",
              guidanceId: "OWASP-A02-006",
              severity: "CRITICAL",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: `Hardcoded API key or secret found in variable '${path.node.id.name}'`,
              suggestion: "Determine whether the key is public/restricted or secret, then protect and rotate it accordingly.",
              cvssBaseScore: 9.1,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
            });
          }
        }
      }
    })
  },
  {
    name: "sensitive-query-string",
    id: "OWASP-A02-007",
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
              id: "OWASP-A02-007",
              guidanceId: "OWASP-A02-007",
              severity: "MEDIUM",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "Sensitive credentials embedded in URL query string",
              suggestion: "Remove credentials from URLs and use the protocol's secure body/header mechanism over TLS.",
              cvssBaseScore: 5.3,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
            });
          }
        }
      }
    })
  }
];
// ============================================================
// A01 - Broken Access Control Rules
// ============================================================
const accessControlRules = [
  {
    name: "open-redirect",
    id: "OWASP-A01-001",
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
              let isUnsafe = false;
              if (right.type === 'Identifier') {
                if (!isValidated(path, right.name)) {
                  isUnsafe = true;
                }
              } else if (right.type === 'TemplateLiteral') {
                if (right.expressions && right.expressions.length > 0) {
                  const hasUnvalidatedExpression = right.expressions.some(expr => {
                    if (expr.type === 'Identifier') {
                      return !isValidated(path, expr.name);
                    }
                    return true;
                  });
                  if (hasUnvalidatedExpression) {
                    isUnsafe = true;
                  }
                }
              } else if (right.type === 'CallExpression') {
                isUnsafe = true;
              }

              if (isUnsafe) {
                issues.push({
                  id: "OWASP-A01-001",
                  guidanceId: "OWASP-A01-001",
                  severity: "HIGH",
                  line: path.node.loc?.start?.line || 1,
                  column: path.node.loc?.start?.column || 0,
                  message: "Unsafe location redirection using dynamic value",
                  suggestion: "Allow only configured, trusted destinations.",
                  cvssBaseScore: 7.4,
                  cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N'
                });
              }
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
              let isUnsafe = false;
              if (arg.type === 'Identifier') {
                if (!isValidated(path, arg.name)) {
                  isUnsafe = true;
                }
              } else if (arg.type === 'TemplateLiteral') {
                if (arg.expressions && arg.expressions.length > 0) {
                  const hasUnvalidatedExpression = arg.expressions.some(expr => {
                    if (expr.type === 'Identifier') {
                      return !isValidated(path, expr.name);
                    }
                    return true;
                  });
                  if (hasUnvalidatedExpression) {
                    isUnsafe = true;
                  }
                }
              } else if (arg.type === 'CallExpression') {
                isUnsafe = true;
              }

              if (isUnsafe) {
                issues.push({
                  id: "OWASP-A01-001",
                  guidanceId: "OWASP-A01-001",
                  severity: "HIGH",
                  line: path.node.loc?.start?.line || 1,
                  column: path.node.loc?.start?.column || 0,
                  message: "Unsafe location.replace() using dynamic value",
                  suggestion: "Allow only configured, trusted destinations.",
                  cvssBaseScore: 7.4,
                  cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N'
                });
              }
            }
          }
        }
      }
    })
  },
  {
    name: "client-side-role-check",
    id: "OWASP-A01-002",
    severity: "MEDIUM",
    visitor: (issues) => {
      const isSensitiveProperty = (name) => {
        if (!name) return false;
        const lower = name.toLowerCase();
        return lower === 'role' || lower === 'isadmin' || lower === 'admin';
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
              id: "OWASP-A01-002",
              guidanceId: "OWASP-A01-002",
              severity: "MEDIUM",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "Client-side role or authorization check in condition statement",
              suggestion: "Enforce authorization for every protected action on the server/API.",
              cvssBaseScore: 5.3,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
            });
          }
        }
      };
    }
  }
];

// ============================================================
// A05 - Security Misconfiguration Rules
// ============================================================
const misconfigRules = [
  {
    name: "console-log-secrets",
    id: "OWASP-A05-001",
    severity: "MEDIUM",
    visitor: (issues) => {
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
                  line: path.node.loc?.start?.line || 1,
                  column: path.node.loc?.start?.column || 0,
                  message: `Sensitive variable '${name}' logged to console`,
                  suggestion: "Remove or redact sensitive values before logging.",
                  cvssBaseScore: 5.5,
                  cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
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
    visitor: (issues) => ({
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
                line: path.node.loc?.start?.line || 1,
                column: path.node.loc?.start?.column || 0,
                message: "Wildcard (*) used in Access-Control-Allow-Origin header",
                suggestion: "Configure server CORS for the actual trusted origins and credential policy.",
                cvssBaseScore: 6.5,
                cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N'
              });
            }
          }
        }
      }
    })
  },
  {
    name: "console-log-objects",
    id: "OWASP-A05-003",
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
                  id: "OWASP-A05-003",
                  guidanceId: "OWASP-A05-003",
                  severity: "MEDIUM",
                  line: path.node.loc?.start?.line || 1,
                  column: path.node.loc?.start?.column || 0,
                  message: `Sensitive object variable '${arg.name}' logged to console`,
                  suggestion: "Log an allowlisted, non-sensitive subset rather than whole request/session objects.",
                  cvssBaseScore: 5.5,
                  cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
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
    id: "OWASP-A05-004",
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
                id: "OWASP-A05-004",
                guidanceId: "OWASP-A05-004",
                severity: "LOW",
                line: expressNode?.loc?.start?.line || 1,
                column: expressNode?.loc?.start?.column || 0,
                message: "Express framework imported without protective helmet middleware",
                suggestion: "Review server response-header policy and apply the appropriate Express/server hardening.",
                cvssBaseScore: 3.3,
                cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'
              });
            }
          }
        }
      };
    }
  }
];

// ============================================================
// A03 - Cross-Site Scripting (XSS) Rules
// ============================================================
const xssRules = [
  {
    name: "inner-html-detection",
    id: "OWASP-A03-006",
    severity: "HIGH",
    visitor: (issues) => ({
      AssignmentExpression(path) {
        if (path.node.left && path.node.left.property && path.node.left.property.name === 'innerHTML') {
          issues.push({
            id: "OWASP-A03-006",
            guidanceId: "OWASP-A03-006",
            severity: "HIGH",
            line: path.node.loc?.start?.line || 1,
            column: path.node.loc?.start?.column || 0,
            message: "Dangerous use of innerHTML",
            suggestion: "Prefer safe text/DOM APIs unless a documented HTML policy requires markup.",
            cvssBaseScore: 8.2,
            cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N'
          });
        }
      }
    })
  },
  {
    name: "document-write-detection",
    id: "OWASP-A03-007",
    severity: "CRITICAL",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        if (callee.type === 'MemberExpression' && callee.object.name === 'document' && callee.property.name === 'write') {
          issues.push({
            id: "OWASP-A03-007",
            guidanceId: "OWASP-A03-007",
            severity: "CRITICAL",
            line: path.node.loc?.start?.line || 1,
            column: path.node.loc?.start?.column || 0,
            message: "Dangerous use of document.write()",
            suggestion: "Replace the page-writing strategy according to load timing and intended output.",
            cvssBaseScore: 9.3,
            cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N'
          });
        }
      }
    })
  },
  {
    name: "dangerously-set-inner-html-detection",
    id: "OWASP-A03-008",
    severity: "HIGH",
    visitor: (issues) => ({
      JSXAttribute(path) {
        if (path.node.name && path.node.name.name === 'dangerouslySetInnerHTML') {
          issues.push({
            id: "OWASP-A03-008",
            guidanceId: "OWASP-A03-008",
            severity: "HIGH",
            line: path.node.loc?.start?.line || 1,
            column: path.node.loc?.start?.column || 0,
            message: "Dangerous use of dangerouslySetInnerHTML",
            suggestion: "Prefer React's normal escaped rendering; use a vetted sanitizer only for intentional HTML.",
            cvssBaseScore: 8.2,
            cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N'
          });
        }
      }
    })
  }
];

// ============================================================
// A08 - Software and Data Integrity Rules
// ============================================================
const deserializationRules = [
  {
    name: "unsafe-json-parse",
    id: "OWASP-A08-001",
    severity: "LOW",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        if (callee.type === 'MemberExpression' && callee.object.name === 'JSON' && callee.property.name === 'parse') {
          let isParsedValidated = false;

          const varDecl = path.findParent(p => p.isVariableDeclarator());
          if (varDecl && varDecl.node.id.type === 'Identifier') {
            const varName = varDecl.node.id.name;
            
            // First attempt using scope bindings which is standard and elegant
            const binding = path.scope.getBinding(varName);
            if (binding && binding.referencePaths) {
              for (const refPath of binding.referencePaths) {
                const callPath = refPath.findParent(p => p.isCallExpression());
                if (callPath) {
                  const childCallee = callPath.node.callee;
                  let funcName = '';
                  if (childCallee.type === 'Identifier') {
                    funcName = childCallee.name;
                  } else if (childCallee.type === 'MemberExpression' && childCallee.property.type === 'Identifier') {
                    funcName = childCallee.property.name;
                  }
                  const lowerFunc = funcName.toLowerCase();
                  if (lowerFunc.includes('validate') || lowerFunc.includes('verify') || lowerFunc.includes('isvalid')) {
                    isParsedValidated = true;
                    break;
                  }
                }
              }
            }

            // Fallback to traversing parent scope if binding not resolved
            if (!isParsedValidated) {
              const parentScope = path.findParent(p => p.isFunction() || p.isProgram());
              if (parentScope) {
                parentScope.traverse({
                  CallExpression(childPath) {
                    const childCallee = childPath.node.callee;
                    const hasVarArg = childPath.node.arguments.some(arg => arg.type === 'Identifier' && arg.name === varName);
                    if (hasVarArg) {
                      let funcName = '';
                      if (childCallee.type === 'Identifier') {
                        funcName = childCallee.name;
                      } else if (childCallee.type === 'MemberExpression' && childCallee.property.type === 'Identifier') {
                        funcName = childCallee.property.name;
                      }
                      const lowerFunc = funcName.toLowerCase();
                      if (lowerFunc.includes('validate') || lowerFunc.includes('verify') || lowerFunc.includes('isvalid')) {
                        isParsedValidated = true;
                      }
                    }
                  }
                });
              }
            }
          }

          if (!isParsedValidated) {
            issues.push({
              id: "OWASP-A08-001",
              guidanceId: "OWASP-A08-001",
              severity: "LOW",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "JSON.parse() usage detected",
              suggestion: "Validate untrusted parsed data against the expected structure before sensitive use.",
              cvssBaseScore: 3.7,
              cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N'
            });
          }
        }
      }
    })
  },
  {
    name: "prototype-pollution",
    id: "OWASP-A08-002",
    severity: "HIGH",
    visitor: (issues) => {
      // Recursively check if any MemberExpression in the chain references __proto__ or constructor.prototype
      const hasProtoPollution = (node) => {
        if (!node || node.type !== 'MemberExpression') return false;
        // Check for __proto__ at any level
        if (node.property && (node.property.name === '__proto__' || (node.property.type === 'StringLiteral' && node.property.value === '__proto__'))) return true;
        // Check for constructor.prototype chain
        if (node.object && node.object.type === 'MemberExpression') {
          if (node.object.property && node.object.property.name === 'constructor' && node.property && node.property.name === 'prototype') return true;
        }
        // Recurse into deeper chains like target.__proto__[key]
        return hasProtoPollution(node.object);
      };
      return {
        AssignmentExpression(path) {
          const left = path.node.left;
          if (!left) return;
          if (hasProtoPollution(left)) {
            issues.push({
              id: "OWASP-A08-002",
              guidanceId: "OWASP-A08-002",
              severity: "HIGH",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "Potential prototype pollution assignment detected",
              suggestion: "Stop direct prototype mutation and reject dangerous property names in untrusted data.",
              cvssBaseScore: 7.5,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'
            });
          }
        }
      };
    }
  },
  {
    name: "unsafe-object-assign",
    id: "OWASP-A08-003",
    severity: "MEDIUM",
    visitor: (issues) => ({
      CallExpression(path) {
        const callee = path.node.callee;
        if (callee.type === 'MemberExpression' && callee.object.name === 'Object' && callee.property.name === 'assign') {
          const args = path.node.arguments;
          if (args.length >= 2 && args[0].type === 'Identifier') {
            issues.push({
              id: "OWASP-A08-003",
              guidanceId: "OWASP-A08-003",
              severity: "MEDIUM",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "Unsafe use of Object.assign() mutating target object",
              suggestion: "Construct or merge only allowlisted data into an appropriate target object.",
              cvssBaseScore: 5.3,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
            });
          }
        }
      }
    })
  }
];

// ============================================================
// A06 - Vulnerable and Outdated Components
// ============================================================
const knownVulnsRules = [
  {
    name: "risky-library-import",
    id: "OWASP-A06-001",
    severity: "MEDIUM",
    visitor: (issues) => {
      const cvssBaseScore = 4.8;
      const cvssVector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N';
      const riskyLibs = ['serialize-javascript', 'markdown-it', 'js-yaml', 'node-fetch', 'lodash', 'axios', 'jsonwebtoken', 'express', 'mongoose', 'vm2'];

      const imports = [];
      let hasHelmet = false;
      const axiosCalls = [];

      return {
        ImportDeclaration(path) {
          const moduleName = path.node.source.value;
          if (moduleName === 'helmet') {
            hasHelmet = true;
          }
          if (riskyLibs.includes(moduleName)) {
            imports.push({
              name: moduleName,
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              type: 'import'
            });
          }
        },
        CallExpression(path) {
          const callee = path.node.callee;
          if (callee.type === 'Identifier' && callee.name === 'require') {
            const arg = path.node.arguments[0];
            if (arg && arg.type === 'StringLiteral') {
              const moduleName = arg.value;
              if (moduleName === 'helmet') {
                hasHelmet = true;
              }
              if (riskyLibs.includes(moduleName)) {
                imports.push({
                  name: moduleName,
                  line: path.node.loc?.start?.line || 1,
                  column: path.node.loc?.start?.column || 0,
                  type: 'require'
                });
              }
            }
          }

          if (callee.type === 'MemberExpression') {
            const objName = callee.object.name;
            const propName = callee.property.name;
            if (objName === 'axios' && (propName === 'get' || propName === 'post')) {
              axiosCalls.push({ path, arg: path.node.arguments[0] });
            }
          } else if (callee.type === 'Identifier' && callee.name === 'axios') {
            axiosCalls.push({ path, arg: path.node.arguments[0] });
          }
        },
        Program: {
          exit() {
            imports.forEach(imp => {
              if (imp.name === 'express') {
                if (!hasHelmet) {
                  issues.push({
                    id: "OWASP-A06-001",
                    guidanceId: "OWASP-A06-001:express-headers",
                    severity: "MEDIUM",
                    line: imp.line,
                    column: imp.column,
                    message: imp.type === 'import' 
                      ? "Risky library imported: 'express' (missing helmet protection)"
                      : "Risky library required: 'express' (missing helmet protection)",
                    suggestion: "Review the Express header-hardening configuration.",
                    cvssBaseScore,
                    cvssVector
                  });
                }
              } else if (imp.name === 'axios') {
                let hasUnsafeAxiosCall = false;
                if (axiosCalls.length > 0) {
                  hasUnsafeAxiosCall = axiosCalls.some(call => {
                    const arg = call.arg;
                    if (!arg) return false;
                    
                    let isUnsafe = false;
                    if (arg.type === 'Identifier') {
                      if (!isValidated(call.path, arg.name)) {
                        isUnsafe = true;
                      }
                    } else if (arg.type === 'TemplateLiteral') {
                      if (arg.expressions && arg.expressions.length > 0) {
                        const hasUnvalidatedExpression = arg.expressions.some(expr => {
                          if (expr.type === 'Identifier') {
                            return !isValidated(call.path, expr.name);
                          }
                          return true;
                        });
                        if (hasUnvalidatedExpression) {
                          isUnsafe = true;
                        }
                      }
                    } else if (arg.type === 'CallExpression') {
                      isUnsafe = true;
                    }
                    return isUnsafe;
                  });
                }

                if (hasUnsafeAxiosCall) {
                  issues.push({
                    id: "OWASP-A06-001",
                    guidanceId: "OWASP-A06-001:dynamic-request-target",
                    severity: "MEDIUM",
                    line: imp.line,
                    column: imp.column,
                    message: imp.type === 'import' 
                      ? "Risky library imported: 'axios' (detected dynamic/unvalidated request targets)"
                      : "Risky library required: 'axios' (detected dynamic/unvalidated request targets)",
                    suggestion: "Restrict outbound request targets using the application's approved destination policy.",
                    cvssBaseScore,
                    cvssVector
                  });
                }
              } else {
                issues.push({
                  id: "OWASP-A06-001",
                  guidanceId: "OWASP-A06-001:component-review",
                  severity: "MEDIUM",
                  line: imp.line,
                  column: imp.column,
                  message: imp.type === 'import'
                    ? `Risky library imported: '${imp.name}'`
                    : `Risky library required: '${imp.name}'`,
                  suggestion: "Identify the exact package version and applicable current advisory, then update or replace with compatibility tests.",
                  cvssBaseScore,
                  cvssVector
                });
              }
            });
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
          if (firstArg.type === 'Identifier') {
            if (!isValidated(path, firstArg.name)) {
              isUnsafe = true;
            }
          } else if (firstArg.type === 'TemplateLiteral') {
            if (firstArg.expressions && firstArg.expressions.length > 0) {
              const hasUnvalidatedExpression = firstArg.expressions.some(expr => {
                if (expr.type === 'Identifier') {
                  return !isValidated(path, expr.name);
                }
                return true;
              });
              if (hasUnvalidatedExpression) {
                isUnsafe = true;
              }
            }
          } else if (firstArg.type === 'CallExpression') {
            isUnsafe = true;
          }

          if (isUnsafe) {
            issues.push({
              id: "OWASP-A10-001",
              guidanceId: "OWASP-A10-001",
              severity: "HIGH",
              line: path.node.loc?.start?.line || 1,
              column: path.node.loc?.start?.column || 0,
              message: "Dynamic request target passed to HTTP client (SSRF risk)",
              suggestion: "On the server, enforce a destination policy before making outbound requests.",
              cvssBaseScore: 8.6,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'
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

