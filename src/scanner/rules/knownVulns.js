/**
 * A06 - Vulnerable and Outdated Components (Known Vulns)
 * Targets: Imports of known risky libraries
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

export const knownVulnsRules = [
  {
    name: "risky-library-import",
    id: "OWASP-A06-001",
    severity: "MEDIUM",
    message: "Import of a potentially risky or often-vulnerable library detected.",
    owasp: "A06:2021-Vulnerable and Outdated Components",
    cvss: {
      AV: 'N',
      AC: 'H',
      PR: 'N',
      UI: 'N',
      S:  'U',
      C:  'L',
      I:  'L',
      A:  'N',
      baseScore: 4.8,
      baseSeverity: 'MEDIUM',
      vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 4.8;
      const cvssVector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N';
      const riskyLibs = [
        'serialize-javascript', 'markdown-it', 'js-yaml', 'node-fetch',
        'lodash', 'axios', 'jsonwebtoken', 'express', 'mongoose', 'vm2'
      ];

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
