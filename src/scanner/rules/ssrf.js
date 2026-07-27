/**
 * A10 - Server-Side Request Forgery Rules
 * Targets: fetch(), axios.get/post calls with dynamic variables or template literals
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

export const ssrfRules = [
  {
    name: "ssrf-detection",
    id: "OWASP-A10-001",
    severity: "HIGH",
    message: "Potential Server-Side Request Forgery (SSRF) risk. Dynamic URLs passed to HTTP clients can allow users to request internal resources or trigger actions.",
    owasp: "A10:2021-Server-Side Request Forgery (SSRF)",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S:  'C',
      C:  'H',
      I:  'N',
      A:  'N',
      baseScore: 8.6,
      baseSeverity: 'HIGH',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 8.6;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N';
      return {
        CallExpression(path) {
          const callee = path.node.callee;
          if (!callee) return;

          let isHttpClientCall = false;
          let firstArg = null;

          // Check for fetch(dynamic)
          if (callee.type === 'Identifier' && callee.name === 'fetch') {
            isHttpClientCall = true;
            firstArg = path.node.arguments[0];
          }
          // Check for axios.get(dynamic) or axios.post(dynamic)
          else if (callee.type === 'MemberExpression') {
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
                severity: "HIGH",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: "Dynamic request target passed to HTTP client (SSRF risk)",
                suggestion: "Do not allow user-supplied input to directly construct connection URLs. Use a strict request whitelist.",
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
