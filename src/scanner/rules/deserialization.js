/**
 * A08 - Software and Data Integrity Failures (Deserialization / Prototype Pollution)
 * Targets: Unsafe JSON.parse(), prototype pollution (__proto__, constructor.prototype), unsafe Object.assign()
 */
export const deserializationRules = [
  {
    name: "unsafe-json-parse",
    id: "OWASP-A08-001",
    severity: "LOW",
    message: "Use of JSON.parse() detected. Ensure the input string is validated and comes from a trusted source.",
    owasp: "A08:2021-Software and Data Integrity Failures",
    cvss: {
      AV: 'N',
      AC: 'H',
      PR: 'N',
      UI: 'N',
      S:  'U',
      C:  'N',
      I:  'L',
      A:  'N',
      baseScore: 3.7,
      baseSeverity: 'LOW',
      vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 3.7;
      const cvssVector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N';
      return {
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
                severity: "LOW",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: "JSON.parse() usage detected",
                suggestion: "If the input comes from an untrusted user, validate the structure of the resulting object immediately.",
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
    name: "prototype-pollution",
    id: "OWASP-A08-002",
    severity: "HIGH",
    message: "Potential prototype pollution detected via direct modification of __proto__ or constructor.prototype. This can alter object structures globally.",
    owasp: "A08:2021-Software and Data Integrity Failures",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S:  'U',
      C:  'N',
      I:  'H',
      A:  'N',
      baseScore: 7.5,
      baseSeverity: 'HIGH',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 7.5;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N';
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
              severity: "HIGH",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: "Potential prototype pollution assignment detected",
              suggestion: "Avoid direct modification of __proto__ or constructor.prototype. Use Map objects, or use Object.create(null).",
              cvssBaseScore,
              cvssVector
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
    message: "Object.assign() used with a dynamic second argument. This can result in prototype pollution or object integrity failures if input is user-controlled.",
    owasp: "A08:2021-Software and Data Integrity Failures",
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
      return {
        CallExpression(path) {
          const callee = path.node.callee;
          if (callee.type === 'MemberExpression' && callee.object.name === 'Object' && callee.property.name === 'assign') {
            const args = path.node.arguments;
            if (args.length >= 2 && args[0].type === 'Identifier') {
              issues.push({
                id: "OWASP-A08-003",
                severity: "MEDIUM",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: "Unsafe use of Object.assign() mutating target object",
                suggestion: "Validate and sanitize dynamic input arguments, or merge properties into a safe new object Object.assign({}, target, ...).",
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
