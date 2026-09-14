/**
 * A01 - Broken Access Control Rules
 * Targets: Open redirects, client-side role checks guarding conditional logic
 */
function isDescendant(childPath, ancestorPath) {
  let cur = childPath;
  while (cur) {
    if (cur === ancestorPath) return true;
    cur = cur.parentPath;
  }
  return false;
}

function getValidAllowlistBinding(scope, arrayName) {
  if (!scope || !arrayName) return null;
  const binding = scope.getBinding(arrayName);
  if (!binding) return null;

  if (!binding.constant || (binding.constantViolations && binding.constantViolations.length > 0)) {
    return null;
  }

  const declarator = binding.path;
  if (!declarator || !declarator.node || declarator.node.type !== 'VariableDeclarator') {
    return null;
  }

  const init = declarator.node.init;
  if (!init || init.type !== 'ArrayExpression' || !Array.isArray(init.elements) || init.elements.length === 0) {
    return null;
  }

  for (const elem of init.elements) {
    if (!elem) return null;
    if (elem.type === 'StringLiteral') continue;
    if (elem.type === 'Literal' && typeof elem.value === 'string') continue;
    if (elem.type === 'TemplateLiteral' && Array.isArray(elem.expressions) && elem.expressions.length === 0) continue;
    return null;
  }

  const mutatingMethods = new Set([
    'push', 'pop', 'shift', 'unshift', 'splice', 'reverse', 'sort', 'fill', 'copyWithin'
  ]);

  const visitedBindings = new Set([binding]);
  const bindingQueue = [binding];

  while (bindingQueue.length > 0) {
    const currentBinding = bindingQueue.shift();
    if (!Array.isArray(currentBinding.referencePaths)) continue;

    for (const refPath of currentBinding.referencePaths) {
      let parent = refPath.parentPath;
      while (parent && parent.isParenthesizedExpression && parent.isParenthesizedExpression()) {
        parent = parent.parentPath;
      }
      if (!parent) continue;

      if (parent.isVariableDeclarator && parent.isVariableDeclarator() && parent.node.init === refPath.node) {
        if (parent.node.id && parent.node.id.type === 'Identifier') {
          const aliasBinding = refPath.scope?.getBinding(parent.node.id.name);
          if (aliasBinding && !visitedBindings.has(aliasBinding)) {
            visitedBindings.add(aliasBinding);
            bindingQueue.push(aliasBinding);
          }
        }
      }

      if (parent.isAssignmentExpression && parent.isAssignmentExpression() && parent.node.right === refPath.node) {
        if (parent.node.left && parent.node.left.type === 'Identifier') {
          const aliasBinding = refPath.scope?.getBinding(parent.node.left.name);
          if (aliasBinding && !visitedBindings.has(aliasBinding)) {
            visitedBindings.add(aliasBinding);
            bindingQueue.push(aliasBinding);
          }
        }
      }

      if (parent.isMemberExpression && parent.isMemberExpression() && parent.node.object === refPath.node) {
        let grandParent = parent.parentPath;
        while (grandParent && grandParent.isParenthesizedExpression && grandParent.isParenthesizedExpression()) {
          grandParent = grandParent.parentPath;
        }
        if (!grandParent) continue;

        if (grandParent.isCallExpression && grandParent.isCallExpression() && grandParent.node.callee === parent.node) {
          const prop = parent.node.property;
          const methodName = prop.name || (prop.type === 'StringLiteral' ? prop.value : null);
          if (mutatingMethods.has(methodName)) {
            return null;
          }
        }

        if (grandParent.isAssignmentExpression && grandParent.isAssignmentExpression() && grandParent.node.left === parent.node) {
          return null;
        }

        if (grandParent.isUpdateExpression && grandParent.isUpdateExpression() && grandParent.node.argument === parent.node) {
          return null;
        }

        if (grandParent.isUnaryExpression && grandParent.isUnaryExpression() &&
            grandParent.node.operator === 'delete' && grandParent.node.argument === parent.node) {
          return null;
        }
      }
    }
  }

  return binding;
}

function parseValidationCondition(node, varName, scope, targetBinding) {
  if (!node || !scope) return null;

  while (node.type === 'ParenthesizedExpression') {
    node = node.expression;
  }

  if (node.type === 'UnaryExpression' && node.operator === '!') {
    const inner = parseValidationCondition(node.argument, varName, scope, targetBinding);
    if (inner && inner.kind === 'POSITIVE') {
      return { kind: 'NEGATED', arrayName: inner.arrayName };
    }
    return null;
  }

  if (node.type === 'CallExpression') {
    const callee = node.callee;
    if (callee && callee.type === 'MemberExpression' && callee.property && callee.property.type === 'Identifier') {
      const propName = callee.property.name;
      if (propName === 'includes') {
        const obj = callee.object;
        if (obj && obj.type === 'Identifier') {
          const arrayName = obj.name;
          const arg = node.arguments && node.arguments[0];
          if (arg && arg.type === 'Identifier' && arg.name === varName) {
            if (scope.getBinding(varName) === targetBinding) {
              const allowBinding = getValidAllowlistBinding(scope, arrayName);
              if (allowBinding) {
                return { kind: 'POSITIVE', arrayName };
              }
            }
          }
        }
      }
    }
    return null;
  }

  if (node.type === 'BinaryExpression') {
    let callNode = null;
    let otherNode = null;
    let op = node.operator;

    if (node.left && node.left.type === 'CallExpression') {
      callNode = node.left;
      otherNode = node.right;
    } else if (node.right && node.right.type === 'CallExpression') {
      callNode = node.right;
      otherNode = node.left;
      if (op === '>') op = '<';
      else if (op === '<') op = '>';
      else if (op === '>=') op = '<=';
      else if (op === '<=') op = '>=';
    }

    if (callNode && callNode.callee && callNode.callee.type === 'MemberExpression' &&
        callNode.callee.property && callNode.callee.property.name === 'indexOf') {
      const obj = callNode.callee.object;
      if (obj && obj.type === 'Identifier') {
        const arrayName = obj.name;
        const arg = callNode.arguments && callNode.arguments[0];
        if (arg && arg.type === 'Identifier' && arg.name === varName) {
          if (scope.getBinding(varName) === targetBinding) {
            const allowBinding = getValidAllowlistBinding(scope, arrayName);
            if (allowBinding) {
              let compVal = null;
              if (otherNode && otherNode.type === 'UnaryExpression' && otherNode.operator === '-' &&
                  otherNode.argument && otherNode.argument.type === 'NumericLiteral' && otherNode.argument.value === 1) {
                compVal = -1;
              } else if (otherNode && otherNode.type === 'NumericLiteral') {
                compVal = otherNode.value;
              }

              if (compVal === -1) {
                if (op === '!==' || op === '!=') return { kind: 'POSITIVE', arrayName };
                if (op === '===' || op === '==') return { kind: 'NEGATED', arrayName };
                if (op === '>') return { kind: 'POSITIVE', arrayName };
                if (op === '<=') return { kind: 'NEGATED', arrayName };
              } else if (compVal === 0) {
                if (op === '>=') return { kind: 'POSITIVE', arrayName };
                if (op === '<') return { kind: 'NEGATED', arrayName };
              }
            }
          }
        }
      }
    }
    return null;
  }

  return null;
}

function doesConsequentUnconditionallyExit(node) {
  if (!node) return false;
  if (node.type === 'ReturnStatement' || node.type === 'ThrowStatement') {
    return true;
  }
  if (node.type === 'BlockStatement') {
    const body = node.body;
    if (!Array.isArray(body) || body.length === 0) return false;
    const lastStmt = body[body.length - 1];
    if (lastStmt && (lastStmt.type === 'ReturnStatement' || lastStmt.type === 'ThrowStatement')) {
      return true;
    }
  }
  return false;
}

function isTargetReassignedInPath(targetBinding, startLoc, endLoc) {
  if (!targetBinding || !targetBinding.constantViolations || targetBinding.constantViolations.length === 0) {
    return false;
  }
  for (const violation of targetBinding.constantViolations) {
    const loc = violation.node?.loc?.start;
    if (!loc || !startLoc || !endLoc) {
      return true;
    }
    if ((loc.line > startLoc.line || (loc.line === startLoc.line && loc.column >= startLoc.column)) &&
        (loc.line < endLoc.line || (loc.line === endLoc.line && loc.column <= endLoc.column))) {
      return true;
    }
  }
  return false;
}

function isValidated(path, varName) {
  if (!varName || !path || !path.scope) return false;
  const targetBinding = path.scope.getBinding(varName);

  // Pattern 1: Check enclosing IfStatements (matching allowed branch)
  let currentPath = path;
  while (currentPath) {
    if (currentPath.isIfStatement && currentPath.isIfStatement()) {
      const ifPath = currentPath;
      const testNode = ifPath.node.test;
      const cond = parseValidationCondition(testNode, varName, ifPath.scope, targetBinding);

      if (cond) {
        const consequentPath = ifPath.get('consequent');
        const alternatePath = ifPath.node.alternate ? ifPath.get('alternate') : null;

        let inMatchingBranch = false;
        let branchStart = null;
        const branchEnd = path.node.loc?.start;

        if (cond.kind === 'POSITIVE' && isDescendant(path, consequentPath)) {
          inMatchingBranch = true;
          branchStart = consequentPath.node.loc?.start;
        } else if (cond.kind === 'NEGATED' && alternatePath && isDescendant(path, alternatePath)) {
          inMatchingBranch = true;
          branchStart = alternatePath.node.loc?.start;
        }

        if (inMatchingBranch) {
          if (!isTargetReassignedInPath(targetBinding, branchStart, branchEnd)) {
            return true;
          }
        }
      }
    }

    if (currentPath.isFunction && currentPath.isFunction()) {
      break;
    }
    currentPath = currentPath.parentPath;
  }

  // Pattern 2: Check preceding sibling statements for early return guard
  let stmt = null;
  try {
    stmt = path.getStatementParent ? path.getStatementParent() : null;
  } catch {
    stmt = null;
  }

  while (stmt) {
    const parentBlock = stmt.parentPath;
    if (parentBlock && Array.isArray(parentBlock.node?.body)) {
      const siblings = parentBlock.get('body');
      if (Array.isArray(siblings)) {
        const currentIndex = siblings.findIndex(s => s === stmt);

        if (currentIndex > 0) {
          for (let i = currentIndex - 1; i >= 0; i--) {
            const sibling = siblings[i];
            if (sibling.isIfStatement && sibling.isIfStatement()) {
              const ifNode = sibling.node;
              const cond = parseValidationCondition(ifNode.test, varName, sibling.scope, targetBinding);

              if (cond && cond.kind === 'NEGATED' && doesConsequentUnconditionallyExit(ifNode.consequent)) {
                const guardEnd = ifNode.loc?.end;
                const sinkStart = path.node.loc?.start;
                if (!isTargetReassignedInPath(targetBinding, guardEnd, sinkStart)) {
                  return true;
                }
              }
            }
          }
        }
      }
    }

    if (!parentBlock || (parentBlock.isFunction && parentBlock.isFunction()) || (parentBlock.isProgram && parentBlock.isProgram())) {
      break;
    }
    try {
      stmt = parentBlock.getStatementParent();
    } catch {
      break;
    }
  }

  return false;
}

export const accessControlRules = [
  {
    name: "open-redirect",
    id: "OWASP-A01-001",
    severity: "HIGH",
    message: "Potential open redirect vulnerability. Assigning window.location or calling location.replace() with dynamic variables can let attackers redirect users to malicious websites.",
    owasp: "A01:2021-Broken Access Control",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'R',
      S:  'C',
      C:  'N',
      I:  'H',
      A:  'N',
      baseScore: 7.4,
      baseSeverity: 'HIGH',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 7.4;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N';
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
                    line: path.node.loc?.start?.line || 'unknown',
                    column: path.node.loc?.start?.column || 'unknown',
                    message: "Unsafe location redirection using dynamic value",
                    suggestion: "Allow only configured, trusted destinations.",
                    cvssBaseScore,
                    cvssVector
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
            const isLocationObject =
              callee.object.name === 'location' ||
              (callee.object.type === 'MemberExpression' &&
               callee.object.object.name === 'window' &&
               callee.object.property.name === 'location');

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
                    line: path.node.loc?.start?.line || 'unknown',
                    column: path.node.loc?.start?.column || 'unknown',
                    message: "Unsafe location.replace() using dynamic value",
                    suggestion: "Allow only configured, trusted destinations.",
                    cvssBaseScore,
                    cvssVector
                  });
                }
              }
            }
          }
        }
      };
    }
  },
  {
    name: "client-side-role-check",
    id: "OWASP-A01-002",
    severity: "MEDIUM",
    message: "Client-side role or authorization check detected. Restricting features in the client browser only can be bypassed. Ensure security checks are enforced on the backend server.",
    owasp: "A01:2021-Broken Access Control",
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
        return lower === 'role' || lower === 'isadmin' || lower === 'admin';
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
              id: "OWASP-A01-002",
              guidanceId: "OWASP-A01-002",
              severity: "MEDIUM",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: "Client-side role or authorization check in condition statement",
              suggestion: "Enforce authorization for every protected action on the server/API.",
              cvssBaseScore,
              cvssVector
            });
          }
        }
      };
    }
  }
];

