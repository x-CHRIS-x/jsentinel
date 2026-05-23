/**
 * A10 - Server-Side Request Forgery Rules
 * Targets: fetch(), axios.get/post calls with dynamic variables or template literals
 */
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
            // Unsafe if argument is an Identifier or a dynamic TemplateLiteral (i.e. contains expressions)
            let isUnsafe = false;
            
            if (firstArg.type === 'Identifier') {
              isUnsafe = true;
            } else if (firstArg.type === 'TemplateLiteral') {
              if (firstArg.expressions && firstArg.expressions.length > 0) {
                isUnsafe = true;
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
