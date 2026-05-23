/**
 * A8 - Software and Data Integrity Failures (Deserialization / Prototype Pollution)
 * Targets: Unsafe JSON.parse(), prototype pollution (__proto__, constructor.prototype), unsafe Object.assign()
 */
export const deserializationRules = [
  {
    name: "unsafe-json-parse",
    id: "OWASP-A8-001",
    severity: "LOW",
    message: "Use of JSON.parse() detected. Ensure the input string is validated and comes from a trusted source.",
    owasp: "A8:2021-Software and Data Integrity Failures",
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
            issues.push({
              id: "OWASP-A8-001",
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
      };
    }
  },
  {
    name: "prototype-pollution",
    id: "OWASP-A8-002",
    severity: "HIGH",
    message: "Potential prototype pollution detected via direct modification of __proto__ or constructor.prototype. This can alter object structures globally.",
    owasp: "A8:2021-Software and Data Integrity Failures",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S:  'U',
      C:  'H',
      I:  'H',
      A:  'N',
      baseScore: 7.5,
      baseSeverity: 'HIGH',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 7.5;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N';
      return {
        AssignmentExpression(path) {
          const left = path.node.left;
          if (!left) return;

          let isPollution = false;
          
          if (left.type === 'MemberExpression') {
            // Check for assignment to __proto__
            if (left.property && left.property.name === '__proto__') {
              isPollution = true;
            }
            // Check for assignment to constructor.prototype
            if (left.object && left.object.type === 'MemberExpression') {
              if (left.object.property && left.object.property.name === 'constructor' && 
                  left.property && left.property.name === 'prototype') {
                isPollution = true;
              }
            }
          }

          if (isPollution) {
            issues.push({
              id: "OWASP-A8-002",
              severity: "HIGH",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: "Potential prototype pollution assignment detected",
              suggestion: "Avoid direct modification of __proto__ or constructor.prototype. Use Map objects, or use Object.create(null) for safe storage.",
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
    id: "OWASP-A8-003",
    severity: "MEDIUM",
    message: "Object.assign() used with a dynamic second argument. This can result in prototype pollution or object integrity failures if input is user-controlled.",
    owasp: "A8:2021-Software and Data Integrity Failures",
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
            if (args.length >= 2) {
              const firstArg = args[0];
              const secondArg = args[1];
              // First argument is empty object literal, second is variable
              if (firstArg.type === 'ObjectExpression' && secondArg.type === 'Identifier') {
                issues.push({
                  id: "OWASP-A8-003",
                  severity: "MEDIUM",
                  line: path.node.loc?.start?.line || 'unknown',
                  column: path.node.loc?.start?.column || 'unknown',
                  message: "Unsafe use of Object.assign() with dynamic source argument",
                  suggestion: "Validate and sanitize dynamic input arguments, or use a strict schema validator before merging objects.",
                  cvssBaseScore,
                  cvssVector
                });
              }
            }
          }
        }
      };
    }
  }
];
