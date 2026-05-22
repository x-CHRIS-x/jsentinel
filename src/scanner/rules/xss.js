/**
 * A7 - XSS Rules
 * Targets: innerHTML, document.write, dangerouslySetInnerHTML
 */
export const xssRules = [
  {
    name: "inner-html-detection",
    id: "OWASP-A7-001",
    severity: "MEDIUM",
    message: "Use of innerHTML detected. This can lead to Cross-Site Scripting (XSS) if user-provided content is not properly sanitized.",
    owasp: "A7:2021-Cross-Site Scripting (XSS)",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'R',
      S:  'C',
      C:  'L',
      I:  'L',
      A:  'N',
      baseScore: 6.1,
      baseSeverity: 'MEDIUM',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 6.1;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
      return {
        AssignmentExpression(path) {
          // Detect: element.innerHTML = '...'
          if (path.node.left && path.node.left.property && path.node.left.property.name === 'innerHTML') {
            issues.push({
              id: "OWASP-A7-001",
              severity: "MEDIUM",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: "Dangerous use of innerHTML",
              suggestion: "Use .textContent or .innerText to set text, or use a sanitization library like DOMPurify.",
              cvssBaseScore,
              cvssVector
            });
          }
        }
      };
    }
  },
  {
    name: "document-write-detection",
    id: "OWASP-A7-002",
    severity: "CRITICAL",
    message: "Use of document.write() detected. This is a common XSS vector and can break page loading.",
    owasp: "A7:2021-XSS",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'R',
      S:  'C',
      C:  'H',
      I:  'H',
      A:  'N',
      baseScore: 9.3,
      baseSeverity: 'CRITICAL',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 9.3;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N';
      return {
        CallExpression(path) {
          // Detect: document.write('...')
          const callee = path.node.callee;
          if (callee.type === 'MemberExpression' && callee.object.name === 'document' && callee.property.name === 'write') {
            issues.push({
              id: "OWASP-A7-002",
              severity: "CRITICAL",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: "Dangerous use of document.write()",
              suggestion: "Use DOM manipulation methods like document.createElement() and appendChild() instead.",
              cvssBaseScore,
              cvssVector
            });
          }
        }
      };
    }
  },
  {
    name: "dangerously-set-inner-html-detection",
    id: "OWASP-A7-003",
    severity: "MEDIUM",
    message: "Use of dangerouslySetInnerHTML in React detected. This explicitly tells React to bypass XSS protections.",
    owasp: "A7:2021-XSS",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'R',
      S:  'C',
      C:  'L',
      I:  'L',
      A:  'N',
      baseScore: 6.1,
      baseSeverity: 'MEDIUM',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 6.1;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
      return {
        JSXAttribute(path) {
          // Detect: <div dangerouslySetInnerHTML={{...}} />
          if (path.node.name && path.node.name.name === 'dangerouslySetInnerHTML') {
            issues.push({
              id: "OWASP-A7-003",
              severity: "MEDIUM",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: "Dangerous use of dangerouslySetInnerHTML",
              suggestion: "Avoid setting raw HTML from user input. Use safer alternatives or a sanitization library.",
              cvssBaseScore,
              cvssVector
            });
          }
        }
      };
    }
  }
];
