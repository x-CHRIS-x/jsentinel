/**
 * A03 - Injection / XSS Rules
 * Targets: innerHTML, document.write, dangerouslySetInnerHTML
 */
export const xssRules = [
  {
    name: "inner-html-detection",
    id: "OWASP-A03-006",
    severity: "HIGH",
    message: "Use of innerHTML detected. This can lead to Cross-Site Scripting (XSS) if user-provided content is not properly sanitized.",
    owasp: "A03:2021-Injection",
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
        AssignmentExpression(path) {
          if (path.node.left && path.node.left.property && path.node.left.property.name === 'innerHTML') {
            issues.push({
              id: "OWASP-A03-006",
              guidanceId: "OWASP-A03-006",
              severity: "HIGH",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: "Dangerous use of innerHTML",
              suggestion: "Prefer safe text/DOM APIs unless a documented HTML policy requires markup.",
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
    id: "OWASP-A03-007",
    severity: "CRITICAL",
    message: "Use of document.write() detected. This is a common XSS vector and can break page loading.",
    owasp: "A03:2021-Injection",
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
          const callee = path.node.callee;
          if (callee.type === 'MemberExpression' && callee.object.name === 'document' && callee.property.name === 'write') {
            issues.push({
              id: "OWASP-A03-007",
              guidanceId: "OWASP-A03-007",
              severity: "CRITICAL",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: "Dangerous use of document.write()",
              suggestion: "Replace the page-writing strategy according to load timing and intended output.",
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
    id: "OWASP-A03-008",
    severity: "HIGH",
    message: "Use of dangerouslySetInnerHTML in React detected. This explicitly tells React to bypass XSS protections.",
    owasp: "A03:2021-Injection",
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
        JSXAttribute(path) {
          if (path.node.name && path.node.name.name === 'dangerouslySetInnerHTML') {
            issues.push({
              id: "OWASP-A03-008",
              guidanceId: "OWASP-A03-008",
              severity: "HIGH",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: "Dangerous use of dangerouslySetInnerHTML",
              suggestion: "Prefer React's normal escaped rendering; use a vetted sanitizer only for intentional HTML.",
              cvssBaseScore,
              cvssVector
            });
          }
        }
      };
    }
  }
];
