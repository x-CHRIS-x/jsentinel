/**
 * A9 - Vulnerable and Outdated Components (Known Vulns)
 * Targets: Imports of known risky libraries
 */
export const knownVulnsRules = [
  {
    name: "risky-library-import",
    id: "OWASP-A9-001",
    severity: "MEDIUM",
    message: "Import of a potentially risky or often-vulnerable library detected.",
    owasp: "A9:2021-Vulnerable and Outdated Components",
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
      const riskyLibs = ['serialize-javascript', 'markdown-it', 'js-yaml', 'node-fetch'];
      return {
        ImportDeclaration(path) {
          const moduleName = path.node.source.value;
          if (riskyLibs.includes(moduleName)) {
            issues.push({
              id: "OWASP-A9-001",
              severity: "MEDIUM",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: `Risky library imported: '${moduleName}'`,
              suggestion: "Ensure this library is kept strictly up-to-date and its inputs are heavily sanitized.",
              cvssBaseScore,
              cvssVector
            });
          }
        },
        CallExpression(path) {
          // Handle require('...')
          if (path.node.callee.name === 'require') {
            const arg = path.node.arguments[0];
            if (arg && arg.type === 'StringLiteral') {
              if (riskyLibs.includes(arg.value)) {
                issues.push({
                  id: "OWASP-A9-001",
                  severity: "MEDIUM",
                  line: path.node.loc?.start?.line || 'unknown',
                  column: path.node.loc?.start?.column || 'unknown',
                  message: `Risky library required: '${arg.value}'`,
                  suggestion: "Ensure this library is kept strictly up-to-date and its inputs are heavily sanitized.",
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
