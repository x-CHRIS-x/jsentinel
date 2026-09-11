/**
 * A06 - Vulnerable and Outdated Components (Known Vulns)
 * Targets: Imports of known risky libraries (component-review advisory signal)
 *
 * Active browser check: OWASP-A06-001 (component-review branch only)
 *
 * This check is an advisory-only import review signal. An import alone does
 * not establish that an affected package version is in use. The finding
 * prompts the developer to check the actual installed version and current
 * advisories. Document this as a limitation if used in the paper.
 *
 * RETIRED FROM ACTIVE BROWSER SCANNING (Phase 01):
 *   express-headers branch — Checked whether Express was imported without
 *     helmet. Express is a Node.js server framework; browser JavaScript
 *     cannot import or run it. This check produced false positives on any
 *     browser code that happened to import a package named 'express'.
 *   dynamic-request-target branch — Tracked axios calls with dynamic URL
 *     arguments and classified them as SSRF risk. This is the same incorrect
 *     SSRF classification as OWASP-A10-001. Browser axios calls are client
 *     HTTP requests, not server-side request forgery.
 *
 * Rule ID and guidance entries are retained so historical scan results
 * that reference these sub-variants can still resolve guidance.
 */
export const knownVulnsRules = [
  {
    name: "risky-library-import",
    id: "OWASP-A06-001",
    severity: "MEDIUM",
    message: "Import of a potentially risky or often-vulnerable library detected. Check the installed version against current security advisories.",
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

      // Libraries with known vulnerability history or known risky usage patterns.
      // 'express' and 'axios' remain listed because they can appear in browser-adjacent
      // code. Only the component-review signal fires — no server-header or SSRF logic.
      const riskyLibs = [
        'serialize-javascript', 'markdown-it', 'js-yaml', 'node-fetch',
        'lodash', 'axios', 'jsonwebtoken', 'express', 'mongoose', 'vm2'
      ];

      const imports = [];

      return {
        ImportDeclaration(path) {
          const moduleName = path.node.source.value;
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
        },
        Program: {
          exit() {
            // Component-review branch only: flag any risky library import.
            // An import does not establish an affected version. This is an
            // advisory signal prompting a manual version and advisory check.
            imports.forEach(imp => {
              issues.push({
                id: "OWASP-A06-001",
                guidanceId: "OWASP-A06-001:component-review",
                severity: "MEDIUM",
                line: imp.line,
                column: imp.column,
                message: imp.type === 'import'
                  ? `Risky library imported: '${imp.name}' — verify the installed version against current security advisories`
                  : `Risky library required: '${imp.name}' — verify the installed version against current security advisories`,
                suggestion: "Identify the exact package version and applicable current advisory, then update or replace with compatibility tests.",
                cvssBaseScore,
                cvssVector
              });
            });
          }
        }
      };
    }
  }
];
