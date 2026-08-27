/**
 * A02 - Cryptographic Failures / Sensitive Data Exposure Rules
 * Targets: Hardcoded API keys, IPs, AWS Keys, JWTs, secret variables, sensitive query strings
 */
export const sensitiveDataRules = [
  {
    name: "hardcoded-secret-patterns",
    id: "OWASP-A02-005",
    severity: "CRITICAL",
    message: "Potential sensitive data or secret key hardcoded in string.",
    owasp: "A02:2021-Cryptographic Failures",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S:  'U',
      C:  'H',
      I:  'H',
      A:  'N',
      baseScore: 9.1,
      baseSeverity: 'CRITICAL',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
    },
    visitor: (issues) => {
      return {
        StringLiteral(path) {
          const val = path.node.value;
          if (!val) return;
          
          const jwtPattern = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
          const awsKeyPattern = /(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|AQCA|AMZA|AWA|A2A)[A-Z0-9]{16}/;
          const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;

          let type = null;
          if (val.startsWith('eyJ') && jwtPattern.test(val)) type = "JWT Token";
          else if (awsKeyPattern.test(val)) type = "AWS Access Key";
          else if (ipPattern.test(val) && val !== '127.0.0.1' && val !== '0.0.0.0') type = "IP Address";

          if (type) {
            const isNetworkAddress = type === "IP Address";
            const guidanceId = isNetworkAddress ? "OWASP-A02-005:network-address" : "OWASP-A02-005:credential";
            const cvssBaseScore = isNetworkAddress ? 5.3 : 9.1;
            const cvssVector = isNetworkAddress
              ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
              : 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N';
            const suggestion = isNetworkAddress
              ? "Review whether the endpoint address is sensitive configuration before changing it."
              : "Revoke, rotate, and move genuine secrets out of source and client bundles.";
            
            issues.push({
              id: "OWASP-A02-005",
              guidanceId,
              severity: isNetworkAddress ? "MEDIUM" : "CRITICAL",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: `Hardcoded ${type} detected in string.`,
              suggestion,
              cvssBaseScore,
              cvssVector
            });
          }
        }
      };
    }
  },
  {
    name: "hardcoded-api-key",
    id: "OWASP-A02-006",
    severity: "CRITICAL",
    message: "Potential sensitive API key or secret hardcoded in variable declaration.",
    owasp: "A02:2021-Cryptographic Failures",
    cvss: {
      AV: 'N',
      AC: 'L',
      PR: 'N',
      UI: 'N',
      S:  'U',
      C:  'H',
      I:  'H',
      A:  'N',
      baseScore: 9.1,
      baseSeverity: 'CRITICAL',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
    },
    visitor: (issues) => {
      const cvssBaseScore = 9.1;
      const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N';
      return {
        VariableDeclarator(path) {
          const varName = path.node.id.name?.toLowerCase();
          if (varName && (varName.includes('key') || varName.includes('secret') || varName.includes('token') || varName.includes('api'))) {
            // Exclude non-key identifiers like apiUrl, endpoint, path, route, host
            if (varName.includes('url') || varName.includes('uri') || varName.includes('endpoint') || varName.includes('path') || varName.includes('route') || varName.includes('host') || varName.includes('domain')) {
              return;
            }
            const init = path.node.init;
            if (init && init.type === 'StringLiteral' && init.value.length > 8) {
              const val = init.value.toLowerCase();
              // Exclude non-sensitive placeholders and network URLs/paths
              if (val.includes('placeholder') || val.includes('dummy') || val.includes('test') || val.includes('example') ||
                  val.startsWith('http://') || val.startsWith('https://') || val.startsWith('/')) {
                return;
              }
              issues.push({
                id: "OWASP-A02-006",
                guidanceId: "OWASP-A02-006",
                severity: "CRITICAL",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: `Hardcoded API key or secret found in variable '${path.node.id.name}'`,
                suggestion: "Determine whether the key is public/restricted or secret, then protect and rotate it accordingly.",
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
    name: "sensitive-query-string",
    id: "OWASP-A02-007",
    severity: "MEDIUM",
    message: "Sensitive information embedded in URL query parameters. This can expose secrets through browser history or server logs.",
    owasp: "A02:2021-Cryptographic Failures",
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
        StringLiteral(path) {
          const val = path.node.value;
          if (val && typeof val === 'string') {
            const lowerVal = val.toLowerCase();
            if (lowerVal.includes('?password=') || lowerVal.includes('&password=') ||
                lowerVal.includes('?token=') || lowerVal.includes('&token=') ||
                lowerVal.includes('?key=') || lowerVal.includes('&key=') ||
                lowerVal.includes('?secret=') || lowerVal.includes('&secret=')) {
              issues.push({
                id: "OWASP-A02-007",
                guidanceId: "OWASP-A02-007",
                severity: "MEDIUM",
                line: path.node.loc?.start?.line || 'unknown',
                column: path.node.loc?.start?.column || 'unknown',
                message: "Sensitive credentials embedded in URL query string",
                suggestion: "Remove credentials from URLs and use the protocol's secure body/header mechanism over TLS.",
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
