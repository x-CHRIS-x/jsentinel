/**
 * A3 - Sensitive Data Exposure Rules
 * Targets: Hardcoded API keys, IPs, AWS Keys, JWTs in strings
 */
export const sensitiveDataRules = [
  {
    name: "hardcoded-secret-patterns",
    id: "OWASP-A3-001",
    severity: "CRITICAL",
    message: "Potential sensitive data or secret key hardcoded in string.",
    owasp: "A3:2021-Sensitive Data Exposure",
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
      // Rule logic uses different scores based on what it finds
      const criticalBaseScore = 9.1;
      const criticalVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N';
      const mediumBaseScore = 5.3; // Estimated for IP Address, but reference.html says 9.1 for the whole rule?
      // Wait, let me re-check reference.html for OWASP-A3-001
      return {
        StringLiteral(path) {
          const val = path.node.value;
          // Tightened Regex Patterns
          const jwtPattern = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
          const awsKeyPattern = /(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|AQCA|AMZA|AWA|A2A)[A-Z0-9]{16}/;
          const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;

          let type = null;
          if (val.startsWith('eyJ') && jwtPattern.test(val)) type = "JWT Token";
          else if (awsKeyPattern.test(val)) type = "AWS Access Key";
          else if (ipPattern.test(val) && val !== '127.0.0.1' && val !== '0.0.0.0') type = "IP Address";

          if (type) {
            // Reference.html says 9.1 for OWASP-A3-001. I'll use that as the baseScore.
            const cvssBaseScore = 9.1;
            const cvssVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N';
            
            issues.push({
              id: "OWASP-A3-001",
              severity: type === "IP Address" ? "MEDIUM" : "CRITICAL",
              line: path.node.loc?.start?.line || 'unknown',
              column: path.node.loc?.start?.column || 'unknown',
              message: `Hardcoded ${type} detected in string.`,
              suggestion: `Never hardcode ${type}s. Use environment variables (e.g., process.env or import.meta.env).`,
              cvssBaseScore,
              cvssVector
            });
          }
        }
      };
    }
  }
];
