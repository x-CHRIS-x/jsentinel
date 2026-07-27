import * as Babel from '@babel/standalone';
import { calculateShannonEntropy } from './entropy';

/**
 * Main scanning engine that coordinates file parsing and rule execution.
 * Includes built-in Shannon Entropy analysis and Confidence Level evaluation.
 * 
 * @param {File} file - Browser File object.
 * @param {Array} rules - Array of security rule objects.
 * @returns {Promise<Object>} - Results including AST and any vulnerabilities.
 */
export const scanFile = async (file, rules) => {
  let hasError = false;
  try {
    const code = await file.text();
    const issues = [];

    // Built-in Shannon Entropy Rule for Detecting Secrets
    const runEntropyCheck = (node) => {
      const val = node.value;
      // Secrets are generally longer than 8 characters, lack whitespace, and are not SVG paths or URLs
      if (val && val.length > 8 && !val.includes(' ')) {
        // Exclude common dynamic structures or static assets
        const isCommonAsset = 
          val.startsWith('http://') || 
          val.startsWith('https://') || 
          val.startsWith('data:') ||
          (val.startsWith('M') && val.includes('z')) || // SVG path indicator
          val.endsWith('.css') || 
          val.endsWith('.png') || 
          val.endsWith('.jpg') || 
          val.endsWith('.svg');

        if (!isCommonAsset) {
          const entropy = calculateShannonEntropy(val);
          if (entropy > 4.5) {
            issues.push({
              id: "OWASP-A3-ENTROPY",
              severity: "MEDIUM",
              line: node.loc?.start?.line || 'unknown',
              column: node.loc?.start?.column || 'unknown',
              message: `High-entropy string detected (randomness: ${entropy} bits/char)`,
              suggestion: "Verify if this string represents a password, token, or private key, and move it to environment variables.",
              cvssBaseScore: 5.3,
              cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
              confidence: "LOW"
            });
          }
        }
      }
    };

    // Run rules via @babel/standalone parser
    for (const rule of rules) {
      try {
        Babel.transform(code, {
          filename: file.name,
          ast: false,
          code: false,
          highlightCode: false,
          parserOpts: {
            errorRecovery: true // Allows partial scans of broken files
          },
          presets: [
            file.name.endsWith('.ts') || file.name.endsWith('.tsx') ? 'typescript' : null,
            ['react', { runtime: 'automatic' }]
          ].filter(Boolean),
          plugins: [
            () => ({
              visitor: rule.visitor(issues)
            })
          ]
        });
      } catch (ruleError) {
        console.error(`Error running rule ${rule.name} on ${file.name}:`, ruleError);
        hasError = true;
      }
    }

    // Run custom visitor for Shannon Entropy
    try {
      Babel.transform(code, {
        filename: file.name,
        ast: false,
        code: false,
        highlightCode: false,
        parserOpts: {
          errorRecovery: true
        },
        presets: [
          file.name.endsWith('.ts') || file.name.endsWith('.tsx') ? 'typescript' : null,
          ['react', { runtime: 'automatic' }]
        ].filter(Boolean),
        plugins: [
          () => ({
            visitor: {
              StringLiteral(path) {
                runEntropyCheck(path.node);
              }
            }
          })
        ]
      });
    } catch (entropyError) {
      console.error(`Error running Shannon Entropy check on ${file.name}:`, entropyError);
      hasError = true;
    }

    // Post-Process issues to assign confidence levels.
    // Confidence answers: "How likely is this flagged finding to be a
    // real exploitable vulnerability rather than a false positive?"
    //
    // HIGH:   Almost certainly a real vulnerability. The detected pattern
    //         has virtually no safe use case in production code.
    // MEDIUM: Likely a real vulnerability, but context matters. The pattern
    //         could be used safely in certain controlled scenarios.
    // LOW:    Informational or probabilistic. The finding may or may not
    //         represent a real security issue depending on project context.
    issues.forEach(issue => {
      // If confidence level is already defined (e.g. by Entropy), retain it
      if (issue.confidence) return;

      let confidence = "MEDIUM"; // Default for unrecognized rules

      const messageLower = issue.message?.toLowerCase() || "";
      const ruleId = issue.id;

      // ---------------------------------------------------------------
      // HIGH confidence: Almost certainly a real vulnerability.
      // These patterns have virtually no legitimate safe use case.
      // If the scanner flags them, the code is almost certainly insecure.
      // ---------------------------------------------------------------
      const highConfidenceRules = [
        'OWASP-A2-003', // Insecure cookie missing HttpOnly/Secure: definitively misconfigured
        'OWASP-A6-002', // Wildcard CORS *: definitively permissive, no ambiguity
        'OWASP-A7-002', // document.write(): no legitimate modern use case
        'OWASP-A8-002', // Prototype pollution via __proto__: always dangerous
      ];

      // ---------------------------------------------------------------
      // MEDIUM confidence: Likely a real vulnerability, but the pattern
      // could have legitimate uses depending on developer intent or
      // surrounding context that the static analyzer cannot evaluate.
      // ---------------------------------------------------------------
      const mediumConfidenceRules = [
        'OWASP-A1-001', // eval(): dangerous, but sometimes intentional in dev tools or sandboxes
        'OWASP-A1-002', // String timer: dangerous, but may be legacy code with known safe strings
        'OWASP-A1-003', // new Function(): dangerous, but used intentionally in template engines
        'OWASP-A1-004', // innerHTML with template literal: could be sanitized before assignment
        'OWASP-A1-005', // innerHTML from function call: the function may return sanitized content
        'OWASP-A2-002', // localStorage token: depends on whether the token is actually sensitive
        'OWASP-A2-004', // Math.random() for security: naming heuristic may not match actual intent
        'OWASP-A2-005', // http:// URL: could be a local development endpoint
        'OWASP-A3-003', // Sensitive data in query string: substring matching may be coincidental
        'OWASP-A5-001', // Open redirect: the variable may come from a trusted internal source
        'OWASP-A5-002', // Client-side role check: server-side enforcement may also exist
        'OWASP-A6-001', // console.log of sensitive variable name: may be dev-only code
        'OWASP-A6-003', // console.log of sensitive objects: may be dev-only code
        'OWASP-A7-001', // innerHTML general: content may be sanitized through DOMPurify or similar
        'OWASP-A7-003', // dangerouslySetInnerHTML: React names it "dangerous" but devs may sanitize
        'OWASP-A8-003', // Object.assign() dynamic: common pattern, only risky with untrusted input
        'OWASP-A10-001', // SSRF dynamic URL: the URL may be constructed internally from safe sources
      ];

      // ---------------------------------------------------------------
      // LOW confidence: Informational or probabilistic findings.
      // These may or may not represent real vulnerabilities. They flag
      // patterns that are common in normal code and only become security
      // issues under very specific circumstances.
      // ---------------------------------------------------------------
      const lowConfidenceRules = [
        'OWASP-A8-001', // JSON.parse(): used everywhere, almost never a vulnerability by itself
        'OWASP-A9-001', // Risky library import: the library is not itself a vulnerability
        'OWASP-A6-004', // Express without helmet: best practice gap, not directly exploitable
      ];

      if (highConfidenceRules.includes(ruleId)) {
        confidence = "HIGH";
      } else if (mediumConfidenceRules.includes(ruleId)) {
        confidence = "MEDIUM";
      } else if (lowConfidenceRules.includes(ruleId)) {
        confidence = "LOW";
      } else if (ruleId === 'OWASP-A2-001' || ruleId === 'OWASP-A3-002') {
        // Hardcoded passwords and API keys: confidence depends on how
        // strongly the variable name matches known credential patterns.
        // A variable literally named "password" containing a string literal
        // is almost certainly a real credential leak (HIGH). A variable
        // named "apiKey" could be a non-sensitive public identifier (MEDIUM).
        const matchesStrongIndicator =
          messageLower.includes("password") ||
          messageLower.includes("secret");

        confidence = matchesStrongIndicator ? "HIGH" : "MEDIUM";
      } else if (ruleId === 'OWASP-A3-001') {
        // Hardcoded secrets with known structural signatures.
        // JWT tokens and AWS keys have distinctive formats that are
        // very unlikely to appear in non-credential strings (HIGH).
        // IP addresses are common in configuration and may be benign (MEDIUM).
        if (messageLower.includes("jwt") || messageLower.includes("aws")) {
          confidence = "HIGH";
        } else {
          confidence = "MEDIUM";
        }
      }

      issue.confidence = confidence;
    });

    return {
      fileName: file.webkitRelativePath || file.name,
      issues,
      rawCode: code,
      success: true,
      hasError, // Track if any rule execution failed
    };
  } catch (error) {
    console.error("Scanner Error:", error);
    return {
      fileName: file.webkitRelativePath || file.name,
      error: error.message,
      success: false,
      hasError: true
    };
  }
};
