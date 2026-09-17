/**
 * Test Vulnerable Sample 032 (A6)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: sensitive authentication secret printed to console (OWASP-A6-001)
function recordAuthSession(user, secretKey) {
    console.warn("Session established for: " + user + " secret: " + secretKey);
}

// Variation signature: #2
