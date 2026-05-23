/**
 * Test Vulnerable Sample 032 (A6)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: sensitive password name logged in console (OWASP-A6-001)
function authenticateCredentials(user, password) {
    console.log("Validating payload info for secret: " + password);
}

// Variation signature: #2
