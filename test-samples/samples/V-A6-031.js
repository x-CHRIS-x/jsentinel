/**
 * Test Vulnerable Sample 031 (A6)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: sensitive password name logged in console (OWASP-A6-001)
function authenticateCredentials(user, password) {
    console.log("Validating login for user: " + user + " with password: " + password);
}

// Variation signature: #1
