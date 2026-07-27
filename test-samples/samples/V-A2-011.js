/**
 * Test Vulnerable Sample 011 (A2)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: hardcoded credential variables (OWASP-A2-001)
const adminAuthPassword = "SuperSecretFallbackPassword2026!";
function loginMaster(pwd) {
    return pwd === adminAuthPassword;
}

// Variation signature: #1
