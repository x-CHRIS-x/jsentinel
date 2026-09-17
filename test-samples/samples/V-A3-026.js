/**
 * Test Vulnerable Sample 026 (A3)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: password reset token exposed in query string (OWASP-A3-003)
function buildPasswordResetUrl(accountEmail, resetToken) {
    return "/auth/reset?email=" + accountEmail + "&token=" + resetToken;
}

// Variation signature: #2
