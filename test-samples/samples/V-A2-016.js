/**
 * Test Vulnerable Sample 016 (A2)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: insecure cookie properties (OWASP-A2-003)
function createSessionCookie(userId) {
    document.cookie = "session=" + userId + "; path=/;";
}

// Variation signature: #2
