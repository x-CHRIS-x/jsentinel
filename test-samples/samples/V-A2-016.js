/**
 * Test Vulnerable Sample 016 (A2)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: insecure cookie token storage (OWASP-A2-003)
function storeAuthCookie(authToken) {
    document.cookie = "auth_token=" + authToken + "; path=/;";
}

// Variation signature: #2
