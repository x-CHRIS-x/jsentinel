/**
 * Test Vulnerable Sample 016 (A2)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: storing authentication credentials directly in document.cookie without HttpOnly protection (OWASP-A2-003)
function storeAuthCookie(authToken) {
    document.cookie = "auth_token=" + authToken + "; path=/;";
}

// Variation signature: #2
