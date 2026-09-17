/**
 * Test Vulnerable Sample 014 (A2)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: localStorage auth credential storage (OWASP-A2-002)
function persistAuthCredentials(authToken) {
    localStorage.setItem("user_auth_credential", authToken);
}

// Variation signature: #2
