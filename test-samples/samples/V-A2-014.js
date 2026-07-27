/**
 * Test Vulnerable Sample 014 (A2)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: localStorage token caching (OWASP-A2-002)
function cacheSessionToken(jwtToken) {
    localStorage.setItem("session_token", jwtToken);
}

// Variation signature: #2
