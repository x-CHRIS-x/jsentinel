/**
 * Test Vulnerable Sample 051 (A9)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: storing sensitive bearer token in sessionStorage (CWE-922)
function persistBearerToken(token) {
    sessionStorage.setItem("bearer_token", token);
}

// Variation signature: #1
