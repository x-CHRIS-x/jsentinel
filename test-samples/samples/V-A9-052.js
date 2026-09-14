/**
 * Test Vulnerable Sample 052 (A9)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: sensitive authentication token exposed in window URL fragment (CWE-598)
function publishAccessTokenInUrl(userToken) {
    window.location.hash = "access_token=" + userToken;
}

// Variation signature: #2
